/*
 * HTTP authentication
 * Copyright (c) 2010 Martin Storsjo
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "httpauth.h"
#include "libavutil/base64.h"
#include "libavutil/avstring.h"
#include "internal.h"
#include "libavutil/random_seed.h"
#include "libavutil/hash.h"
#include "urldecode.h"

static void handle_basic_params(HTTPAuthState *state, const char *key,
                                int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "realm=", key_len)) {
        *dest     =        state->realm;
        *dest_len = sizeof(state->realm);
    }
}

static void handle_digest_params(HTTPAuthState *state, const char *key,
                                 int key_len, char **dest, int *dest_len)
{
    DigestParams *digest = &state->digest_params;

    if (!strncmp(key, "realm=", key_len)) {
        *dest     =        state->realm;
        *dest_len = sizeof(state->realm);
    } else if (!strncmp(key, "nonce=", key_len)) {
        *dest     =        digest->nonce;
        *dest_len = sizeof(digest->nonce);
    } else if (!strncmp(key, "opaque=", key_len)) {
        *dest     =        digest->opaque;
        *dest_len = sizeof(digest->opaque);
    } else if (!strncmp(key, "algorithm=", key_len)) {
        *dest     =        digest->algorithm;
        *dest_len = sizeof(digest->algorithm);
    } else if (!strncmp(key, "qop=", key_len)) {
        *dest     =        digest->qop;
        *dest_len = sizeof(digest->qop);
    } else if (!strncmp(key, "stale=", key_len)) {
        *dest     =        digest->stale;
        *dest_len = sizeof(digest->stale);
    }
}

static void handle_digest_update(HTTPAuthState *state, const char *key,
                                 int key_len, char **dest, int *dest_len)
{
    DigestParams *digest = &state->digest_params;

    if (!strncmp(key, "nextnonce=", key_len)) {
        *dest     =        digest->nonce;
        *dest_len = sizeof(digest->nonce);
    }
}

static void choose_qop(char *qop, int size)
{
    char *ptr = strstr(qop, "auth");
    char *end = ptr + strlen("auth");

    if (ptr && (!*end || av_isspace(*end) || *end == ',') &&
        (ptr == qop || av_isspace(ptr[-1]) || ptr[-1] == ',')) {
        av_strlcpy(qop, "auth", size);
    } else {
        qop[0] = 0;
    }
}

void ff_http_auth_handle_header(HTTPAuthState *state, const char *key,
                                const char *value)
{
    if (!av_strcasecmp(key, "WWW-Authenticate") || !av_strcasecmp(key, "Proxy-Authenticate")) {
        const char *p;
        if (av_stristart(value, "Basic ", &p) &&
            state->auth_type <= HTTP_AUTH_BASIC) {
            state->auth_type = HTTP_AUTH_BASIC;
            state->realm[0] = 0;
            state->stale = 0;
            ff_parse_key_value(p, (ff_parse_key_val_cb) handle_basic_params,
                               state);
        } else if (av_stristart(value, "Digest ", &p) &&
                   state->auth_type <= HTTP_AUTH_DIGEST) {
            state->auth_type = HTTP_AUTH_DIGEST;
            memset(&state->digest_params, 0, sizeof(DigestParams));
            state->realm[0] = 0;
            state->stale = 0;
            ff_parse_key_value(p, (ff_parse_key_val_cb) handle_digest_params,
                               state);
            choose_qop(state->digest_params.qop,
                       sizeof(state->digest_params.qop));
            if (!av_strcasecmp(state->digest_params.stale, "true"))
                state->stale = 1;
        }
    } else if (!av_strcasecmp(key, "Authentication-Info")) {
        ff_parse_key_value(value, (ff_parse_key_val_cb) handle_digest_update,
                           state);
    }
}

/* Generate hash string, updated to use AVHashContext to support other algorithms */
static void update_hash_strings(struct AVHashContext *hash_ctx, ...)
{
    va_list vl;

    va_start(vl, hash_ctx);
    while (1) {
        const char *str = va_arg(vl, const char*);
        if (!str)
            break;
        av_hash_update(hash_ctx, (const uint8_t *)str, strlen(str));
    }
    va_end(vl);
}

/* Generate a digest reply, according to RFC 2617. Update to support RFC 7617*/
static char *make_digest_auth(HTTPAuthState *state, const char *username,
                              const char *password, const char *uri,
                              const char *method)
{
    DigestParams *digest = &state->digest_params;
    size_t len;
    uint32_t cnonce_buf[2];
    char cnonce[17];
    char nc[9];
    int i;
    char a1_hash[65], a2_hash[65], response[65];
    struct AVHashContext *hash_ctx = NULL; // use AVHashContext for other algorithm support
    size_t len_hash = 33; // Modifiable hash length, MD5:32, SHA-2:64
    char *authstr;

    digest->nc++;
    snprintf(nc, sizeof(nc), "%08x", digest->nc);

    /* Generate a client nonce. */
    for (i = 0; i < 2; i++)
        cnonce_buf[i] = av_get_random_seed();
    ff_data_to_hex(cnonce, (const uint8_t*) cnonce_buf, sizeof(cnonce_buf), 1);

    /* Generate hash context by algorithm. */
    const char *algorithm = digest->algorithm;
    const char *hashing_algorithm;
    if (!*algorithm) {
        algorithm = "MD5";  // if empty, use MD5 as Default 
        hashing_algorithm = "MD5";
    } else if (av_stristr(algorithm, "MD5")) {
        hashing_algorithm = "MD5";
    } else if (av_stristr(algorithm, "sha256") || av_stristr(algorithm, "sha-256")) {
        hashing_algorithm = "SHA256";
        len_hash = 65; // SHA-2: 64 characters.
    } else if (av_stristr(algorithm, "sha512-256") || av_stristr(algorithm, "sha-512-256")) {
        hashing_algorithm = "SHA512_256";
        len_hash = 65; // SHA-2: 64 characters.
    } else { // Unsupported algorithm
        return NULL;
    }

    int ret = av_hash_alloc(&hash_ctx, hashing_algorithm);
    if (ret < 0)
        return NULL;

    /* a1 hash calculation */
    av_hash_init(hash_ctx);
    update_hash_strings(hash_ctx, username, ":", state->realm, ":", password, NULL);
    if (av_stristr(algorithm, "-sess")) {
        update_hash_strings(hash_ctx, ":", digest->nonce, ":", cnonce, NULL);
    }
    av_hash_final_hex(hash_ctx, a1_hash, len_hash);

    /* a2 hash calculation */
    av_hash_init(hash_ctx);
    update_hash_strings(hash_ctx, method, ":", uri, NULL);
    av_hash_final_hex(hash_ctx, a2_hash, len_hash);
    
    /* response hash calculation */
    av_hash_init(hash_ctx);
    update_hash_strings(hash_ctx, a1_hash, ":", digest->nonce, NULL);
    if (!strcmp(digest->qop, "auth")) {
        update_hash_strings(hash_ctx, ":", nc, ":", cnonce, ":", digest->qop, NULL);
    } else if (!strcmp(digest->qop, "auth-int")) { // unsupported
        av_hash_freep(&hash_ctx);
        return NULL;
    }
    update_hash_strings(hash_ctx, ":", a2_hash, NULL);
    update_hash_strings(hash_ctx, NULL);
    av_hash_final_hex(hash_ctx, response, len_hash);
    av_hash_freep(&hash_ctx);

    /* Authorization header generation */
    len = strlen(username) + strlen(state->realm) + strlen(digest->nonce) +
              strlen(uri) + strlen(response) + strlen(digest->algorithm) +
              strlen(digest->opaque) + strlen(digest->qop) + strlen(cnonce) +
              strlen(nc) + 150;

    authstr = av_malloc(len);
    if (!authstr)
        return NULL;
    snprintf(authstr, len, "Authorization: Digest ");

    /* TODO: Escape the quoted strings properly. */
    av_strlcatf(authstr, len, "username=\"%s\"",   username);
    av_strlcatf(authstr, len, ", realm=\"%s\"",     state->realm);
    av_strlcatf(authstr, len, ", nonce=\"%s\"",     digest->nonce);
    av_strlcatf(authstr, len, ", uri=\"%s\"",       uri);
    av_strlcatf(authstr, len, ", response=\"%s\"",  response);

    // we are violating the RFC and use "" because all others seem to do that too.
    if (digest->algorithm[0])
        av_strlcatf(authstr, len, ", algorithm=\"%s\"",  digest->algorithm);

    if (digest->opaque[0])
        av_strlcatf(authstr, len, ", opaque=\"%s\"", digest->opaque);
    if (digest->qop[0]) {
        av_strlcatf(authstr, len, ", qop=\"%s\"",    digest->qop);
        av_strlcatf(authstr, len, ", cnonce=\"%s\"", cnonce);
        av_strlcatf(authstr, len, ", nc=%s",         nc);
    }

    av_strlcatf(authstr, len, "\r\n");

    return authstr;
}

char *ff_http_auth_create_response(HTTPAuthState *state, const char *auth,
                                   const char *path, const char *method)
{
    char *authstr = NULL;

    /* Clear the stale flag, we assume the auth is ok now. It is reset
     * by the server headers if there's a new issue. */
    state->stale = 0;
    if (!auth || !strchr(auth, ':'))
        return NULL;

    if (state->auth_type == HTTP_AUTH_BASIC) {
        int auth_b64_len, len;
        char *ptr, *decoded_auth = ff_urldecode(auth, 0);

        if (!decoded_auth)
            return NULL;

        auth_b64_len = AV_BASE64_SIZE(strlen(decoded_auth));
        len = auth_b64_len + 30;

        authstr = av_malloc(len);
        if (!authstr) {
            av_free(decoded_auth);
            return NULL;
        }

        snprintf(authstr, len, "Authorization: Basic ");
        ptr = authstr + strlen(authstr);
        av_base64_encode(ptr, auth_b64_len, decoded_auth, strlen(decoded_auth));
        av_strlcat(ptr, "\r\n", len - (ptr - authstr));
        av_free(decoded_auth);
    } else if (state->auth_type == HTTP_AUTH_DIGEST) {
        char *username = ff_urldecode(auth, 0), *password;

        if (!username)
            return NULL;

        if ((password = strchr(username, ':'))) {
            *password++ = 0;
            authstr = make_digest_auth(state, username, password, path, method);
        }
        av_free(username);
    }
    return authstr;
}
