/* Restricted read-only source capture for the exact patched C2a build.
 * Direction and lengths reviewed against pinned ssl/ssl_local.h and
 * ssl/tls13_enc.c: server READ uses client application secret, WRITE server
 * application secret. This is not a complete semantic TLS capsule. */
#ifndef _DEFAULT_SOURCE
# define _DEFAULT_SOURCE 1
#endif
#include "crypto/bio/bio_local.h"
#include "ssl/ssl_local.h"
#include "openssl-capture.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#if OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 0 \
    || OPENSSL_VERSION_PATCH != 13
# error capture_requires_exact_OpenSSL_3_0_13_headers_and_pinned_source
#endif

/* Private, pointer-free, source-only representation. It has no serialization
 * or import API. Secret bytes are written directly into the locked mapping;
 * no extra secret-bearing struct is placed on the stack. */
typedef struct {
    uint32_t schema_version;
    uint64_t read_generation, write_generation, mutation_serial, call_serial;
    char nonce[33];
    unsigned char read_secret[32], write_secret[32];
    unsigned char read_iv[12], write_iv[12];
    unsigned char read_sequence[8], write_sequence[8];
} X10_CAPTURE_MATERIAL;

static int capture_profile(const SSL *s)
{
    const EVP_MD *digest;

    if (s->session == NULL || s->session->cipher == NULL) return 0;
    /* The handshake scratch new_hash is cleared after completion. The
     * negotiated cipher retains its checked SHA256 handshake-digest ID. */
    digest = SSL_CIPHER_get_handshake_digest(s->session->cipher);
    return s->server == 1 && s->version == TLS1_3_VERSION
        && s->session != NULL && s->session->cipher != NULL
        && s->session->cipher->id == TLS1_3_CK_AES_128_GCM_SHA256
        && digest != NULL && EVP_MD_get_type(digest) == NID_sha256
        && EVP_MD_get_size(digest) == 32
        && s->enc_read_ctx != NULL && s->enc_write_ctx != NULL
        && EVP_CIPHER_CTX_get0_cipher(s->enc_read_ctx) != NULL
        && EVP_CIPHER_CTX_get0_cipher(s->enc_write_ctx) != NULL
        && EVP_CIPHER_CTX_get_nid(s->enc_read_ctx) == NID_aes_128_gcm
        && EVP_CIPHER_CTX_get_nid(s->enc_write_ctx) == NID_aes_128_gcm
        && EVP_CIPHER_CTX_get_key_length(s->enc_read_ctx) == 16
        && EVP_CIPHER_CTX_get_key_length(s->enc_write_ctx) == 16
        && EVP_CIPHER_CTX_get_iv_length(s->enc_read_ctx) == 12
        && EVP_CIPHER_CTX_get_iv_length(s->enc_write_ctx) == 12
        && EVP_CIPHER_CTX_is_encrypting(s->enc_read_ctx) == 0
        && EVP_CIPHER_CTX_is_encrypting(s->enc_write_ctx) == 1;
}

static int capture_material_matches(const X10_CAPTURE_MATERIAL *m,
    const SSL *s, const X10_PROBE_RESULT *initial, const char nonce[33])
{
    return m->schema_version == 1 && m->read_generation == 0
        && m->write_generation == 0 && m->mutation_serial == 2
        && m->call_serial == initial->ledger_call_serial
        && memcmp(m->nonce, nonce, sizeof(m->nonce)) == 0
        && CRYPTO_memcmp(m->read_secret, s->client_app_traffic_secret, 32) == 0
        && CRYPTO_memcmp(m->write_secret, s->server_app_traffic_secret, 32) == 0
        && CRYPTO_memcmp(m->read_iv, s->read_iv, 12) == 0
        && CRYPTO_memcmp(m->write_iv, s->write_iv, 12) == 0
        && memcmp(m->read_sequence, s->rlayer.read_sequence, 8) == 0
        && memcmp(m->write_sequence, s->rlayer.write_sequence, 8) == 0;
}

int x10_capture_source(const SSL *s, const X10_PROBE_LEDGER *ledger,
    const X10_PROBE_RESULT *initial, const char nonce[33],
    const volatile sig_atomic_t *interrupted, X10_CAPTURE_RESULT *out)
{
#if defined(__linux__) && defined(MAP_ANONYMOUS) \
    && defined(MADV_DONTDUMP) && defined(MADV_DONTFORK)
    X10_PROBE_RESULT observed;
    X10_PROBE_LEDGER before;
    X10_CAPTURE_MATERIAL *material;
    unsigned char *mapping = MAP_FAILED, *page = NULL;
    const volatile unsigned char *cleared;
    long page_size;
    size_t size = 0, i;
    int success = 0, writable = 0, locked = 0, copied = 0;
    unsigned char nonzero = 0;

    if (out == NULL) return 0;
    memset(out, 0, sizeof(*out));
    if (s == NULL || ledger == NULL || initial == NULL || nonce == NULL
        || interrupted == NULL || *interrupted || !initial->allowed
        || initial->schema_version != 1 || initial->reasons != 0
        || initial->read_generation != 0 || initial->write_generation != 0
        || initial->mutation_serial != 2 || strnlen(nonce, 33) != 32)
        return 0;
    for (i = 0; i < 32; i++)
        if (!((nonce[i] >= '0' && nonce[i] <= '9')
            || (nonce[i] >= 'a' && nonce[i] <= 'f'))) return 0;
    before = *ledger;
    if (!x10_openssl_probe(s, ledger, &observed)
        || memcmp(initial, &observed, sizeof(observed)) != 0
        || memcmp(&before, ledger, sizeof(before)) != 0
        || !capture_profile(s)) return 0;
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 4096 || page_size > 65536
        || (size_t) page_size < sizeof(*material)) return 0;
    size = (size_t) page_size;
    mapping = mmap(NULL, size * 3, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return 0;
    page = mapping + size;
    if (mprotect(page, size, PROT_READ | PROT_WRITE) != 0) goto done;
    writable = 1;
    if (mlock(page, size) != 0) goto done;
    locked = 1; out->locked = 1;
    if (madvise(page, size, MADV_DONTDUMP) != 0) goto done;
    out->dont_dump = 1;
    if (madvise(page, size, MADV_DONTFORK) != 0) goto done;
    out->dont_fork = 1;
    if (*interrupted) goto done;
    material = (X10_CAPTURE_MATERIAL *) page;
    material->schema_version = 1;
    material->read_generation = initial->read_generation;
    material->write_generation = initial->write_generation;
    material->mutation_serial = initial->mutation_serial;
    material->call_serial = initial->ledger_call_serial;
    memcpy(material->nonce, nonce, sizeof(material->nonce));
    /* No source mutation, derivation, callback, provider operation or I/O. */
    copied = 1;
    memcpy(material->read_secret, s->client_app_traffic_secret, 32);
    memcpy(material->write_secret, s->server_app_traffic_secret, 32);
    memcpy(material->read_iv, s->read_iv, 12);
    memcpy(material->write_iv, s->write_iv, 12);
    memcpy(material->read_sequence, s->rlayer.read_sequence, 8);
    memcpy(material->write_sequence, s->rlayer.write_sequence, 8);
    out->captured = 1;
    out->secret_bytes = 64; out->iv_bytes = 24; out->sequence_bytes = 16;
    if (mprotect(page, size, PROT_READ) != 0) goto done;
    writable = 0; out->read_only = 1;
    if (*interrupted || !capture_material_matches(material, s, initial, nonce)
        || !x10_openssl_probe(s, ledger, &observed)
        || memcmp(initial, &observed, sizeof(observed)) != 0
        || memcmp(&before, ledger, sizeof(before)) != 0
        || !capture_profile(s)) goto done;
    out->source_unchanged = 1;
    success = 1;
done:
    /* Even an interrupted/refused sample reaches this synchronous cleanup.
     * If the restore-to-writable fails, do not touch the read-only page or
     * claim a wipe: unmap it and refuse, then the caller terminates. */
    if (copied && !writable) {
        if (mprotect(page, size, PROT_READ | PROT_WRITE) == 0) writable = 1;
        else success = 0;
    }
    if (writable) {
        OPENSSL_cleanse(page, size);
        cleared = page;
        for (i = 0; i < size; i++) nonzero |= cleared[i];
        if (nonzero == 0) out->cleansed = 1;
        else success = 0;
    } else if (copied) success = 0;
    if (locked && munlock(page, size) != 0) success = 0;
    if (munmap(mapping, size * 3) == 0) out->unmapped = 1;
    else success = 0;
    if (*interrupted) success = 0;
    return success && out->captured && out->locked && out->dont_dump
        && out->dont_fork && out->read_only && out->source_unchanged
        && out->cleansed && out->unmapped;
#else
    (void) s; (void) ledger; (void) initial; (void) nonce; (void) interrupted;
    if (out != NULL) memset(out, 0, sizeof(*out));
    return 0;
#endif
}
