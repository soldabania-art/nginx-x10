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
#include <time.h>

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

enum x10_capture_state {
    X10_CAPTURE_EMPTY, X10_CAPTURE_PREPARING, X10_CAPTURE_READY,
    X10_CAPTURE_DESTROYING, X10_CAPTURE_CLEARED, X10_CAPTURE_FAILED
};

/* This slot contains only bindings and mapping ownership, not secret bytes.
 * The trusted fixture owns its lifetime and makes no concurrent SSL/BIO call.
 * It keeps this tombstone until its hold exits; only the by-value generation
 * can be sent over the public control channel. */
struct x10_capture_slot_st {
    enum x10_capture_state state;
    uint64_t generation;
    int64_t deadline_ms;
    const SSL *ssl;
    const X10_PROBE_LEDGER *ledger;
    X10_PROBE_LEDGER before;
    X10_PROBE_RESULT initial;
    char nonce[33];
    unsigned char *mapping, *page;
    size_t size;
    unsigned int writable, locked, copied, cleanup_failed;
    X10_CAPTURE_RESULT result;
};

/* One trusted event-loop thread, not a process-global concurrent allocator.
 * Exhaustion refuses instead of wrapping and reusing a generation. */
static uint64_t capture_generation;

static int64_t capture_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0 || ts.tv_sec < 0
        || (uint64_t) ts.tv_sec > (uint64_t) INT64_MAX / 1000 - 1)
        return -1;
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

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

X10_CAPTURE_SLOT *x10_capture_slot_new(void)
{
    return OPENSSL_zalloc(sizeof(X10_CAPTURE_SLOT));
}

uint64_t x10_capture_slot_generation(const X10_CAPTURE_SLOT *slot)
{
    return slot != NULL && slot->state == X10_CAPTURE_READY
        ? slot->generation : 0;
}

int x10_capture_slot_check(const X10_CAPTURE_SLOT *slot, uint64_t generation,
    const SSL *s, const X10_PROBE_LEDGER *ledger, const char nonce[33],
    const volatile sig_atomic_t *interrupted)
{
    X10_PROBE_RESULT observed;
    int64_t now;

    if (slot == NULL || slot->state != X10_CAPTURE_READY || generation == 0
        || generation != slot->generation || s == NULL || s != slot->ssl
        || ledger == NULL || ledger != slot->ledger || nonce == NULL
        || interrupted == NULL || *interrupted
        || memcmp(slot->nonce, nonce, sizeof(slot->nonce)) != 0)
        return 0;
    now = capture_now_ms();
    if (now < 0 || now >= slot->deadline_ms
        || memcmp(&slot->before, ledger, sizeof(slot->before)) != 0
        || !x10_openssl_probe(s, ledger, &observed)
        || memcmp(&slot->initial, &observed, sizeof(observed)) != 0
        || !capture_profile(s)
        || !capture_material_matches((const X10_CAPTURE_MATERIAL *) slot->page,
                                     s, &slot->initial, nonce))
        return 0;
    now = capture_now_ms();
    return !*interrupted && now >= 0 && now < slot->deadline_ms
        && memcmp(&slot->before, ledger, sizeof(slot->before)) == 0;
}

int x10_capture_slot_cleanup(X10_CAPTURE_SLOT *slot, X10_CAPTURE_RESULT *out)
{
#if defined(__linux__) && defined(MAP_ANONYMOUS) \
    && defined(MADV_DONTDUMP) && defined(MADV_DONTFORK)
    const volatile unsigned char *cleared;
    size_t i;
    unsigned char nonzero = 0;

    if (slot == NULL) { if (out != NULL) memset(out, 0, sizeof(*out)); return 0; }
    if (slot->state == X10_CAPTURE_CLEARED
        || slot->state == X10_CAPTURE_FAILED) {
        if (out != NULL) *out = slot->result;
        return !slot->cleanup_failed;
    }
    /* Revoke before any system call. Expiry, interruption and bad decisions
     * do not bypass destruction, and cannot turn cleanup into a resume grant. */
    slot->state = X10_CAPTURE_DESTROYING;
    if (slot->mapping != NULL) {
        if (slot->copied && !slot->writable) {
            if (mprotect(slot->page, slot->size,
                         PROT_READ | PROT_WRITE) == 0) slot->writable = 1;
            else slot->cleanup_failed = 1;
        }
        if (slot->writable) {
            OPENSSL_cleanse(slot->page, slot->size);
            cleared = slot->page;
            for (i = 0; i < slot->size; i++) nonzero |= cleared[i];
            if (nonzero == 0) slot->result.cleansed = 1;
            else slot->cleanup_failed = 1;
        } else if (slot->copied) slot->cleanup_failed = 1;
        if (slot->locked && munlock(slot->page, slot->size) != 0)
            slot->cleanup_failed = 1;
        if (munmap(slot->mapping, slot->size * 3) == 0) {
            slot->result.unmapped = 1;
            slot->mapping = NULL; slot->page = NULL;
        } else slot->cleanup_failed = 1;
    }
    slot->ssl = NULL; slot->ledger = NULL;
    slot->state = slot->cleanup_failed ? X10_CAPTURE_FAILED
                                     : X10_CAPTURE_CLEARED;
    if (out != NULL) *out = slot->result;
    return !slot->cleanup_failed;
#else
    if (out != NULL) memset(out, 0, sizeof(*out));
    if (slot != NULL) { slot->state = X10_CAPTURE_FAILED; slot->cleanup_failed = 1; }
    return 0;
#endif
}

void x10_capture_slot_free(X10_CAPTURE_SLOT *slot)
{
    if (slot == NULL) return;
    (void) x10_capture_slot_cleanup(slot, NULL);
    OPENSSL_clear_free(slot, sizeof(*slot));
}

int x10_capture_slot_open(X10_CAPTURE_SLOT *slot, const SSL *s,
    const X10_PROBE_LEDGER *ledger, const X10_PROBE_RESULT *initial,
    const char nonce[33], int64_t deadline_ms,
    const volatile sig_atomic_t *interrupted, X10_CAPTURE_RESULT *out)
{
#if defined(__linux__) && defined(MAP_ANONYMOUS) \
    && defined(MADV_DONTDUMP) && defined(MADV_DONTFORK)
    X10_PROBE_RESULT observed;
    X10_CAPTURE_MATERIAL *material;
    long page_size;
    size_t i;
    int64_t now;

    if (out == NULL) {
        (void) x10_capture_slot_cleanup(slot, NULL);
        return 0;
    }
    memset(out, 0, sizeof(*out));
    if (slot == NULL) return 0;
    if (slot->state != X10_CAPTURE_EMPTY) {
        (void) x10_capture_slot_cleanup(slot, out);
        return 0;
    }
    slot->state = X10_CAPTURE_PREPARING;
    now = capture_now_ms();
    if (now < 0 || deadline_ms <= now || deadline_ms - now > 3000
        || capture_generation == UINT64_MAX
        || s == NULL || ledger == NULL || initial == NULL || nonce == NULL
        || interrupted == NULL || *interrupted || !initial->allowed
        || initial->schema_version != 1 || initial->reasons != 0
        || initial->read_generation != 0 || initial->write_generation != 0
        || initial->mutation_serial != 2 || strnlen(nonce, 33) != 32)
        goto refused;
    for (i = 0; i < 32; i++)
        if (!((nonce[i] >= '0' && nonce[i] <= '9')
            || (nonce[i] >= 'a' && nonce[i] <= 'f'))) goto refused;
    slot->ssl = s; slot->ledger = ledger;
    slot->before = *ledger; slot->initial = *initial;
    memcpy(slot->nonce, nonce, sizeof(slot->nonce));
    slot->deadline_ms = deadline_ms;
    slot->generation = ++capture_generation;
    if (!x10_openssl_probe(s, ledger, &observed)
        || memcmp(initial, &observed, sizeof(observed)) != 0
        || memcmp(&slot->before, ledger, sizeof(slot->before)) != 0
        || !capture_profile(s)) goto refused;
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 4096 || page_size > 65536
        || (size_t) page_size < sizeof(*material)) goto refused;
    slot->size = (size_t) page_size;
    slot->mapping = mmap(NULL, slot->size * 3, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (slot->mapping == MAP_FAILED) { slot->mapping = NULL; goto refused; }
    slot->page = slot->mapping + slot->size;
    if (mprotect(slot->page, slot->size, PROT_READ | PROT_WRITE) != 0)
        goto refused;
    slot->writable = 1;
    if (mlock(slot->page, slot->size) != 0) goto refused;
    slot->locked = 1; slot->result.locked = 1;
    if (madvise(slot->page, slot->size, MADV_DONTDUMP) != 0) goto refused;
    slot->result.dont_dump = 1;
    if (madvise(slot->page, slot->size, MADV_DONTFORK) != 0) goto refused;
    slot->result.dont_fork = 1;
    now = capture_now_ms();
    if (*interrupted || now < 0 || now >= slot->deadline_ms) goto refused;
    material = (X10_CAPTURE_MATERIAL *) slot->page;
    material->schema_version = 1;
    material->read_generation = initial->read_generation;
    material->write_generation = initial->write_generation;
    material->mutation_serial = initial->mutation_serial;
    material->call_serial = initial->ledger_call_serial;
    memcpy(material->nonce, nonce, sizeof(material->nonce));
    /* No source mutation, derivation, callback, provider operation or I/O. */
    slot->copied = 1;
    memcpy(material->read_secret, s->client_app_traffic_secret, 32);
    memcpy(material->write_secret, s->server_app_traffic_secret, 32);
    memcpy(material->read_iv, s->read_iv, 12);
    memcpy(material->write_iv, s->write_iv, 12);
    memcpy(material->read_sequence, s->rlayer.read_sequence, 8);
    memcpy(material->write_sequence, s->rlayer.write_sequence, 8);
    slot->result.captured = 1;
    slot->result.secret_bytes = 64; slot->result.iv_bytes = 24;
    slot->result.sequence_bytes = 16;
    if (mprotect(slot->page, slot->size, PROT_READ) != 0) goto refused;
    slot->writable = 0; slot->result.read_only = 1;
    slot->state = X10_CAPTURE_READY;
    if (!x10_capture_slot_check(slot, slot->generation, s, ledger, nonce,
                                interrupted)) goto refused;
    slot->result.source_unchanged = 1;
    *out = slot->result;
    return 1;
refused:
    (void) x10_capture_slot_cleanup(slot, out);
    return 0;
#else
    (void) s; (void) ledger; (void) initial; (void) nonce; (void) interrupted;
    (void) deadline_ms;
    if (out != NULL) memset(out, 0, sizeof(*out));
    if (slot != NULL) { slot->state = X10_CAPTURE_FAILED; slot->cleanup_failed = 1; }
    return 0;
#endif
}

int x10_capture_slot_discard(X10_CAPTURE_SLOT *slot, uint64_t generation,
    const SSL *s, const X10_PROBE_LEDGER *ledger, const char nonce[33],
    const volatile sig_atomic_t *interrupted, X10_CAPTURE_RESULT *out)
{
    int valid = out != NULL
        && x10_capture_slot_check(slot, generation, s, ledger, nonce,
                                  interrupted);
    int cleared = x10_capture_slot_cleanup(slot, out);
    int64_t now = capture_now_ms();

    return valid && cleared && interrupted != NULL && !*interrupted
        && now >= 0 && now < slot->deadline_ms;
}

int x10_capture_source(const SSL *s, const X10_PROBE_LEDGER *ledger,
    const X10_PROBE_RESULT *initial, const char nonce[33],
    const volatile sig_atomic_t *interrupted, X10_CAPTURE_RESULT *out)
{
    X10_CAPTURE_SLOT *slot;
    int success = 0;
    int64_t now = capture_now_ms();

    if (out == NULL) return 0;
    memset(out, 0, sizeof(*out));
    if (now < 0 || now > INT64_MAX - 3000) return 0;
    slot = x10_capture_slot_new();
    if (slot == NULL) return 0;
    if (x10_capture_slot_open(slot, s, ledger, initial, nonce, now + 3000,
                              interrupted, out))
        success = x10_capture_slot_discard(slot,
            x10_capture_slot_generation(slot), s, ledger, nonce,
            interrupted, out);
    x10_capture_slot_free(slot);
    return success && out->captured && out->locked && out->dont_dump
        && out->dont_fork && out->read_only && out->source_unchanged
        && out->cleansed && out->unmapped;
}
