/* Synthetic protection controls for the actual capture translation unit.
 * Fixed public bytes only; no handshake, network endpoint or TLS admission. */
#define _DEFAULT_SOURCE 1
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
typedef struct x10_capture_slot_st X10_CAPTURE_SLOT;
uint64_t x10_capture_slot_generation(const X10_CAPTURE_SLOT *slot);

enum fault { NONE, MAP, INITIAL_RW, LOCK, DUMP, FORK, READ_ONLY,
             RESTORE_RW, UNLOCK, UNMAP, CLOCK, PAGE_SMALL, PAGE_LARGE };
static enum fault fault_a, fault_b;
static int persistent, failures_a, failures_b, rw_calls;
static unsigned int calls[PAGE_LARGE + 1], probe_calls, scenarios;
static unsigned char *owned_mapping, *owned_page;
static size_t owned_size;
static int page_readable, cleanup_active, revoked, zero_before_unlock;
static int copied_before_unmap, zero_before_unmap, unlock_nonzero;
static X10_CAPTURE_SLOT *observed_slot;
static const char *case_name;

static void check(int value, int line)
{
    if (!value) {
        printf("{\"passed\":false,\"case\":\"%s\",\"check\":%d}\n",
               case_name, line);
        exit(1);
    }
}
#define CHECK(c) check(!!(c), __LINE__)

static int fail(enum fault point)
{
    calls[point]++;
    if (point == fault_a && (persistent || failures_a++ == 0)) return 1;
    if (point == fault_b && (persistent || failures_b++ == 0)) return 1;
    return 0;
}

static int all_zero(void)
{
    const volatile unsigned char *p = owned_page;
    size_t i;
    unsigned char nonzero = 0;
    if (!page_readable || p == NULL) return 0;
    for (i = 0; i < owned_size; i++) nonzero |= p[i];
    return nonzero == 0;
}

static void note_cleanup(void)
{
    if (cleanup_active && x10_capture_slot_generation(observed_slot) != 0)
        revoked = 0;
}

static void *controlled_mmap(void *p, size_t n, int prot, int flags,
    int fd, off_t offset)
{
    void *mapped;
    note_cleanup();
    if (fail(MAP)) { errno = ENOMEM; return MAP_FAILED; }
    CHECK(prot == PROT_NONE && n % 3 == 0);
    mapped = mmap(p, n, prot, flags, fd, offset);
    if (mapped != MAP_FAILED) {
        owned_mapping = mapped; owned_size = n / 3;
        owned_page = owned_mapping + owned_size;
    }
    return mapped;
}

static int controlled_mprotect(void *p, size_t n, int prot)
{
    enum fault point = READ_ONLY;
    int result;
    note_cleanup();
    CHECK(p == owned_page && n == owned_size);
    if (prot == (PROT_READ | PROT_WRITE))
        point = ++rw_calls == 1 ? INITIAL_RW : RESTORE_RW;
    else CHECK(prot == PROT_READ);
    if (fail(point)) { errno = EACCES; return -1; }
    result = mprotect(p, n, prot);
    if (result == 0) page_readable = 1;
    return result;
}

static int controlled_mlock(const void *p, size_t n)
{
    note_cleanup();
    if (fail(LOCK)) { errno = ENOMEM; return -1; }
    /* ASan's mlock interceptor may report success without locking. Exercise
     * the actual Linux syscall in both builds, rather than weaken VmFlags. */
    return (int) syscall(SYS_mlock, p, n);
}

static int controlled_madvise(void *p, size_t n, int advice)
{
    enum fault point = advice == MADV_DONTDUMP ? DUMP : FORK;
    note_cleanup();
    CHECK(advice == MADV_DONTDUMP || advice == MADV_DONTFORK);
    if (fail(point)) { errno = EINVAL; return -1; }
    return madvise(p, n, advice);
}

static int controlled_munlock(const void *p, size_t n)
{
    note_cleanup();
    if (!all_zero()) unlock_nonzero = 1;
    else zero_before_unlock++;
    if (fail(UNLOCK)) { errno = EIO; return -1; }
    return (int) syscall(SYS_munlock, p, n);
}

static int controlled_munmap(void *p, size_t n)
{
    int result;
    note_cleanup();
    if (page_readable) {
        if (all_zero()) zero_before_unmap++;
        else copied_before_unmap++;
    }
    if (fail(UNMAP)) { errno = EIO; return -1; }
    result = munmap(p, n);
    if (result == 0) {
        owned_mapping = owned_page = NULL; page_readable = 0;
    }
    return result;
}

static long controlled_sysconf(int name)
{
    CHECK(name == _SC_PAGESIZE);
    if (fault_a == PAGE_SMALL) return 4095;
    if (fault_a == PAGE_LARGE) return 65537;
    return sysconf(name);
}

static int controlled_clock_gettime(clockid_t id, struct timespec *ts)
{
    if (fail(CLOCK)) { errno = EIO; return -1; }
    return clock_gettime(id, ts);
}

#define mmap controlled_mmap
#define mprotect controlled_mprotect
#define mlock controlled_mlock
#define madvise controlled_madvise
#define munlock controlled_munlock
#define munmap controlled_munmap
#define sysconf controlled_sysconf
#define clock_gettime controlled_clock_gettime
#include "openssl-capture.c"
#undef mmap
#undef mprotect
#undef mlock
#undef madvise
#undef munlock
#undef munmap
#undef sysconf
#undef clock_gettime

static X10_PROBE_RESULT observation;

int x10_openssl_probe(const SSL *s, const X10_PROBE_LEDGER *ledger,
    X10_PROBE_RESULT *out)
{
    (void) s; (void) ledger;
    probe_calls++; *out = observation; return 1;
}

static const char nonce[33] = "0123456789abcdef0123456789abcdef";
static X10_PROBE_LEDGER ledger;
static volatile sig_atomic_t interrupted;

static SSL *source(SSL_CTX *ctx)
{
    SSL *s = SSL_new(ctx);
    const unsigned char cipher[2] = { 0x13, 0x01 };
    const unsigned char key[16] = { 0xa5 };
    const unsigned char iv[12] = { 0x5a };
    CHECK(s != NULL && s->session == NULL);
    s->session = SSL_SESSION_new(); CHECK(s->session != NULL);
    s->session->cipher = SSL_CIPHER_find(s, cipher);
    CHECK(s->session->cipher != NULL);
    s->server = 1; s->version = TLS1_3_VERSION;
    s->enc_read_ctx = EVP_CIPHER_CTX_new();
    s->enc_write_ctx = EVP_CIPHER_CTX_new();
    CHECK(s->enc_read_ctx != NULL && s->enc_write_ctx != NULL);
    CHECK(EVP_DecryptInit_ex(s->enc_read_ctx, EVP_aes_128_gcm(),
                           NULL, key, iv) == 1);
    CHECK(EVP_EncryptInit_ex(s->enc_write_ctx, EVP_aes_128_gcm(),
                           NULL, key, iv) == 1);
    memset(s->client_app_traffic_secret, 0xa5, 32);
    memset(s->server_app_traffic_secret, 0x5a, 32);
    memset(s->read_iv, 0x33, 12); memset(s->write_iv, 0x44, 12);
    s->rlayer.read_sequence[7] = 3; s->rlayer.write_sequence[7] = 5;
    return s;
}

static void reset(const char *name, enum fault a, enum fault b)
{
    CHECK(owned_mapping == NULL);
    case_name = name; fault_a = a; fault_b = b;
    failures_a = failures_b = rw_calls = 0; persistent = 0;
    memset(calls, 0, sizeof(calls));
    probe_calls = 0; cleanup_active = 0; revoked = 1;
    zero_before_unlock = copied_before_unmap = zero_before_unmap = 0;
    unlock_nonzero = 0;
}

static int open_slot(SSL *s, X10_CAPTURE_RESULT *out)
{
    struct timespec ts;
    int64_t deadline;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    deadline = (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + 2500;
    observed_slot = x10_capture_slot_new(); CHECK(observed_slot != NULL);
    return x10_capture_slot_open(observed_slot, s, &ledger, &observation,
        nonce, deadline, &interrupted, out);
}

static void terminal(void)
{
    X10_CAPTURE_RESULT out;
    CHECK(x10_capture_slot_generation(observed_slot) == 0);
    CHECK(!x10_capture_slot_check(observed_slot, 1, NULL, &ledger,
                                  nonce, &interrupted));
    CHECK(!x10_capture_slot_open(observed_slot, NULL, NULL, NULL, nonce,
        0, &interrupted, &out));
    x10_capture_slot_free(observed_slot); observed_slot = NULL;
    CHECK(owned_mapping == NULL && revoked && !unlock_nonzero);
}

/* Controlled fault children never print addresses or inherited state. */
static void fault_exit(int number) { (void) number; _exit(77); }
static void access_refused(unsigned char *p, int write_byte)
{
    pid_t child = fork(); int status;
    CHECK(child >= 0);
    if (child == 0) {
        struct sigaction sa;
        alarm(2);
        memset(&sa, 0, sizeof(sa)); sa.sa_handler = fault_exit;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGSEGV, &sa, NULL) != 0
            || sigaction(SIGBUS, &sa, NULL) != 0) _exit(78);
        if (write_byte) *(volatile unsigned char *) p = 1;
        else { volatile unsigned char value = *p; (void) value; }
        _exit(79);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

static void protection_flags(void)
{
    FILE *f = fopen("/proc/self/smaps", "r");
    char line[1024]; unsigned long lo, hi;
    int matched = 0, checked = 0;
    CHECK(f != NULL);
    while (fgets(line, sizeof(line), f) != NULL) {
        if (sscanf(line, "%lx-%lx", &lo, &hi) == 2)
            matched = (uintptr_t) owned_page >= lo && (uintptr_t) owned_page < hi;
        else if (matched && strncmp(line, "VmFlags:", 8) == 0) {
            CHECK(strstr(line, " dd ") != NULL && strstr(line, " dc ") != NULL
                  && strstr(line, " lo ") != NULL);
            checked = 1;
        }
    }
    CHECK(fclose(f) == 0 && checked);
}

int main(void)
{
    SSL_CTX *ctx; SSL *s;
    X10_CAPTURE_RESULT out, again;
    enum fault point;
    unsigned char *mapping; size_t size;
    unsigned char vec[3]; uint64_t saved_generation;
    static const char *names[] = { "none", "mmap", "initial-rw", "mlock",
        "dontdump", "dontfork", "read-only", "restore-rw", "munlock",
        "munmap", "clock", "page-small", "page-large" };
    case_name = "setup";
    memset(&observation, 0, sizeof(observation));
    observation.allowed = observation.schema_version = 1;
    observation.mutation_serial = 2; observation.ledger_call_serial = 7;
    ctx = SSL_CTX_new(TLS_server_method()); CHECK(ctx != NULL);
    s = source(ctx);

    reset("protected-ready", NONE, NONE);
    CHECK(open_slot(s, &out));
    CHECK(out.captured && out.locked && out.dont_dump && out.dont_fork
          && out.read_only && out.source_unchanged && !out.cleansed);
    CHECK(x10_capture_slot_generation(observed_slot) != 0);
    protection_flags();
    /* DONTFORK removes the center in a child; the outer guards stay NONE. */
    access_refused(owned_mapping, 0);
    access_refused(owned_page + owned_size, 0);
    access_refused(owned_page, 0);
    /* Independently remove DONTFORK in this synthetic-only mapping to prove
     * read-only protection is not merely the fork exclusion. */
    CHECK(madvise(owned_page, owned_size, MADV_DOFORK) == 0);
    access_refused(owned_page, 1);
    CHECK(madvise(owned_page, owned_size, MADV_DONTFORK) == 0);
    /* Fill padding as well: cleanup must erase the entire accessible page. */
    CHECK(mprotect(owned_page, owned_size, PROT_READ | PROT_WRITE) == 0);
    memset(owned_page + sizeof(X10_CAPTURE_MATERIAL), 0xa5,
           owned_size - sizeof(X10_CAPTURE_MATERIAL));
    CHECK(mprotect(owned_page, owned_size, PROT_READ) == 0);
    mapping = owned_mapping; size = owned_size; cleanup_active = 1;
    CHECK(x10_capture_slot_cleanup(observed_slot, &out));
    CHECK(out.cleansed && out.unmapped && zero_before_unlock == 1
          && zero_before_unmap == 1 && copied_before_unmap == 0);
    errno = 0; CHECK(mincore(mapping, size * 3, vec) == -1 && errno == ENOMEM);
    CHECK(x10_capture_slot_cleanup(observed_slot, &again));
    CHECK(memcmp(&out, &again, sizeof(out)) == 0);
    terminal(); scenarios++;

    for (point = MAP; point <= READ_ONLY; point++) {
        reset(names[point], point, NONE);
        CHECK(!open_slot(s, &out)); cleanup_active = 1;
        CHECK(x10_capture_slot_generation(observed_slot) == 0);
        CHECK(out.captured == (point == READ_ONLY));
        CHECK(owned_mapping == NULL && !unlock_nonzero);
        CHECK(point == MAP || out.unmapped);
        CHECK(point != READ_ONLY || (out.cleansed && zero_before_unmap == 1));
        terminal(); scenarios++;
    }

    for (point = RESTORE_RW; point <= UNMAP; point++) {
        reset(names[point], NONE, NONE); CHECK(open_slot(s, &out));
        fault_a = point; cleanup_active = 1;
        CHECK(!x10_capture_slot_cleanup(observed_slot, &out));
        CHECK(x10_capture_slot_generation(observed_slot) == 0);
        CHECK(!unlock_nonzero);
        CHECK(point != RESTORE_RW || (!out.cleansed && out.unmapped
              && calls[UNLOCK] == 0));
        CHECK(point != UNLOCK || (out.cleansed && out.unmapped));
        CHECK(point != UNMAP || (out.cleansed && !out.unmapped
              && owned_mapping != NULL));
        fault_a = NONE;
        CHECK(!x10_capture_slot_cleanup(observed_slot, &again));
        CHECK(owned_mapping == NULL);
        terminal(); scenarios++;
    }

    reset("restore-and-unmap-recovery", NONE, NONE);
    CHECK(open_slot(s, &out)); fault_a = RESTORE_RW; fault_b = UNMAP;
    cleanup_active = 1;
    CHECK(!x10_capture_slot_cleanup(observed_slot, &out));
    CHECK(!out.cleansed && !out.unmapped && owned_mapping != NULL);
    CHECK(calls[UNLOCK] == 0 && !unlock_nonzero);
    fault_a = fault_b = NONE;
    CHECK(!x10_capture_slot_cleanup(observed_slot, &again));
    CHECK(again.cleansed && again.unmapped && owned_mapping == NULL
          && zero_before_unlock == 1);
    terminal(); scenarios++;

    reset("persistent-fault-then-recovery", NONE, NONE);
    CHECK(open_slot(s, &out)); fault_a = RESTORE_RW; fault_b = UNMAP;
    persistent = 1; cleanup_active = 1;
    CHECK(!x10_capture_slot_cleanup(observed_slot, &out));
    CHECK(!x10_capture_slot_cleanup(observed_slot, &again));
    CHECK(!again.cleansed && !again.unmapped && owned_mapping != NULL
          && calls[UNLOCK] == 0 && !unlock_nonzero);
    fault_a = fault_b = NONE;
    CHECK(!x10_capture_slot_cleanup(observed_slot, &again));
    CHECK(again.cleansed && again.unmapped && owned_mapping == NULL);
    terminal(); scenarios++;

    reset("persistent-unmap-then-recovery", NONE, NONE);
    CHECK(open_slot(s, &out)); fault_a = UNMAP;
    persistent = 1; cleanup_active = 1;
    CHECK(!x10_capture_slot_cleanup(observed_slot, &out));
    CHECK(out.cleansed && !out.unmapped && owned_mapping != NULL);
    CHECK(!x10_capture_slot_cleanup(observed_slot, &again));
    CHECK(again.cleansed && !again.unmapped && owned_mapping != NULL
          && calls[UNLOCK] == 1 && zero_before_unlock == 1);
    fault_a = NONE;
    CHECK(!x10_capture_slot_cleanup(observed_slot, &again));
    CHECK(again.cleansed && again.unmapped && owned_mapping == NULL);
    terminal(); scenarios++;

    reset("free-retries-live-failed-mapping", NONE, NONE);
    CHECK(open_slot(s, &out)); fault_a = UNMAP; cleanup_active = 1;
    CHECK(!x10_capture_slot_cleanup(observed_slot, &out));
    CHECK(owned_mapping != NULL); fault_a = NONE;
    x10_capture_slot_free(observed_slot); observed_slot = NULL;
    CHECK(owned_mapping == NULL && !unlock_nonzero && revoked);
    scenarios++;

    for (point = CLOCK; point <= PAGE_LARGE; point++) {
        reset(names[point], point, NONE);
        CHECK(!open_slot(s, &out));
        CHECK(!out.captured && owned_mapping == NULL);
        cleanup_active = 1; terminal(); scenarios++;
    }

    reset("generation-exhaustion", NONE, NONE);
    saved_generation = capture_generation; capture_generation = UINT64_MAX;
    CHECK(!open_slot(s, &out));
    CHECK(!out.captured && owned_mapping == NULL);
    capture_generation = saved_generation; cleanup_active = 1;
    terminal(); scenarios++;

    SSL_free(s); SSL_CTX_free(ctx);
    printf("{\"passed\":true,\"scenarios\":%u,\"actualTLS\":false,"
           "\"syntheticDataOnly\":true,\"productionTranslationUnit\":true,"
           "\"wholePageCleanse\":true,\"protectionFlags\":true,"
           "\"guardAndForkControls\":4,\"stickyFailure\":true,"
           "\"failedMappingRecovery\":true,\"unownedMappings\":0}\n", scenarios);
    return 0;
}
