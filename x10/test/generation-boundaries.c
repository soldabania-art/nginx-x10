/* Production-TU counter and JSON boundaries; no network or worker ACK proof. */
#include <ngx_config.h>
#include <ngx_core.h>
#include <assert.h>
#include <stdio.h>

static char output[1024 * 1024];
static size_t output_size;
static ssize_t review_send(int fd, const void *buf, size_t length, int flags);
#define send review_send
#ifndef NGX_CONTROL_SOURCE
#define NGX_CONTROL_SOURCE "../../src/os/unix/ngx_control.c"
#endif
#include NGX_CONTROL_SOURCE
#undef send

volatile ngx_cycle_t *ngx_cycle;
ngx_pid_t ngx_pid = 12345;
ngx_int_t ngx_last_process;
ngx_process_t ngx_processes[NGX_MAX_PROCESSES];

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...) { (void)level; (void)log; (void)err; (void)fmt; }

static ssize_t review_send(int fd, const void *buf, size_t length, int flags) {
    (void)fd; (void)flags;
    assert(length < sizeof(output) - output_size);
    memcpy(output + output_size, buf, length);
    output_size += length;
    output[output_size] = '\0';
    return (ssize_t)length;
}

static void reset(ngx_cycle_t *cycle) {
    memset(ngx_processes, 0, sizeof(ngx_processes));
    ngx_last_process = 0;
    ngx_control_pollfd_n = 1;
    ngx_control_generation_start(cycle);
}
static void spawn_record(ngx_cycle_t *cycle, int slot, int pid, int detached) {
    ngx_processes[slot].pid = pid;
    ngx_processes[slot].name = "worker process";
    ngx_processes[slot].detached = detached;
    if (ngx_last_process <= slot) ngx_last_process = slot + 1;
    ngx_control_process_spawned(cycle, slot, pid, detached);
}
static void emit(const char *name) {
    ngx_control_request_t request;
    ngx_control_process_identity_t before[NGX_MAX_PROCESSES];
    ngx_log_t log;
    memset(&request, 0, sizeof(request)); memset(&log, 0, sizeof(log));
    memcpy(before, ngx_control_identities, sizeof(before));
    request.pool = ngx_create_pool(16384, &log); assert(request.pool);
    request.fd = 42;
    output_size = 0; output[0] = '\0';
    assert(ngx_control_show_generations(&request) == NGX_DONE);
    assert(memcmp(before, ngx_control_identities, sizeof(before)) == 0);
    assert(strstr(output, "HTTP/1.1 200 OK\r\n") == output);
    char *body = strstr(output, "\r\n\r\n"); assert(body);
    printf("%s\t%s\n", name, body + 4);
    ngx_destroy_pool(request.pool);
}
int main(void) {
    ngx_cycle_t a, b, c;
    memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b)); memset(&c, 0, sizeof(c));
    reset(&a); spawn_record(&a, 0, 101, 0); spawn_record(&a, 1, 102, 0);
    emit("initial-two-workers");
    ngx_control_generation_commit(&b); ngx_control_generation_commit(&c);
    assert(ngx_control_generation == 3); emit("two-cycle-commits-before-spawn");
    spawn_record(&c, 0, 103, 0); emit("respawn-overwrites-slot");
    spawn_record(&c, 0, 103, 0); emit("same-pid-new-birth");
    ngx_processes[0].pid = 104; emit("stale-slot-pid");
    reset(&a); spawn_record(&b, 0, 105, 0); emit("unclassified-cycle");
    reset(&a); spawn_record(&a, 0, 106, 0); spawn_record(&a, 1, 107, 1);
    assert(ngx_control_birth == 1); emit("detached-excluded");
    uint64_t before = ngx_control_birth;
    ngx_control_process_spawned(&a, -1, 108, 0);
    ngx_control_process_spawned(&a, NGX_MAX_PROCESSES, 109, 0);
    assert(ngx_control_birth == before); emit("invalid-slot-noop");
    reset(&a); ngx_control_generation = UINT64_C(4294967419);
    ngx_control_birth = UINT64_C(9007199254741103);
    ngx_control_generation_commit(&b); spawn_record(&b, 0, 110, 0);
    emit("wide-decimal-identities");
    reset(&a); ngx_control_generation = UINT64_MAX - 1;
    ngx_control_generation_commit(&b); spawn_record(&b, 0, 111, 0);
    emit("last-generation-value");
    ngx_control_generation_commit(&c); emit("generation-exhausted");
    spawn_record(&c, 0, 112, 0); ngx_control_generation_commit(&a);
    assert(ngx_control_generation == UINT64_MAX && ngx_control_birth == 1);
    emit("generation-exhaustion-latched");
    reset(&a); ngx_control_birth = UINT64_MAX - 1;
    spawn_record(&a, 0, 113, 0); emit("last-birth-value");
    spawn_record(&a, 1, 114, 0); emit("birth-exhausted");
    assert(ngx_control_birth == UINT64_MAX && ngx_control_identity_exhausted);
    ngx_control_generation_commit(&b); spawn_record(&b, 2, 115, 0);
    assert(ngx_control_generation == 1 && ngx_control_birth == UINT64_MAX);
    emit("birth-exhaustion-latched");
    reset(&a); ngx_control_generation = 0; emit("uninitialized");
    reset(&a); spawn_record(&a, 0, 116, 0);
    ngx_control_pollfd_n = 0; ngx_control_generation_commit(&b);
    ngx_control_process_spawned(&b, 0, 117, 0);
    assert(ngx_control_generation == 1 && ngx_control_birth == 1 && ngx_control_identities[0].pid == 116);
    ngx_control_pollfd_n = 1; emit("inactive-hooks-noop");
    reset(&c); assert(ngx_control_generation == 1 && ngx_control_birth == 0);
    emit("master-start-reset");
    return 0;
}
