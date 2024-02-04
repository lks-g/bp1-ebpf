/* Tento kód slúži na sledovanie otvorení súborov v systéme. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <bpf/bpf.h>

#define LOG_BUF_SIZE 65536

char _license[] SEC("license") = "GPL";

int _version SEC("version") = 1;

struct data_t {
    u64 ts;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
    u32 mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int BPF_PROG(sys_enter_openat)(struct pt_regs *ctx, int dfd, const char *filename, int flags, umode_t mode) {
    struct data_t data = {};
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read(&data.filename, sizeof(data.filename), (void *)filename);
    data.mode = mode;
    bpf_perf_event_output(ctx, &data, sizeof(data));
    return 0;
}

char _help[] SEC("help") = "Trace file opens in the system.";

int _print_bpf_output(struct data_t *data) {
    printf("[%5llu.%06llu] %s: opening file '%s' with mode %u\n", data->ts / 1000000, data->ts % 1000000, data->comm, data->filename, data->mode);
    return 0;
}

SEC("kprobe/tracing_mark_write")
int _bpf_event_output(struct pt_regs *ctx) {
    struct data_t data;
    u32 pid, cpu;
    u64 ts;

    pid = bpf_get_current_pid_tgid();
    cpu = bpf_get_smp_processor_id();
    ts = bpf_ktime_get_ns();

    bpf_perf_event_read(&data, sizeof(data));
    bpf_trace_printk("[%d] %llu.%06llu: %s: opening file '%s' with mode %u\n", pid, ts / 1000000, ts % 1000000, data.comm, data.filename, data.mode);

    return 0;
}

int main(int argc, char **argv) {
    int key, pid, cpu;

    key = 0;
    pid = bpf_get_current_pid_tgid();
    cpu = bpf_get_smp_processor_id();

    // Open perf event
    int fd = bpf_perf_event_open(sys_enter_openat, -1, key, -1, 0);
    if (fd < 0) {
        printf("Error opening perf event: %d\n", fd);
        return -1;
    }

    // Attach kprobe to tracing_mark_write
    int res = bpf_attach_kprobe(fd, _bpf_event_output, "tracing_mark_write");
    if (res < 0) {
        printf("Error attaching kprobe: %d\n", res);
        return -1;
    }

    // Print output
    int num_events = 0;
    while (1) {
        struct data_t data;
        int res = read(fd, &data, sizeof(data));
        if (res < 0) {
            if (errno == EINTR) {
                continue;
            }
            printf("Error reading perf event: %d\n", res);
            return -1;
        }

        _print_bpf_output(&data);
        num_events++;
    }

    return 0;
}