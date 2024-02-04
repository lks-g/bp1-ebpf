/* This program uses eBPF to attach a trace function to the do_execve kprobe, which is called every time 
an executable file is executed in the system. The trace function increments a count in a BPF hash map for each process id (pid) 
that is executing a file. This allows you to monitor for any unusual execution patterns that might indicate fileless malware. 

!! Note that this is just a simple example and does not cover all aspects of detecting fileless malware. !!

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>

const char *program =
    "#include <uapi/linux/ptrace.h>\n"
    "#include <linux/sched.h>\n"
    "\n"
    "BPF_HASH(events, u32, u64);\n"
    "\n"
    "int trace_execve(struct pt_regs *ctx)\n"
    "{\n"
    "    u32 pid = bpf_get_current_pid_tgid() >> 32;\n"
    "    u64 zero = 0, *val;\n"
    "\n"
    "    val = events.lookup_or_init(&pid, &zero);\n"
    "    (*val)++;\n"
    "    return 0;\n"
    "};\n";

int main(int argc, char **argv) {
    int ret;
    int prog_fd;
    char err_buf[256];

    prog_fd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, program, strlen(program), "GPL", 0, err_buf, sizeof(err_buf));

    if (prog_fd < 0) {
        fprintf(stderr, "Error loading BPF program: %s\n", err_buf);
        return -1;
    }

    ret = bpf_attach_kprobe(prog_fd, "do_execve", trace_execve, 0, NULL);
    if (ret < 0) {
        fprintf(stderr, "Error attaching BPF program to kprobe: %s\n",
                strerror(errno));
        return -1;
    }

    printf("BPF program loaded and attached to kprobe!\n");

    while (1) {
        sleep(1);
    }

    return 0;
}
