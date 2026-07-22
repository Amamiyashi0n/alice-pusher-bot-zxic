#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <asm/unistd.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

#define MAX_TRACED_THREADS 96
#define REMOTE_COPY_MAX 4096
#define STREAM_MAX 8192
#define CMT_MARKER "+CMT: "
#define CMT_MARKER_LEN 6

typedef struct {
    pid_t tid;
    int attached;
    int syscall_active;
    int capture;
    unsigned long buffer;
} tracee_t;

static volatile sig_atomic_t stop_requested;
static unsigned char stream_buffer[STREAM_MAX];
static size_t stream_length;

static void on_signal(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static int write_all(int fd, const char *buffer, size_t length) {
    while (length > 0) {
        ssize_t written = write(fd, buffer, length);
        if (written > 0) {
            buffer += written;
            length -= (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        return -1;
    }
    return 0;
}

static size_t find_bytes(const unsigned char *haystack, size_t haystack_length,
                         const unsigned char *needle, size_t needle_length,
                         size_t start) {
    size_t i;

    if (needle_length == 0 || start > haystack_length ||
        needle_length > haystack_length - start)
        return (size_t)-1;
    for (i = start; i + needle_length <= haystack_length; i++) {
        if (memcmp(haystack + i, needle, needle_length) == 0)
            return i;
    }
    return (size_t)-1;
}

static void emit_escaped_record(const unsigned char *record, size_t length) {
    char output[REMOTE_COPY_MAX * 2 + 32];
    size_t output_length = 0;
    size_t i;

    for (i = 0; i < length && output_length + 5 < sizeof(output); i++) {
        unsigned char c = record[i];
        if (c == '\r') {
            output[output_length++] = '\\';
            output[output_length++] = 'r';
        } else if (c == '\n') {
            output[output_length++] = '\\';
            output[output_length++] = 'n';
        } else if (c == '\\') {
            output[output_length++] = '\\';
            output[output_length++] = '\\';
        } else if (c >= 0x20 && c <= 0x7e) {
            output[output_length++] = (char)c;
        } else {
            static const char hex[] = "0123456789ABCDEF";
            output[output_length++] = '\\';
            output[output_length++] = 'x';
            output[output_length++] = hex[(c >> 4) & 0xf];
            output[output_length++] = hex[c & 0xf];
        }
    }
    output[output_length++] = '\n';
    write_all(STDERR_FILENO, output, output_length);
}

static void consume_stream(size_t length) {
    if (length >= stream_length) {
        stream_length = 0;
        return;
    }
    memmove(stream_buffer, stream_buffer + length, stream_length - length);
    stream_length -= length;
}

static void emit_complete_cmt_records(void) {
    static const unsigned char marker[] = CMT_MARKER;
    static const unsigned char crlf[] = "\r\n";

    for (;;) {
        size_t start = find_bytes(stream_buffer, stream_length, marker,
                                  CMT_MARKER_LEN, 0);
        size_t header_end;
        size_t pdu_end;

        if (start == (size_t)-1) {
            if (stream_length > CMT_MARKER_LEN - 1) {
                memmove(stream_buffer,
                        stream_buffer + stream_length - (CMT_MARKER_LEN - 1),
                        CMT_MARKER_LEN - 1);
                stream_length = CMT_MARKER_LEN - 1;
            }
            return;
        }
        if (start > 0) {
            consume_stream(start);
            continue;
        }

        header_end = find_bytes(stream_buffer, stream_length, crlf, 2,
                                CMT_MARKER_LEN);
        if (header_end == (size_t)-1)
            return;
        pdu_end = find_bytes(stream_buffer, stream_length, crlf, 2,
                             header_end + 2);
        if (pdu_end == (size_t)-1)
            return;
        if (pdu_end <= header_end + 2) {
            consume_stream(pdu_end + 2);
            continue;
        }

        emit_escaped_record(stream_buffer, pdu_end + 2);
        consume_stream(pdu_end + 2);
    }
}

static void append_stream(const unsigned char *data, size_t length) {
    if (length == 0)
        return;
    if (length >= sizeof(stream_buffer)) {
        data += length - sizeof(stream_buffer);
        length = sizeof(stream_buffer);
        stream_length = 0;
    }
    if (stream_length + length > sizeof(stream_buffer)) {
        size_t keep = CMT_MARKER_LEN - 1;
        if (stream_length > keep) {
            memmove(stream_buffer,
                    stream_buffer + stream_length - keep, keep);
            stream_length = keep;
        } else if (stream_length + length > sizeof(stream_buffer)) {
            stream_length = 0;
        }
    }
    if (length > sizeof(stream_buffer) - stream_length)
        length = sizeof(stream_buffer) - stream_length;
    memcpy(stream_buffer + stream_length, data, length);
    stream_length += length;
    emit_complete_cmt_records();
}

static int read_remote_memory(pid_t tid, unsigned long address,
                              unsigned char *output, size_t length) {
    size_t offset = 0;
    size_t word_size = sizeof(long);

    while (offset < length) {
        long word;
        size_t copy_length = word_size;
        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, tid,
                      (void *)(address + offset), 0);
        if (word == -1 && errno != 0)
            return -1;
        if (copy_length > length - offset)
            copy_length = length - offset;
        memcpy(output + offset, &word, copy_length);
        offset += copy_length;
    }
    return 0;
}

static void capture_syscall_result(tracee_t *tracee,
                                   const struct user_regs *registers) {
    long result = (long)registers->uregs[0];
    unsigned char data[REMOTE_COPY_MAX];
    size_t length;

    if (!tracee->capture || result <= 0)
        return;
    length = (size_t)result;
    if (length > sizeof(data))
        length = sizeof(data);
    if (read_remote_memory(tracee->tid, tracee->buffer, data, length) == 0)
        append_stream(data, length);
}

static int add_tracee(tracee_t *tracees, size_t *tracee_count, pid_t tid) {
    size_t i;

    if (tid <= 0)
        return -1;
    for (i = 0; i < *tracee_count; i++) {
        if (tracees[i].tid == tid)
            return 0;
    }
    if (*tracee_count >= MAX_TRACED_THREADS)
        return -1;
    memset(&tracees[*tracee_count], 0, sizeof(tracees[*tracee_count]));
    tracees[*tracee_count].tid = tid;
    (*tracee_count)++;
    return 0;
}

static int enumerate_threads(pid_t pid, tracee_t *tracees,
                              size_t *tracee_count) {
    char path[64];
    DIR *directory;
    struct dirent *entry;

    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    directory = opendir(path);
    if (!directory)
        return add_tracee(tracees, tracee_count, pid);
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long tid;
        if (!isdigit((unsigned char)entry->d_name[0]))
            continue;
        tid = strtol(entry->d_name, &end, 10);
        if (!end || *end != '\0' || tid <= 0)
            continue;
        add_tracee(tracees, tracee_count, (pid_t)tid);
    }
    closedir(directory);
    return *tracee_count > 0 ? 0 : -1;
}

static int attach_tracee(tracee_t *tracee) {
    int status;

    if (ptrace(PTRACE_ATTACH, tracee->tid, 0, 0) < 0)
        return -1;
    if (waitpid(tracee->tid, &status, __WALL) < 0 ||
        !WIFSTOPPED(status)) {
        return -1;
    }
    tracee->attached = 1;
    if (ptrace(PTRACE_SETOPTIONS, tracee->tid, 0,
               PTRACE_O_TRACESYSGOOD) < 0) {
        fprintf(stderr, "sms-ptrace: setoptions tid=%d failed: %s\n",
                (int)tracee->tid, strerror(errno));
    }
    if (ptrace(PTRACE_SYSCALL, tracee->tid, 0, 0) < 0)
        return -1;
    return 0;
}

static void resume_tracee(tracee_t *tracee, int signal_number) {
    if (ptrace(PTRACE_SYSCALL, tracee->tid, 0,
               (void *)(long)signal_number) < 0 && errno != ESRCH)
        tracee->attached = 0;
}

static void handle_syscall_stop(tracee_t *tracee) {
    struct user_regs registers;
    long syscall_number;

    if (ptrace(PTRACE_GETREGS, tracee->tid, 0, &registers) < 0) {
        tracee->attached = 0;
        return;
    }
    if (!tracee->syscall_active) {
        syscall_number = (long)registers.uregs[7];
        tracee->capture = syscall_number == __NR_read ||
                          syscall_number == __NR_write;
        tracee->buffer = tracee->capture ? registers.uregs[1] : 0;
        tracee->syscall_active = 1;
        return;
    }
    capture_syscall_result(tracee, &registers);
    tracee->capture = 0;
    tracee->buffer = 0;
    tracee->syscall_active = 0;
}

static void detach_tracees(tracee_t *tracees, size_t tracee_count,
                           pid_t process_id) {
    size_t i;

    for (i = 0; i < tracee_count; i++) {
        if (!tracees[i].attached)
            continue;
        ptrace(PTRACE_DETACH, tracees[i].tid, 0, 0);
        tracees[i].attached = 0;
    }
    kill(process_id, SIGCONT);
}

static int trace_process(pid_t process_id) {
    tracee_t tracees[MAX_TRACED_THREADS];
    size_t tracee_count = 0;
    size_t attached_count = 0;
    size_t i;

    if (enumerate_threads(process_id, tracees, &tracee_count) < 0) {
        fprintf(stderr, "sms-ptrace: cannot enumerate pid=%d: %s\n",
                (int)process_id, strerror(errno));
        return 1;
    }
    for (i = 0; i < tracee_count; i++) {
        if (attach_tracee(&tracees[i]) == 0)
            attached_count++;
    }
    if (attached_count == 0) {
        fprintf(stderr, "sms-ptrace: cannot attach pid=%d: %s\n",
                (int)process_id, strerror(errno));
        return 1;
    }

    while (!stop_requested && attached_count > 0) {
        int status;
        pid_t tid = waitpid(-1, &status, __WALL);
        tracee_t *tracee = NULL;
        int signal_number;

        if (tid < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ECHILD)
                break;
            continue;
        }
        for (i = 0; i < tracee_count; i++) {
            if (tracees[i].tid == tid) {
                tracee = &tracees[i];
                break;
            }
        }
        if (!tracee || !tracee->attached)
            continue;
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            tracee->attached = 0;
            attached_count--;
            continue;
        }
        if (!WIFSTOPPED(status))
            continue;

        signal_number = WSTOPSIG(status);
        if (signal_number == (SIGTRAP | 0x80) ||
            signal_number == SIGTRAP) {
            if (signal_number == (SIGTRAP | 0x80))
                handle_syscall_stop(tracee);
            resume_tracee(tracee, 0);
        } else {
            if (signal_number == SIGSTOP || signal_number == SIGCHLD)
                signal_number = 0;
            resume_tracee(tracee, signal_number);
        }
    }
    detach_tracees(tracees, tracee_count, process_id);
    return 0;
}

static pid_t parse_pid(int argc, char **argv) {
    int i;
    for (i = 1; i < argc; i++) {
        const char *value = NULL;
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
            value = argv[++i];
        else if (strncmp(argv[i], "--pid=", 6) == 0)
            value = argv[i] + 6;
        if (value) {
            char *end = NULL;
            long pid = strtol(value, &end, 10);
            if (end && *end == '\0' && pid > 0)
                return (pid_t)pid;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    struct sigaction action;
    pid_t process_id;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("alice sms-ptrace helper 0.1 (ARM read/write +CMT)");
        return 0;
    }
    process_id = parse_pid(argc, argv);
    if (process_id <= 0) {
        fprintf(stderr, "usage: %s -p PID\n", argv[0]);
        return 2;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    return trace_process(process_id);
}
