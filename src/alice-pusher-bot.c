#include <time.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/version.h>
#include "alice-pusher-bot.h"
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdint.h>
#define MAX_BUFFER_LEN 2048
#define STRACE_QUEUE_LINES 16
#define SMS_TEXT_MAX 512
#define SMS_CONCAT_MAX_PARTS ALICE_ENGINE_CONCAT_MAX_PARTS
#define SMS_CONCAT_MAX_ACTIVE ALICE_ENGINE_CONCAT_MAX_ACTIVE
#define SMS_CONCAT_TIMEOUT_SECONDS ALICE_ENGINE_CONCAT_TIMEOUT_SECONDS
#define SMS_CONCAT_MAX_TEXT ALICE_ENGINE_SMS_MAX_BYTES
#define SMS_PUSH_MESSAGE_MAX ALICE_ENGINE_PUSH_MESSAGE_MAX
#define SMS_PAYLOAD_MAX ALICE_ENGINE_PAYLOAD_MAX
#define TARGET_MIFI_PATH ALICE_TARGET_MIFI_PATH
#define TARGET_UFI_PATH ALICE_TARGET_UFI_PATH

static char g_target_path[256] = TARGET_MIFI_PATH;

static const int g_webhook_ciphersuites[] = {
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
    0
};


// 函数声明
static pid_t get_strace_pid_from_file(void);
static void set_strace_pid_to_file(pid_t pid);
int alice_engine_send_webhook_msg(const char *webhook, const char *platform,
                                    const char *txt, const char *custom_ctype,
                                    const char *custom_body);
static void print_mbedtls_error(int ret, const char *msg);
static void parse_url(const char *url, char **host, char **path);
static void engine_signal_handler(int sig);
static int find_process_by_exe_path(const char *exe_path);
static void sigcont_process_by_path(const char *exe_path);
static void json_escape(char *out, size_t outsz, const char *in);
static void safe_copy(char *dst, size_t dstsz, const char *src);
static void load_device_msisdn_from_nv_show(void);
static void* strace_thread_func(void* arg);
static void* pdu_thread_func(void* arg);
static void engine_log(const char *fmt, ...);
struct sms_info;
static int decode_pdu(const char *pdu, struct sms_info *info);
static int smtp_send_message(const char *host, const char *port,
                             const char *user, const char *password,
                             const char *from, const char *to,
                             const char *security, const char *txt);

// 线程控制变量
static volatile int threads_running = 1;
static pthread_t strace_thread_id;
static pthread_t pdu_thread_id;
static char device_msisdn[64] = "";
static alice_engine_log_fn g_log_fn;
static void *g_log_ctx;

static void process_strace_line_for_sms(
    const char *line, const alice_engine_push_target_t *targets,
    size_t target_count, int long_sms_reassembly);
static void expire_concat_assemblies(time_t now);

typedef struct {
    const alice_engine_push_target_t *targets;
    size_t target_count;
    int long_sms_reassembly;
} pdu_thread_args_t;

typedef struct {
    char lines[STRACE_QUEUE_LINES][MAX_BUFFER_LEN];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} strace_line_queue_t;

static strace_line_queue_t g_strace_queue = {
    .head = 0,
    .tail = 0,
    .count = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
};

void alice_engine_set_log_callback(alice_engine_log_fn fn, void *ctx) {
    g_log_fn = fn;
    g_log_ctx = ctx;
}

static void engine_log(const char *fmt, ...) {
    char line[2048];
    va_list ap;

    if (!fmt)
        return;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    if (g_log_fn) {
        g_log_fn(g_log_ctx, line);
        return;
    }
    fprintf(stderr, "%s\n", line);
    fflush(stderr);
}

static void strace_queue_push_line(const char *line) {
    pthread_mutex_lock(&g_strace_queue.mutex);
    if (g_strace_queue.count == (int)(sizeof(g_strace_queue.lines) / sizeof(g_strace_queue.lines[0]))) {
        g_strace_queue.head = (g_strace_queue.head + 1) % (int)(sizeof(g_strace_queue.lines) / sizeof(g_strace_queue.lines[0]));
        g_strace_queue.count--;
    }
    strncpy(g_strace_queue.lines[g_strace_queue.tail], line, MAX_BUFFER_LEN - 1);
    g_strace_queue.lines[g_strace_queue.tail][MAX_BUFFER_LEN - 1] = 0;
    g_strace_queue.tail = (g_strace_queue.tail + 1) % (int)(sizeof(g_strace_queue.lines) / sizeof(g_strace_queue.lines[0]));
    g_strace_queue.count++;
    pthread_cond_signal(&g_strace_queue.cond);
    pthread_mutex_unlock(&g_strace_queue.mutex);
}

static int strace_queue_pop_line(char *out, size_t outlen, int timeout_ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&g_strace_queue.mutex);
    while (threads_running && g_strace_queue.count == 0) {
        if (pthread_cond_timedwait(&g_strace_queue.cond, &g_strace_queue.mutex, &ts) == ETIMEDOUT) {
            pthread_mutex_unlock(&g_strace_queue.mutex);
            return 0;
        }
    }
    if (!threads_running || g_strace_queue.count == 0) {
        pthread_mutex_unlock(&g_strace_queue.mutex);
        return 0;
    }
    strncpy(out, g_strace_queue.lines[g_strace_queue.head], outlen - 1);
    out[outlen - 1] = 0;
    g_strace_queue.head = (g_strace_queue.head + 1) % (int)(sizeof(g_strace_queue.lines) / sizeof(g_strace_queue.lines[0]));
    g_strace_queue.count--;
    pthread_mutex_unlock(&g_strace_queue.mutex);
    return 1;
}

static time_t get_next_midnight_epoch(void) {
    time_t now = time(NULL);
    struct tm *tm_now_ptr = localtime(&now);
    if (!tm_now_ptr) return now + 24 * 3600;
    struct tm tm_now = *tm_now_ptr;
    tm_now.tm_hour = 0;
    tm_now.tm_min = 0;
    tm_now.tm_sec = 0;
    time_t today_midnight = mktime(&tm_now);
    return today_midnight + 24 * 3600;
}

static int start_strace_with_pipe(int target_pid, pid_t *out_strace_pid, int *out_read_fd) {
    int fds[2];
    if (pipe(fds) != 0) return -1;

    pid_t child = fork();
    if (child == 0) {
        close(fds[0]);
        dup2(fds[1], STDERR_FILENO);
        close(fds[1]);

        char pidstr[16];
        snprintf(pidstr, sizeof(pidstr), "%d", target_pid);
        execl("/tmp/strace", "strace", "-f", "-e", "trace=read,write", "-s", "1024", "-p", pidstr, (char*)NULL);
        execl("/sbin/strace", "strace", "-f", "-e", "trace=read,write", "-s", "1024", "-p", pidstr, (char*)NULL);
        _exit(127);
    }

    if (child < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    close(fds[1]);
    int flags = fcntl(fds[0], F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
    }
    *out_strace_pid = child;
    *out_read_fd = fds[0];
    return 0;
}

// 用文件记录strace子进程pid，便于跨进程kill
static pid_t get_strace_pid_from_file() {
    FILE *fp = fopen("/tmp/zte_strace.pid", "r");
    if (!fp) return 0;
    pid_t pid = 0;
    fscanf(fp, "%d", &pid);
    fclose(fp);
    return pid;
}
static void set_strace_pid_to_file(pid_t pid) {
    FILE *fp = fopen("/tmp/zte_strace.pid", "w");
    if (fp) {
        fprintf(fp, "%d", pid);
        fclose(fp);
    }
}

// 查找指定可执行文件路径的进程 pid，返回第一个找到的 pid，找不到返回 -1
static int find_process_by_exe_path(const char *exe_path) {
    DIR *dir;
    struct dirent *entry;
    char path[256], buf[256];
    int pid = -1;
    if (!exe_path || !exe_path[0]) return -1;
    dir = opendir("/proc");
    if (!dir) return -1;
    while ((entry = readdir(dir)) != NULL) {
        int id = atoi(entry->d_name);
        if (id <= 0) continue;
        snprintf(path, sizeof(path), "/proc/%d/exe", id);
        ssize_t len = readlink(path, buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            if (strcmp(buf, exe_path) == 0) {
                pid = id;
                break;
            }
        }
    }
    closedir(dir);
    return pid;
}

static void sigcont_process_by_path(const char *exe_path) {
    int pid = find_process_by_exe_path(exe_path);
    if (pid > 0)
        kill(pid, SIGCONT);
}



static void reset_strace_queue(void) {
    pthread_mutex_lock(&g_strace_queue.mutex);
    g_strace_queue.head = 0;
    g_strace_queue.tail = 0;
    g_strace_queue.count = 0;
    pthread_cond_broadcast(&g_strace_queue.cond);
    pthread_mutex_unlock(&g_strace_queue.mutex);
}

static void safe_copy(char *dst, size_t dstsz, const char *src) {
    if (!dstsz) return;
    if (!src) src = "";
    strncpy(dst, src, dstsz - 1);
    dst[dstsz - 1] = 0;
}

static void json_escape(char *out, size_t outsz, const char *in) {
    size_t used = 0;
    if (!outsz) return;
    if (!in) in = "";
    while (*in && used + 1 < outsz) {
        unsigned char c = (unsigned char)*in++;
        if (c == '"' || c == '\\') {
            if (used + 2 >= outsz) break;
            out[used++] = '\\';
            out[used++] = (char)c;
        } else if (c == '\n' || c == '\r') {
            if (used + 2 >= outsz) break;
            out[used++] = '\\';
            out[used++] = 'n';
        } else if (c < 0x20) {
            continue;
        } else {
            out[used++] = (char)c;
        }
    }
    out[used] = 0;
}

const char *alice_engine_normalize_platform(const char *platform) {
    if (!platform || !platform[0]) return "dingtalk";
    if (strcmp(platform, "dingtalk") == 0) return "dingtalk";
    if (strcmp(platform, "feishu") == 0) return "feishu";
    if (strcmp(platform, "wecom") == 0) return "wecom";
    if (strcmp(platform, "serverchan") == 0) return "serverchan";
    if (strcmp(platform, "discord") == 0) return "discord";
    if (strcmp(platform, "telegram") == 0) return "telegram";
    if (strcmp(platform, "bark") == 0) return "bark";
    if (strcmp(platform, "custom") == 0) return "custom";
    return "dingtalk";
}

const char *alice_engine_detect_platform_from_url(const char *url) {
    if (!url) return "dingtalk";
    if (strstr(url, "open.feishu.cn") || strstr(url, "feishu.cn/"))
        return "feishu";
    if (strstr(url, "qyapi.weixin.qq.com") ||
        strstr(url, "work.weixin.qq.com"))
        return "wecom";
    if (strstr(url, "sctapi.ftqq.com") || strstr(url, "sc.ftqq.com"))
        return "serverchan";
    if (strstr(url, "discord.com/api/webhooks/") ||
        strstr(url, "discordapp.com/api/webhooks/"))
        return "discord";
    if (strstr(url, "api.telegram.org/bot"))
        return "telegram";
    if (strstr(url, "api.day.app"))
        return "bark";
    return "dingtalk";
}

int alice_engine_send_once(const char *webhook,
                           const char *platform,
                           const char *txt,
                           const char *custom_ctype,
                           const char *custom_body) {
    const char *p;

    if (!webhook || !webhook[0] || !txt)
        return -1;
    p = alice_engine_normalize_platform(platform && platform[0] ?
                                        platform :
                                        alice_engine_detect_platform_from_url(webhook));
    return alice_engine_send_webhook_msg(webhook, p, txt,
                                         custom_ctype, custom_body);
}

static const char *push_target_name(const alice_engine_push_target_t *target,
                                    size_t index) {
    if (target && target->name && target->name[0])
        return target->name;
    return target && target->type && strcmp(target->type, "email") == 0 ?
           "邮箱" : index < ALICE_ENGINE_MAX_TARGETS ? "Webhook" : "目标";
}

static int send_one_target_message(const alice_engine_push_target_t *target,
                                   size_t index, const char *txt) {
    const char *name;
    int rc = -1;

    if (!target || !target->enabled || !txt)
        return -1;
    name = push_target_name(target, index);
    if (target->type && strcmp(target->type, "email") == 0) {
        if (target->smtp_host && target->smtp_host[0] &&
            target->smtp_from && target->smtp_from[0] &&
            target->smtp_to && target->smtp_to[0]) {
            rc = smtp_send_message(target->smtp_host, target->smtp_port,
                                   target->smtp_user, target->smtp_password,
                                   target->smtp_from, target->smtp_to,
                                   target->smtp_security, txt);
        }
        if (rc < 0)
            engine_log("[PUSH][%s] email delivery failed", name);
        else
            engine_log("[PUSH][%s] email delivery succeeded", name);
    } else if (target->webhook && target->webhook[0]) {
        const char *platform = target->platform && target->platform[0] ?
            target->platform : alice_engine_detect_platform_from_url(target->webhook);
        rc = alice_engine_send_webhook_msg(
            target->webhook, platform, txt,
            target->custom_ctype, target->custom_body);
        if (rc < 0)
            engine_log("[PUSH][%s] webhook delivery failed", name);
        else
            engine_log("[PUSH][%s] webhook delivery succeeded", name);
    } else {
        engine_log("[PUSH][%s] target configuration is incomplete", name);
    }
    return rc;
}

int alice_engine_send_target_list(const alice_engine_push_target_t *targets,
                                  size_t target_count,
                                  const char *txt) {
    size_t i;
    int configured = 0;
    int failed = 0;

    if (!txt || !targets || target_count > ALICE_ENGINE_MAX_TARGETS)
        return -1;
    for (i = 0; i < target_count; i++) {
        const alice_engine_push_target_t *target = &targets[i];
        char target_txt[ALICE_ENGINE_PUSH_MESSAGE_MAX];
        int rc = -1;

        if (!target->enabled)
            continue;
        configured = 1;
        if (alice_engine_build_push_message_checked(
                target_txt, sizeof(target_txt), target->headtxt, txt,
                target->tailtxt) < 0) {
            engine_log("[PUSH][%s] formatted message exceeds push buffer",
                       push_target_name(target, i));
            failed = 1;
            continue;
        }
        rc = send_one_target_message(target, i, target_txt);
        if (rc < 0)
            failed = 1;
    }
    return configured && !failed ? 0 : -1;
}

int alice_engine_send_targets(const char *webhook,
                              const char *platform,
                              const char *txt,
                              const char *custom_ctype,
                              const char *custom_body,
                              const char *smtp_host,
                              const char *smtp_port,
                              const char *smtp_user,
                              const char *smtp_password,
                              const char *smtp_from,
                              const char *smtp_to,
                              const char *smtp_security) {
    alice_engine_push_target_t targets[2];
    size_t count = 0;

    memset(targets, 0, sizeof(targets));
    if (webhook && webhook[0]) {
        targets[count].enabled = 1;
        targets[count].name = "Webhook";
        targets[count].type = "webhook";
        targets[count].platform = platform;
        targets[count].webhook = webhook;
        targets[count].custom_ctype = custom_ctype;
        targets[count].custom_body = custom_body;
        count++;
    }
    if (smtp_host && smtp_host[0] && smtp_from && smtp_from[0] &&
        smtp_to && smtp_to[0] && count < 2) {
        targets[count].enabled = 1;
        targets[count].name = "邮箱";
        targets[count].type = "email";
        targets[count].smtp_host = smtp_host;
        targets[count].smtp_port = smtp_port;
        targets[count].smtp_user = smtp_user;
        targets[count].smtp_password = smtp_password;
        targets[count].smtp_from = smtp_from;
        targets[count].smtp_to = smtp_to;
        targets[count].smtp_security = smtp_security;
        count++;
    }
    return alice_engine_send_target_list(targets, count, txt);
}

int alice_engine_start_service(const alice_engine_service_config_t *cfg) {
    const char *target_path;
    char target_path_buf[256];
    alice_engine_push_target_t legacy_targets[2];
    pdu_thread_args_t pdu_args;
    const alice_engine_push_target_t *targets;
    size_t target_count;

    if (!cfg || cfg->target_count > ALICE_ENGINE_MAX_TARGETS) {
        errno = EINVAL;
        return -1;
    }

    memset(legacy_targets, 0, sizeof(legacy_targets));
    targets = cfg->targets;
    target_count = cfg->target_count;
    if (!targets || !target_count) {
        target_count = 0;
        if (cfg->webhook && cfg->webhook[0]) {
            legacy_targets[target_count].enabled = 1;
            legacy_targets[target_count].name = "Webhook";
            legacy_targets[target_count].type = "webhook";
            legacy_targets[target_count].num = cfg->num;
            legacy_targets[target_count].headtxt = cfg->headtxt;
            legacy_targets[target_count].tailtxt = cfg->tailtxt;
            legacy_targets[target_count].platform = cfg->platform;
            legacy_targets[target_count].webhook = cfg->webhook;
            legacy_targets[target_count].custom_ctype = cfg->custom_ctype;
            legacy_targets[target_count].custom_body = cfg->custom_body;
            target_count++;
        }
        if (cfg->smtp_host && cfg->smtp_host[0] && cfg->smtp_from &&
            cfg->smtp_from[0] && cfg->smtp_to && cfg->smtp_to[0] &&
            target_count < 2) {
            legacy_targets[target_count].enabled = 1;
            legacy_targets[target_count].name = "邮箱";
            legacy_targets[target_count].type = "email";
            legacy_targets[target_count].num = cfg->num;
            legacy_targets[target_count].headtxt = cfg->headtxt;
            legacy_targets[target_count].tailtxt = cfg->tailtxt;
            legacy_targets[target_count].smtp_host = cfg->smtp_host;
            legacy_targets[target_count].smtp_port = cfg->smtp_port;
            legacy_targets[target_count].smtp_user = cfg->smtp_user;
            legacy_targets[target_count].smtp_password = cfg->smtp_password;
            legacy_targets[target_count].smtp_from = cfg->smtp_from;
            legacy_targets[target_count].smtp_to = cfg->smtp_to;
            legacy_targets[target_count].smtp_security = cfg->smtp_security;
            target_count++;
        }
        targets = legacy_targets;
    }
    if (!target_count) {
        errno = EINVAL;
        return -1;
    }
    target_path = cfg->target_path && cfg->target_path[0] ?
                  cfg->target_path : TARGET_MIFI_PATH;
    safe_copy(target_path_buf, sizeof(target_path_buf), target_path);
    safe_copy(g_target_path, sizeof(g_target_path), target_path_buf);

    if (cfg->num && cfg->num[0]) {
        safe_copy(device_msisdn, sizeof(device_msisdn), cfg->num);
    } else {
        load_device_msisdn_from_nv_show();
        if (!device_msisdn[0]) {
            safe_copy(device_msisdn, sizeof(device_msisdn),
                      "读取手机号失败 请使用 --num=参数进行手动添加");
        }
    }

    threads_running = 1;
    reset_strace_queue();
    engine_log("[ENGINE] service mode starting");
    engine_log("[ENGINE] target=%s strace=attached", g_target_path);
    engine_log("[ENGINE] press Ctrl+C to stop");
    signal(SIGINT, engine_signal_handler);
    signal(SIGTERM, engine_signal_handler);

    if (pthread_create(&strace_thread_id, NULL, strace_thread_func,
                       g_target_path) != 0) {
        engine_log("[ENGINE] failed to create strace thread errno=%d", errno);
        return -1;
    }
    pdu_args.targets = targets;
    pdu_args.target_count = target_count;
    pdu_args.long_sms_reassembly = cfg->long_sms_reassembly ? 1 : 0;
    if (pthread_create(&pdu_thread_id, NULL, pdu_thread_func,
                       &pdu_args) != 0) {
        engine_log("[ENGINE] failed to create PDU thread errno=%d", errno);
        threads_running = 0;
        pthread_cond_broadcast(&g_strace_queue.cond);
        pthread_join(strace_thread_id, NULL);
        return -1;
    }
    pthread_join(strace_thread_id, NULL);
    pthread_join(pdu_thread_id, NULL);
    return 0;
}

int alice_engine_process_alive(pid_t pid) {
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    return errno == EPERM;
}

pid_t alice_engine_get_strace_pid(void) {
    return get_strace_pid_from_file();
}

int alice_engine_find_process_by_exe_path(const char *exe_path) {
    return find_process_by_exe_path(exe_path);
}

void alice_engine_cleanup_strace_child(const char *target_path) {
    pid_t strace_pid = get_strace_pid_from_file();

    if (strace_pid > 0 && alice_engine_process_alive(strace_pid)) {
        kill(strace_pid, SIGTERM);
        usleep(200 * 1000);
        if (alice_engine_process_alive(strace_pid))
            kill(strace_pid, SIGKILL);
    }
    if (target_path && target_path[0])
        sigcont_process_by_path(target_path);
    sigcont_process_by_path(g_target_path);
    sigcont_process_by_path(TARGET_MIFI_PATH);
    sigcont_process_by_path(TARGET_UFI_PATH);
}

void alice_engine_stop(void) {
    threads_running = 0;
    pthread_cond_broadcast(&g_strace_queue.cond);
    alice_engine_cleanup_strace_child(g_target_path);
}

int alice_engine_load_device_msisdn(char *out, size_t outsz) {
    load_device_msisdn_from_nv_show();
    if (outsz) {
        safe_copy(out, outsz, device_msisdn);
    }
    return device_msisdn[0] ? 0 : -1;
}

// strace线程函数 - 执行 strace 跟踪目标短信进程的 read/write 系统调用
static void* strace_thread_func(void* arg) {
    const char *target_path = (const char *)arg;
    char local_target_path[256];

    if (!target_path || !target_path[0])
        target_path = TARGET_MIFI_PATH;
    safe_copy(local_target_path, sizeof(local_target_path), target_path);
    safe_copy(g_target_path, sizeof(g_target_path), local_target_path);
    target_path = local_target_path;

    while (threads_running) {
        int pid = find_process_by_exe_path(target_path);
        if (pid <= 0) {
            engine_log("[ENGINE] target process not found: %s", target_path);
            sleep(1);
            continue;
        }

        pid_t strace_pid = 0;
        int read_fd = -1;
        if (start_strace_with_pipe(pid, &strace_pid, &read_fd) != 0) {
            engine_log("[ENGINE] start_strace_with_pipe failed errno=%d", errno);
            sleep(1);
            continue;
        }
        set_strace_pid_to_file(strace_pid);
        time_t next_midnight = get_next_midnight_epoch();

        char partial[MAX_BUFFER_LEN];
        size_t partial_len = 0;
        while (threads_running) {
            struct pollfd pfd;
            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = read_fd;
            pfd.events = POLLIN;
            int pr = poll(&pfd, 1, 200);
            if (pr > 0 && (pfd.revents & POLLIN)) {
                char buf[2048];
                ssize_t n = read(read_fd, buf, sizeof(buf));
                if (n > 0) {
                    size_t i;
                    for (i = 0; i < (size_t)n; i++) {
                        char c = buf[i];
                        if (partial_len + 1 < sizeof(partial)) {
                            partial[partial_len++] = c;
                        }
                        if (c == '\n') {
                            partial[partial_len] = 0;
                            if (strstr(partial, "+CMT: ") != NULL)
                                strace_queue_push_line(partial);
                            partial_len = 0;
                        }
                        if (partial_len + 1 >= sizeof(partial)) {
                            partial[partial_len] = 0;
                            if (strstr(partial, "+CMT: ") != NULL)
                                strace_queue_push_line(partial);
                            partial_len = 0;
                        }
                    }
                } else if (n == 0) {
                    break;
                } else {
                    if (errno != EAGAIN && errno != EINTR) break;
                }
            }

            time_t now = time(NULL);
            if (now >= next_midnight) {
                kill(strace_pid, SIGTERM);
                int wait_count = 0;
                while (wait_count < 10) {
                    if (kill(strace_pid, 0) != 0) break;
                    usleep(100*1000);
                    wait_count++;
                }
                if (kill(strace_pid, 0) == 0) {
                    kill(strace_pid, SIGKILL);
                    usleep(200*1000);
                }
                sigcont_process_by_path(target_path);
                break;
            }

            int status = 0;
            pid_t w = waitpid(strace_pid, &status, WNOHANG);
            if (w == strace_pid) break;
        }

        close(read_fd);
        waitpid(strace_pid, NULL, 0);
        if (!threads_running) break;
        sleep(1);
    }
    return NULL;
}

// PDU处理线程函数
static void* pdu_thread_func(void* arg) {
    pdu_thread_args_t *args = (pdu_thread_args_t *)arg;

    while (threads_running) {
        char line[MAX_BUFFER_LEN];
        if (strace_queue_pop_line(line, sizeof(line), 1000)) {
            process_strace_line_for_sms(line, args->targets, args->target_count,
                                        args->long_sms_reassembly);
        } else {
            expire_concat_assemblies(time(NULL));
        }
    }
    return NULL;
}

// PDU解码信息和有限的长短信拼合缓存
#define SMS_UNIQ_QUEUE_SIZE 100
#define SMS_CONCAT_PART_BYTES SMS_TEXT_MAX

typedef struct sms_info {
    char smsc[32];
    char sender[32];
    char timestamp[32];
    char tp_pid[4];
    char tp_dcs[4];
    char tp_dcs_desc[32];
    char sms_class[8];
    char alphabet[32];
    char text[SMS_TEXT_MAX];
    int text_len;
    int coding;
    int has_udh;
    int is_concat;
    unsigned int concat_ref;
    unsigned int concat_ref_bytes;
    unsigned int concat_total;
    unsigned int concat_seq;
} sms_info_t;

enum {
    SMS_CODING_GSM7 = 0,
    SMS_CODING_UCS2 = 1
};

typedef struct {
    char sender[32];
    char timestamp[32];
    unsigned int reference;
    unsigned int reference_bytes;
    unsigned int total;
    unsigned int received_mask;
    time_t last_seen;
    char parts[SMS_CONCAT_MAX_PARTS][SMS_CONCAT_PART_BYTES];
    int used;
} sms_concat_assembly_t;

typedef struct {
    char sender[32];
    char timestamp[32];
    char text[SMS_TEXT_MAX];
} sms_uniq_t;

static sms_uniq_t sms_uniq_queue[SMS_UNIQ_QUEUE_SIZE];
static int sms_uniq_head = 0;
static int sms_uniq_count = 0;
static sms_concat_assembly_t g_concat_assemblies[SMS_CONCAT_MAX_ACTIVE];

static int is_sms_uniq_in_queue(const char *sender, const char *timestamp,
                                const char *text) {
    int i;
    for (i = 0; i < sms_uniq_count; i++) {
        int idx = (sms_uniq_head + i) % SMS_UNIQ_QUEUE_SIZE;
        if (strcmp(sms_uniq_queue[idx].sender, sender) == 0 &&
            strcmp(sms_uniq_queue[idx].timestamp, timestamp) == 0 &&
            strcmp(sms_uniq_queue[idx].text, text) == 0) {
            return 1;
        }
    }
    return 0;
}

static void add_sms_uniq_to_queue(const char *sender, const char *timestamp,
                                  const char *text) {
    int idx;
    if (sms_uniq_count < SMS_UNIQ_QUEUE_SIZE) {
        idx = (sms_uniq_head + sms_uniq_count) % SMS_UNIQ_QUEUE_SIZE;
        safe_copy(sms_uniq_queue[idx].sender,
                  sizeof(sms_uniq_queue[idx].sender), sender);
        safe_copy(sms_uniq_queue[idx].timestamp,
                  sizeof(sms_uniq_queue[idx].timestamp), timestamp);
        safe_copy(sms_uniq_queue[idx].text,
                  sizeof(sms_uniq_queue[idx].text), text);
        sms_uniq_count++;
    } else {
        safe_copy(sms_uniq_queue[sms_uniq_head].sender,
                  sizeof(sms_uniq_queue[0].sender), sender);
        safe_copy(sms_uniq_queue[sms_uniq_head].timestamp,
                  sizeof(sms_uniq_queue[0].timestamp), timestamp);
        safe_copy(sms_uniq_queue[sms_uniq_head].text,
                  sizeof(sms_uniq_queue[0].text), text);
        sms_uniq_head = (sms_uniq_head + 1) % SMS_UNIQ_QUEUE_SIZE;
    }
}

static int pdu_hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int pdu_read_byte(const char *pdu, size_t pdu_len, size_t *pos,
                        unsigned char *out) {
    int hi;
    int lo;

    if (!pdu || !pos || !out || *pos + 2 > pdu_len)
        return -1;
    hi = pdu_hex_value(pdu[*pos]);
    lo = pdu_hex_value(pdu[*pos + 1]);
    if (hi < 0 || lo < 0)
        return -1;
    *out = (unsigned char)((hi << 4) | lo);
    *pos += 2;
    return 0;
}

static void decode_bcd_number(char *out, size_t outsz,
                              const unsigned char *bytes, size_t byte_count,
                              unsigned int digit_count) {
    static const char hex[] = "0123456789ABCDEF";
    size_t i;
    size_t used = 0;

    if (!outsz) return;
    out[0] = 0;
    for (i = 0; i < byte_count && used + 1 < outsz; i++) {
        unsigned int low = bytes[i] & 0x0f;
        unsigned int high = (bytes[i] >> 4) & 0x0f;
        if (digit_count == 0 || used < digit_count) {
            if (low <= 9) out[used++] = hex[low];
        }
        if (digit_count == 0 || used < digit_count) {
            if (high <= 9) out[used++] = hex[high];
        }
    }
    out[used] = 0;
}

static int append_utf8_codepoint(char *out, size_t outsz, size_t *used,
                                 unsigned long codepoint) {
    if (!out || !used || codepoint > 0x10ffff ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff))
        return -1;
    if (codepoint < 0x80) {
        if (*used + 1 >= outsz) return -1;
        out[(*used)++] = (char)codepoint;
    } else if (codepoint < 0x800) {
        if (*used + 2 >= outsz) return -1;
        out[(*used)++] = (char)(0xc0 | (codepoint >> 6));
        out[(*used)++] = (char)(0x80 | (codepoint & 0x3f));
    } else {
        if (*used + 3 >= outsz) return -1;
        out[(*used)++] = (char)(0xe0 | (codepoint >> 12));
        out[(*used)++] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
        out[(*used)++] = (char)(0x80 | (codepoint & 0x3f));
    }
    out[*used] = 0;
    return 0;
}

static const uint16_t gsm7_default[128] = {
    0x0040, 0x00a3, 0x0024, 0x00a5, 0x00e8, 0x00e9, 0x00f9, 0x00ec,
    0x00f2, 0x00c7, 0x000a, 0x00d8, 0x00f8, 0x000d, 0x00c5, 0x00e5,
    0x0394, 0x005f, 0x03a6, 0x0393, 0x039b, 0x03a9, 0x03a0, 0x03a8,
    0x03a3, 0x0398, 0x039e, 0x001b, 0x00c6, 0x00e6, 0x00df, 0x00c9,
    0x0020, 0x0021, 0x0022, 0x0023, 0x00a4, 0x0025, 0x0026, 0x0027,
    0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
    0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
    0x00a1, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
    0x0058, 0x0059, 0x005a, 0x00c4, 0x00d6, 0x00d1, 0x00dc, 0x00a7,
    0x00bf, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
    0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f,
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
    0x0078, 0x0079, 0x007a, 0x00e4, 0x00f6, 0x00f1, 0x00fc, 0x00e0
};

static int gsm7_extension_codepoint(unsigned int value,
                                    unsigned long *codepoint) {
    if (!codepoint) return -1;
    switch (value) {
    case 0x0a: *codepoint = 0x000c; return 0;
    case 0x14: *codepoint = 0x005e; return 0;
    case 0x28: *codepoint = 0x007b; return 0;
    case 0x29: *codepoint = 0x007d; return 0;
    case 0x2f: *codepoint = 0x005c; return 0;
    case 0x3c: *codepoint = 0x005b; return 0;
    case 0x3d: *codepoint = 0x007e; return 0;
    case 0x3e: *codepoint = 0x005d; return 0;
    case 0x40: *codepoint = 0x007c; return 0;
    case 0x65: *codepoint = 0x20ac; return 0;
    default: return -1;
    }
}

static int parse_concat_udh(const unsigned char *ud, size_t ud_bytes,
                            sms_info_t *info, size_t *header_bytes) {
    size_t pos;
    size_t end;

    if (!ud || !info || !header_bytes || ud_bytes == 0)
        return -1;
    *header_bytes = (size_t)ud[0] + 1;
    if (*header_bytes > ud_bytes)
        return -1;
    pos = 1;
    end = *header_bytes;
    while (pos < end) {
        unsigned int iei;
        unsigned int ielen;
        if (pos + 2 > end)
            return -1;
        iei = ud[pos++];
        ielen = ud[pos++];
        if (pos + ielen > end)
            return -1;
        if (iei == 0x00 && ielen == 3) {
            info->is_concat = 1;
            info->concat_ref = ud[pos];
            info->concat_ref_bytes = 1;
            info->concat_total = ud[pos + 1];
            info->concat_seq = ud[pos + 2];
        } else if (iei == 0x08 && ielen == 4) {
            info->is_concat = 1;
            info->concat_ref = ((unsigned int)ud[pos] << 8) | ud[pos + 1];
            info->concat_ref_bytes = 2;
            info->concat_total = ud[pos + 2];
            info->concat_seq = ud[pos + 3];
        }
        pos += ielen;
    }
    if (info->is_concat &&
        (info->concat_total == 0 || info->concat_seq == 0 ||
         info->concat_seq > info->concat_total))
        return -1;
    return 0;
}

static int decode_gsm7_text(const unsigned char *ud, size_t ud_bytes,
                            size_t header_bytes, unsigned int udl,
                            char *out, size_t outsz) {
    size_t header_septets = (header_bytes * 8 + 6) / 7;
    size_t text_septets;
    size_t i;
    size_t used = 0;
    int escaped = 0;

    if (udl < header_septets)
        return -1;
    text_septets = (size_t)udl - header_septets;
    for (i = 0; i < text_septets; i++) {
        size_t bitpos = header_bytes * 8 + i * 7;
        size_t bytepos = bitpos / 8;
        unsigned int value;
        unsigned long codepoint;

        if (bytepos >= ud_bytes)
            return -1;
        value = (unsigned int)(ud[bytepos] >> (bitpos % 8));
        if (bitpos % 8 > 1 && bytepos + 1 < ud_bytes)
            value |= (unsigned int)ud[bytepos + 1] << (8 - (bitpos % 8));
        value &= 0x7f;
        if (escaped) {
            if (gsm7_extension_codepoint(value, &codepoint) < 0)
                codepoint = '?';
            escaped = 0;
        } else if (value == 0x1b) {
            escaped = 1;
            continue;
        } else {
            codepoint = gsm7_default[value];
        }
        if (append_utf8_codepoint(out, outsz, &used, codepoint) < 0)
            return -1;
    }
    if (escaped && append_utf8_codepoint(out, outsz, &used, '?') < 0)
        return -1;
    return 0;
}

static int decode_ucs2_text(const unsigned char *ud, size_t ud_bytes,
                            size_t header_bytes, char *out, size_t outsz) {
    size_t pos = header_bytes;
    size_t used = 0;

    if (pos > ud_bytes || ((ud_bytes - pos) % 2) != 0)
        return -1;
    while (pos + 1 < ud_bytes) {
        unsigned long codepoint = ((unsigned long)ud[pos] << 8) | ud[pos + 1];
        if (append_utf8_codepoint(out, outsz, &used, codepoint) < 0)
            return -1;
        pos += 2;
    }
    return 0;
}

static int decode_pdu(const char *pdu, sms_info_t *info) {
    size_t pdu_len;
    size_t pos = 0;
    unsigned char value;
    unsigned char smsc_bytes[32];
    unsigned char sender_bytes[32];
    unsigned char ud[256];
    size_t smsc_count;
    size_t sender_count;
    size_t ud_bytes;
    size_t expected_ud_bytes;
    size_t header_bytes = 0;
    unsigned int smsc_len;
    unsigned int sender_len;
    unsigned int first_octet;
    unsigned int dcs;
    unsigned int udl;
    unsigned int i;
    unsigned char timestamp[7];
    char timestamp_digits[15];

    if (!pdu || !info)
        return -1;
    memset(info, 0, sizeof(*info));
    pdu_len = strlen(pdu);
    if (pdu_len < 20 || (pdu_len & 1) != 0)
        return -1;

    if (pdu_read_byte(pdu, pdu_len, &pos, &value) < 0)
        return -1;
    smsc_len = value;
    if (smsc_len > 0) {
        if (pdu_read_byte(pdu, pdu_len, &pos, &value) < 0)
            return -1;
        smsc_count = smsc_len - 1;
        if (smsc_count > sizeof(smsc_bytes))
            return -1;
        for (i = 0; i < smsc_count; i++)
            if (pdu_read_byte(pdu, pdu_len, &pos, &smsc_bytes[i]) < 0)
                return -1;
        decode_bcd_number(info->smsc, sizeof(info->smsc), smsc_bytes,
                          smsc_count, 0);
        if (strncmp(info->smsc, "86", 2) == 0)
            memmove(info->smsc, info->smsc + 2,
                    strlen(info->smsc + 2) + 1);
    }

    if (pdu_read_byte(pdu, pdu_len, &pos, &value) < 0)
        return -1;
    first_octet = value;
    if (pdu_read_byte(pdu, pdu_len, &pos, &value) < 0)
        return -1;
    sender_len = value;
    if (pdu_read_byte(pdu, pdu_len, &pos, &value) < 0)
        return -1;
    sender_count = (sender_len + 1) / 2;
    if (sender_count > sizeof(sender_bytes))
        return -1;
    for (i = 0; i < sender_count; i++)
        if (pdu_read_byte(pdu, pdu_len, &pos, &sender_bytes[i]) < 0)
            return -1;
    decode_bcd_number(info->sender, sizeof(info->sender), sender_bytes,
                      sender_count, sender_len);
    if (strncmp(info->sender, "86", 2) == 0)
        memmove(info->sender, info->sender + 2,
                strlen(info->sender + 2) + 1);

    if (pdu_read_byte(pdu, pdu_len, &pos, &value) < 0)
        return -1;
    snprintf(info->tp_pid, sizeof(info->tp_pid), "%02X", value);
    if (pdu_read_byte(pdu, pdu_len, &pos, &value) < 0)
        return -1;
    dcs = value;
    snprintf(info->tp_dcs, sizeof(info->tp_dcs), "%02X", dcs);
    if ((dcs & 0x0c) == 0x00) {
        info->coding = SMS_CODING_GSM7;
        safe_copy(info->tp_dcs_desc, sizeof(info->tp_dcs_desc), "GSM 7-bit");
        safe_copy(info->sms_class, sizeof(info->sms_class), "0");
        safe_copy(info->alphabet, sizeof(info->alphabet), "GSM 7-bit");
    } else if ((dcs & 0x0c) == 0x08) {
        info->coding = SMS_CODING_UCS2;
        safe_copy(info->tp_dcs_desc, sizeof(info->tp_dcs_desc),
                  "Uncompressed Text");
        safe_copy(info->sms_class, sizeof(info->sms_class), "0");
        safe_copy(info->alphabet, sizeof(info->alphabet), "UCS2(16)bit");
    } else {
        engine_log("[PDU] unsupported DCS=0x%02X", dcs);
        return -1;
    }

    for (i = 0; i < 7; i++)
        if (pdu_read_byte(pdu, pdu_len, &pos, &timestamp[i]) < 0)
            return -1;
    for (i = 0; i < 7; i++) {
        static const char hex[] = "0123456789ABCDEF";
        timestamp_digits[i * 2] = hex[timestamp[i] & 0x0f];
        timestamp_digits[i * 2 + 1] = hex[(timestamp[i] >> 4) & 0x0f];
    }
    timestamp_digits[14] = 0;
    snprintf(info->timestamp, sizeof(info->timestamp),
             "%c%c/%c%c/%c%c %c%c:%c%c:%c%c",
             timestamp_digits[0], timestamp_digits[1],
             timestamp_digits[2], timestamp_digits[3],
             timestamp_digits[4], timestamp_digits[5],
             timestamp_digits[6], timestamp_digits[7],
             timestamp_digits[8], timestamp_digits[9],
             timestamp_digits[10], timestamp_digits[11]);

    if (pdu_read_byte(pdu, pdu_len, &pos, &value) < 0)
        return -1;
    udl = value;
    info->text_len = (int)udl;
    expected_ud_bytes = info->coding == SMS_CODING_GSM7 ?
        ((size_t)udl * 7 + 7) / 8 : (size_t)udl;
    if (expected_ud_bytes > sizeof(ud) ||
        expected_ud_bytes > (pdu_len - pos) / 2)
        return -1;
    ud_bytes = expected_ud_bytes;
    for (i = 0; i < ud_bytes; i++)
        if (pdu_read_byte(pdu, pdu_len, &pos, &ud[i]) < 0)
            return -1;

    info->has_udh = (first_octet & 0x40) != 0;
    if (info->has_udh && parse_concat_udh(ud, ud_bytes, info,
                                          &header_bytes) < 0)
        return -1;
    if (!info->has_udh)
        header_bytes = 0;
    if (info->coding == SMS_CODING_GSM7)
        return decode_gsm7_text(ud, ud_bytes, header_bytes, udl,
                                info->text, sizeof(info->text));
    return decode_ucs2_text(ud, ud_bytes, header_bytes,
                            info->text, sizeof(info->text));
}

static int concat_key_matches(const sms_concat_assembly_t *assembly,
                              const sms_info_t *info) {
    return assembly && info && assembly->used &&
           assembly->reference == info->concat_ref &&
           assembly->reference_bytes == info->concat_ref_bytes &&
           assembly->total == info->concat_total &&
           strcmp(assembly->sender, info->sender) == 0 &&
           strcmp(assembly->timestamp, info->timestamp) == 0;
}

static void expire_concat_assemblies(time_t now) {
    int i;

    for (i = 0; i < SMS_CONCAT_MAX_ACTIVE; i++) {
        sms_concat_assembly_t *assembly = &g_concat_assemblies[i];
        if (!assembly->used)
            continue;
        if (now - assembly->last_seen >= SMS_CONCAT_TIMEOUT_SECONDS) {
            engine_log("[PDU] concat timeout sender=%s ref=%u received=%u/%u",
                       assembly->sender, assembly->reference,
                       (unsigned int)__builtin_popcount(assembly->received_mask),
                       assembly->total);
            memset(assembly, 0, sizeof(*assembly));
        }
    }
}

static sms_concat_assembly_t *find_concat_assembly(const sms_info_t *info,
                                                   time_t now) {
    sms_concat_assembly_t *free_slot = NULL;
    sms_concat_assembly_t *oldest = NULL;
    int i;

    expire_concat_assemblies(now);
    for (i = 0; i < SMS_CONCAT_MAX_ACTIVE; i++) {
        sms_concat_assembly_t *assembly = &g_concat_assemblies[i];
        if (concat_key_matches(assembly, info))
            return assembly;
        if (!assembly->used && !free_slot)
            free_slot = assembly;
        if (assembly->used &&
            (!oldest || assembly->last_seen < oldest->last_seen))
            oldest = assembly;
    }
    if (!free_slot)
        free_slot = oldest;
    if (!free_slot)
        return NULL;
    if (free_slot->used) {
        engine_log("[PDU] concat cache full, evict sender=%s ref=%u received=%u/%u",
                   free_slot->sender, free_slot->reference,
                   (unsigned int)__builtin_popcount(free_slot->received_mask),
                   free_slot->total);
    }
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = 1;
    safe_copy(free_slot->sender, sizeof(free_slot->sender), info->sender);
    safe_copy(free_slot->timestamp, sizeof(free_slot->timestamp),
              info->timestamp);
    free_slot->reference = info->concat_ref;
    free_slot->reference_bytes = info->concat_ref_bytes;
    free_slot->total = info->concat_total;
    free_slot->last_seen = now;
    return free_slot;
}

static int add_concat_segment(const sms_info_t *info, char *assembled,
                              size_t assembled_sz) {
    sms_concat_assembly_t *assembly;
    size_t text_len;
    unsigned int bit;
    unsigned int i;
    size_t used = 0;
    time_t now = time(NULL);

    if (!info || !info->is_concat || !assembled || assembled_sz == 0)
        return -1;
    if (info->concat_total > SMS_CONCAT_MAX_PARTS ||
        info->concat_seq == 0 || info->concat_seq > SMS_CONCAT_MAX_PARTS) {
        engine_log("[PDU] concat exceeds limits ref=%u total=%u seq=%u",
                   info->concat_ref, info->concat_total, info->concat_seq);
        return -1;
    }
    text_len = strlen(info->text);
    if (text_len >= SMS_CONCAT_PART_BYTES) {
        engine_log("[PDU] concat segment too long ref=%u bytes=%lu",
                   info->concat_ref, (unsigned long)text_len);
        return -1;
    }
    assembly = find_concat_assembly(info, now);
    if (!assembly)
        return -1;
    assembly->last_seen = now;
    bit = 1U << (info->concat_seq - 1);
    if (assembly->received_mask & bit) {
        if (strcmp(assembly->parts[info->concat_seq - 1], info->text) != 0)
            engine_log("[PDU] duplicate concat segment differs ref=%u seq=%u",
                       info->concat_ref, info->concat_seq);
        return 0;
    }
    safe_copy(assembly->parts[info->concat_seq - 1],
              sizeof(assembly->parts[info->concat_seq - 1]), info->text);
    assembly->received_mask |= bit;
    if (assembly->received_mask != ((1U << assembly->total) - 1U))
        return 0;

    assembled[0] = 0;
    for (i = 0; i < assembly->total; i++) {
        size_t part_len = strlen(assembly->parts[i]);
        if (used + part_len >= assembled_sz) {
            engine_log("[PDU] concat message too long ref=%u bytes>%lu",
                       info->concat_ref, (unsigned long)(assembled_sz - 1));
            memset(assembly, 0, sizeof(*assembly));
            return -1;
        }
        memcpy(assembled + used, assembly->parts[i], part_len);
        used += part_len;
    }
    assembled[used] = 0;
    memset(assembly, 0, sizeof(*assembly));
    return 1;
}

static void load_device_msisdn_from_nv_show(void) {
    device_msisdn[0] = 0;
    FILE *fp = popen("nv show", "r");
    if (!fp) return;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *p = strstr(line, "msisdn=");
        if (!p) continue;
        p += strlen("msisdn=");
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '"' || *p == '\'') p++;
        char *end = p;
        while (*end && !isspace((unsigned char)*end) && *end != '"' && *end != '\'' && *end != ';') end++;
        size_t len = (size_t)(end - p);
        if (len == 0) continue;
        if (len >= sizeof(device_msisdn)) len = sizeof(device_msisdn) - 1;
        memcpy(device_msisdn, p, len);
        device_msisdn[len] = 0;
        break;
    }

    pclose(fp);
}

/* Legacy UCS2-only decoder retained as reference for older captures. */
#if 0
static void decode_pdu(const char *pdu, sms_info_t *info) {
    memset(info, 0, sizeof(*info));
    int idx = 0;
    int smsc_len = 0;
    int i, j, k; // 统一声明循环变量
    sscanf(pdu, "%2x", &smsc_len);
    idx += 2;
    int smsc_type = 0;
    sscanf(pdu + idx, "%2x", &smsc_type);
    idx += 2;
    int smsc_bcd_len = (smsc_len - 1) * 2;
    char smsc_bcd[32] = {0};
    strncpy(smsc_bcd, pdu + idx, smsc_bcd_len);
    smsc_bcd[smsc_bcd_len] = 0;
    idx += smsc_bcd_len;
    j = 0;
    for (i = 0; i < smsc_bcd_len; i += 2) {
        if (smsc_bcd[i+1] == 'F' || smsc_bcd[i+1] == 'f') {
            info->smsc[j++] = smsc_bcd[i];
        } else {
            info->smsc[j++] = smsc_bcd[i+1];
            info->smsc[j++] = smsc_bcd[i];
        }
    }
    info->smsc[j] = 0;
    // 去除多余+86前缀（只保留一次）
    if (strncmp(info->smsc, "86", 2) == 0) {
        memmove(info->smsc, info->smsc + 2, strlen(info->smsc + 2) + 1);
    }

    int first_octet = 0;
    sscanf(pdu + idx, "%2x", &first_octet);
    idx += 2;
    int sender_len = 0;
    sscanf(pdu + idx, "%2x", &sender_len);
    idx += 2;
    int sender_type = 0;
    sscanf(pdu + idx, "%2x", &sender_type);
    idx += 2;
    int sender_bcd_len = (sender_len % 2 == 0) ? sender_len : sender_len + 1;
    sender_bcd_len /= 2;
    sender_bcd_len *= 2;
    char sender_bcd[32] = {0};
    strncpy(sender_bcd, pdu + idx, sender_bcd_len);
    sender_bcd[sender_bcd_len] = 0;
    idx += sender_bcd_len;
    j = 0;
    for (i = 0; i < sender_bcd_len; i += 2) {
        if (sender_bcd[i+1] == 'F' || sender_bcd[i+1] == 'f') {
            info->sender[j++] = sender_bcd[i];
        } else {
            info->sender[j++] = sender_bcd[i+1];
            info->sender[j++] = sender_bcd[i];
        }
    }
    info->sender[j] = 0;
    // 去除多余+86前缀（只保留一次）
    if (strncmp(info->sender, "86", 2) == 0) {
        memmove(info->sender, info->sender + 2, strlen(info->sender + 2) + 1);
    }

    // TP_PID
    strncpy(info->tp_pid, pdu + idx, 2);
    info->tp_pid[2] = 0;
    idx += 2;

    // TP_DCS
    strncpy(info->tp_dcs, pdu + idx, 2);
    info->tp_dcs[2] = 0;
    idx += 2;
    if (strcmp(info->tp_dcs, "08") == 0) {
        strcpy(info->tp_dcs_desc, "Uncompressed Text");
        strcpy(info->sms_class, "0");
        strcpy(info->alphabet, "UCS2(16)bit");
    } else {
        strcpy(info->tp_dcs_desc, "Unknown");
        strcpy(info->sms_class, "?");
        strcpy(info->alphabet, "Unknown");
    }

    // 时间戳
    char ts[15] = {0};
    strncpy(ts, pdu + idx, 14);
    ts[14] = 0;
    idx += 14;
    char dt[32] = {0};
    for (i = 0; i < 12; i += 2) {
        dt[i] = ts[i+1];
        dt[i+1] = ts[i];
    }
    snprintf(info->timestamp, sizeof(info->timestamp), "%c%c/%c%c/%c%c %c%c:%c%c:%c%c",
        dt[0], dt[1], dt[2], dt[3], dt[4], dt[5], dt[6], dt[7], dt[8], dt[9], dt[10], dt[11]);

    int text_len_oct = 0;
    sscanf(pdu + idx, "%2x", &text_len_oct);
    idx += 2;
    info->text_len = text_len_oct;

    size_t pdu_total_len = strlen(pdu);
    size_t remaining = pdu_total_len > (size_t)idx ? (pdu_total_len - (size_t)idx) : 0;
    size_t expected_ud_hex_len = (size_t)text_len_oct * 2;
    size_t ud_hex_len = expected_ud_hex_len;
    if (ud_hex_len > remaining) ud_hex_len = remaining;

    size_t ud_start_offset = 0;
    if ((first_octet & 0x40) && ud_hex_len >= 2) {
        unsigned int udhl = 0;
        if (sscanf(pdu + idx, "%2x", &udhl) == 1) {
            size_t header_hex = ((size_t)udhl + 1) * 2;
            if (header_hex < ud_hex_len) {
                ud_start_offset = header_hex;
            }
        }
    }

    const char *ud_hex_ptr = pdu + idx + (int)ud_start_offset;
    size_t ud_hex_len_after = ud_hex_len > ud_start_offset ? (ud_hex_len - ud_start_offset) : 0;
    char *ucs2_hex = (char*)malloc(ud_hex_len_after + 1);
    if (!ucs2_hex) {
        info->text[0] = 0;
        return;
    }
    memcpy(ucs2_hex, ud_hex_ptr, ud_hex_len_after);
    ucs2_hex[ud_hex_len_after] = 0;
    k = 0;
    for (i = 0; i + 3 < (int)ud_hex_len_after && k + 3 < (int)sizeof(info->text); i += 4) {
        unsigned int ucs2;
        if (sscanf(ucs2_hex + i, "%4x", &ucs2) != 1) break;
        if (ucs2 < 0x80) {
            info->text[k++] = (char)ucs2;
        } else if (ucs2 < 0x800) {
            info->text[k++] = 0xC0 | (ucs2 >> 6);
            info->text[k++] = 0x80 | (ucs2 & 0x3F);
        } else {
            info->text[k++] = 0xE0 | (ucs2 >> 12);
            info->text[k++] = 0x80 | ((ucs2 >> 6) & 0x3F);
            info->text[k++] = 0x80 | (ucs2 & 0x3F);
        }
    }
    info->text[k] = 0;
    free(ucs2_hex);
}
#endif

static void form_url_escape(char *out, size_t outsz, const char *in) {
    static const char hex[] = "0123456789ABCDEF";
    size_t used = 0;

    if (!outsz) return;
    if (!in) in = "";
    while (*in && used + 1 < outsz) {
        unsigned char c = (unsigned char)*in++;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            out[used++] = (char)c;
        } else if (used + 3 < outsz) {
            out[used++] = '%';
            out[used++] = hex[c >> 4];
            out[used++] = hex[c & 0x0f];
        } else {
            break;
        }
    }
    out[used] = 0;
}

static int replace_token(char *out, size_t outsz, const char *token,
                         const char *value) {
    size_t tlen = strlen(token);
    size_t vlen = strlen(value ? value : "");
    char *p = strstr(out, token);
    size_t tail_len;

    while (p) {
        tail_len = strlen(p + tlen);
        if ((size_t)(p - out) + vlen + tail_len >= outsz)
            return -1;
        memmove(p + vlen, p + tlen, tail_len + 1);
        memcpy(p, value ? value : "", vlen);
        p = strstr(p + vlen, token);
    }
    return 0;
}

static int render_custom_body(const char *tmpl, const char *txt,
                              char *out, size_t outsz) {
    char *json_txt;
    char *url_txt;
    int rc = -1;

    if (!tmpl || !tmpl[0] || !outsz)
        return -1;
    json_txt = (char *)malloc(SMS_PAYLOAD_MAX);
    url_txt = (char *)malloc(SMS_PAYLOAD_MAX);
    if (!json_txt || !url_txt)
        goto cleanup;
    safe_copy(out, outsz, tmpl);
    json_escape(json_txt, SMS_PAYLOAD_MAX, txt);
    form_url_escape(url_txt, SMS_PAYLOAD_MAX, txt);
    if (replace_token(out, outsz, "{{json_text}}", json_txt) < 0)
        goto cleanup;
    if (replace_token(out, outsz, "{{url_text}}", url_txt) < 0)
        goto cleanup;
    if (replace_token(out, outsz, "{{text}}", txt ? txt : "") < 0)
        goto cleanup;
    rc = 0;

cleanup:
    free(json_txt);
    free(url_txt);
    return rc;
}

static int extract_bark_device_key(const char *url, char *out, size_t outsz) {
    const char *p;
    const char *end;
    size_t len;

    if (!url || !out || outsz == 0)
        return -1;
    out[0] = 0;
    p = strstr(url, "://");
    p = p ? p + 3 : url;
    p = strchr(p, '/');
    if (!p || !p[1])
        return -1;
    p++;
    if (strncmp(p, "push", 4) == 0 &&
        (p[4] == 0 || p[4] == '?' || p[4] == '/' || p[4] == '#'))
        return -1;
    end = p;
    while (*end && *end != '/' && *end != '?' && *end != '#')
        end++;
    len = (size_t)(end - p);
    if (len == 0 || len >= outsz)
        return -1;
    memcpy(out, p, len);
    out[len] = 0;
    return 0;
}

int alice_engine_build_webhook_payload(const char *webhook, const char *platform,
                                 const char *txt,
                                 const char *custom_ctype,
                                 const char *custom_body,
                                 char *payload, size_t payload_sz,
                                 char *ctype, size_t ctype_sz) {
    char *safe_txt;
    char safe_key[512];
    char *enc_txt;
    const char *p = platform && platform[0] ? platform : "dingtalk";
    int rc = -1;

    if (!payload || !ctype || !payload_sz || !ctype_sz || !txt)
        return -1;
    safe_txt = (char *)malloc(SMS_PAYLOAD_MAX);
    enc_txt = (char *)malloc(SMS_PAYLOAD_MAX);
    if (!safe_txt || !enc_txt)
        goto cleanup;
    payload[0] = 0;
    ctype[0] = 0;

    if (strcmp(p, "serverchan") == 0) {
        form_url_escape(enc_txt, SMS_PAYLOAD_MAX, txt);
        snprintf(ctype, ctype_sz, "application/x-www-form-urlencoded");
        snprintf(payload, payload_sz, "title=Alice%%20Pusher&desp=%s", enc_txt);
        rc = payload[0] ? 0 : -1;
        goto cleanup;
    }
    if (strcmp(p, "telegram") == 0) {
        form_url_escape(enc_txt, SMS_PAYLOAD_MAX, txt);
        snprintf(ctype, ctype_sz, "application/x-www-form-urlencoded");
        snprintf(payload, payload_sz, "text=%s", enc_txt);
        rc = payload[0] ? 0 : -1;
        goto cleanup;
    }
    if (strcmp(p, "custom") == 0) {
        const char *tmpl = custom_body && custom_body[0] ? custom_body :
                           "{\"text\":\"{{json_text}}\"}";
        snprintf(ctype, ctype_sz, "%s",
                 custom_ctype && custom_ctype[0] ? custom_ctype :
                 "application/json;charset=utf-8");
        if (render_custom_body(tmpl, txt, payload, payload_sz) < 0)
            goto cleanup;
        rc = payload[0] ? 0 : -1;
        goto cleanup;
    }

    json_escape(safe_txt, SMS_PAYLOAD_MAX, txt);
    snprintf(ctype, ctype_sz, "application/json;charset=utf-8");
    if (strcmp(p, "feishu") == 0) {
        snprintf(payload, payload_sz,
                 "{\"msg_type\":\"text\",\"content\":{\"text\":\"%s\"}}",
                 safe_txt);
    } else if (strcmp(p, "discord") == 0) {
        snprintf(payload, payload_sz,
                 "{\"content\":\"%s\"}",
                 safe_txt);
    } else if (strcmp(p, "bark") == 0) {
        char bark_key[256];
        if (extract_bark_device_key(webhook, bark_key, sizeof(bark_key)) < 0)
            goto cleanup;
        json_escape(safe_key, sizeof(safe_key), bark_key);
        snprintf(payload, payload_sz,
                 "{\"title\":\"Alice Pusher\",\"body\":\"%s\",\"device_key\":\"%s\"}",
                 safe_txt, safe_key);
    } else {
        snprintf(payload, payload_sz,
                 "{\"msgtype\":\"text\",\"text\":{\"content\":\"%s\"}}",
                 safe_txt);
    }
    rc = payload[0] ? 0 : -1;

cleanup:
    free(safe_txt);
    free(enc_txt);
    return rc;
}

static int post_https_body(const char *webhook, const char *ctype,
                           const char *payload, const char *platform) {
    char *host = NULL, *path = NULL;
    const char *request_path;
    char *request_buffer = NULL;
    unsigned char read_buf[1024];
    int request_len;
    size_t request_cap;
    int ret = 0;
    int rc = -1;
    const char *port = "443";
    const char *pers = "ssl_client";
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    parse_url(webhook, &host, &path);
    if (!host || !path) {
        engine_log("[WEBHOOK] invalid url");
        goto cleanup_strings;
    }
    request_path = path;
    if (platform && strcmp(platform, "bark") == 0)
        request_path = "/push";

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                     &entropy, (const unsigned char *)pers,
                                     strlen(pers))) != 0) {
        print_mbedtls_error(ret, "mbedtls_ctr_drbg_seed");
        goto cleanup_tls;
    }
    if ((ret = mbedtls_net_connect(&server_fd, host, port,
                                   MBEDTLS_NET_PROTO_TCP)) != 0) {
        print_mbedtls_error(ret, "mbedtls_net_connect");
        goto cleanup_tls;
    }
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        print_mbedtls_error(ret, "mbedtls_ssl_config_defaults");
        goto cleanup_tls;
    }
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_ciphersuites(&conf, g_webhook_ciphersuites);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        print_mbedtls_error(ret, "mbedtls_ssl_setup");
        goto cleanup_tls;
    }
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send,
                        mbedtls_net_recv, NULL);
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_mbedtls_error(ret, "mbedtls_ssl_handshake");
            goto cleanup_tls;
        }
    }

    request_cap = strlen(payload) + strlen(host) + strlen(request_path) +
                  strlen(ctype) + 512;
    request_buffer = (char *)malloc(request_cap);
    if (!request_buffer) {
        engine_log("[WEBHOOK] request buffer allocation failed");
        goto cleanup_tls;
    }
    request_len = snprintf(request_buffer, request_cap,
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: alice-pusher-bot/1.0\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        request_path, host, ctype, strlen(payload), payload);
    if (request_len <= 0 || (size_t)request_len >= request_cap) {
        engine_log("[WEBHOOK] request too large");
        goto cleanup_tls;
    }

    engine_log("[WEBHOOK] platform=%s host=%s bytes=%zu",
               platform ? platform : "dingtalk", host, strlen(payload));
    while ((ret = mbedtls_ssl_write(&ssl,
                                    (const unsigned char *)request_buffer,
                                    (size_t)request_len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_mbedtls_error(ret, "mbedtls_ssl_write");
            goto cleanup_tls;
        }
    }

    memset(read_buf, 0, sizeof(read_buf));
    ret = mbedtls_ssl_read(&ssl, read_buf, sizeof(read_buf) - 1);
    if (ret > 0)
        engine_log("[WEBHOOK] response: %s", read_buf);
    else if (ret < 0 &&
             ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY &&
             ret != MBEDTLS_ERR_SSL_WANT_READ)
        print_mbedtls_error(ret, "mbedtls_ssl_read");
    rc = 0;

cleanup_tls:
    free(request_buffer);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
cleanup_strings:
    if (host) free(host);
    if (path) free(path);
    return rc;
}

typedef struct {
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int tls_active;
} smtp_conn_t;

static int smtp_conn_write(smtp_conn_t *conn, const unsigned char *buf,
                           size_t len) {
    size_t sent = 0;

    while (sent < len) {
        int ret = conn->tls_active ?
            mbedtls_ssl_write(&conn->ssl, buf + sent, len - sent) :
            mbedtls_net_send(&conn->net, buf + sent, len - sent);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (ret <= 0)
            return -1;
        sent += (size_t)ret;
    }
    return 0;
}

static int smtp_conn_read(smtp_conn_t *conn, unsigned char *buf, size_t len) {
    for (;;) {
        int ret = conn->tls_active ?
            mbedtls_ssl_read(&conn->ssl, buf, len) :
            mbedtls_net_recv(&conn->net, buf, len);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        return ret;
    }
}

static int smtp_send_text(smtp_conn_t *conn, const char *text) {
    if (!text)
        return -1;
    return smtp_conn_write(conn, (const unsigned char *)text, strlen(text));
}

static int smtp_read_response(smtp_conn_t *conn) {
    char line[512];
    size_t used = 0;
    int first_code = 0;

    for (;;) {
        unsigned char ch;
        int ret = smtp_conn_read(conn, &ch, 1);
        int code;

        if (ret != 1)
            return -1;
        if (ch != '\n') {
            if (used + 1 >= sizeof(line))
                return -1;
            line[used++] = (char)ch;
            continue;
        }
        if (used && line[used - 1] == '\r')
            used--;
        line[used] = 0;
        if (used < 3 || !isdigit((unsigned char)line[0]) ||
            !isdigit((unsigned char)line[1]) ||
            !isdigit((unsigned char)line[2]))
            return -1;
        code = (line[0] - '0') * 100 + (line[1] - '0') * 10 +
               (line[2] - '0');
        if (!first_code)
            first_code = code;
        if (used < 4 || line[3] != '-') {
            engine_log("[SMTP] response=%d", first_code);
            return first_code;
        }
        used = 0;
    }
}

static int smtp_expect(smtp_conn_t *conn, int min_code, int max_code) {
    int code = smtp_read_response(conn);
    return code >= min_code && code <= max_code ? 0 : -1;
}

static int smtp_command(smtp_conn_t *conn, const char *command,
                        int min_code, int max_code) {
    if (smtp_send_text(conn, command) < 0)
        return -1;
    return smtp_expect(conn, min_code, max_code);
}

static int smtp_base64_encode(const unsigned char *src, size_t src_len,
                              char *dst, size_t dst_sz) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    size_t used = 0;

    while (i < src_len) {
        unsigned int value = (unsigned int)src[i++] << 16;
        int count = 1;
        if (i < src_len) {
            value |= (unsigned int)src[i++] << 8;
            count++;
        }
        if (i < src_len) {
            value |= src[i++];
            count++;
        }
        if (used + 4 >= dst_sz)
            return -1;
        dst[used++] = table[(value >> 18) & 0x3f];
        dst[used++] = table[(value >> 12) & 0x3f];
        dst[used++] = count > 1 ? table[(value >> 6) & 0x3f] : '=';
        dst[used++] = count > 2 ? table[value & 0x3f] : '=';
    }
    if (used + 1 > dst_sz)
        return -1;
    dst[used] = 0;
    return 0;
}

static int smtp_enable_tls(smtp_conn_t *conn, const char *host) {
    int ret;
    const char *pers = "alice-pusher-smtp";

    if ((ret = mbedtls_ctr_drbg_seed(&conn->ctr_drbg,
                                     mbedtls_entropy_func,
                                     &conn->entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0) {
        print_mbedtls_error(ret, "smtp ctr_drbg_seed");
        return -1;
    }
    if ((ret = mbedtls_ssl_config_defaults(&conn->conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        print_mbedtls_error(ret, "smtp ssl_config_defaults");
        return -1;
    }
    mbedtls_ssl_conf_authmode(&conn->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conn->conf, mbedtls_ctr_drbg_random,
                         &conn->ctr_drbg);
    if ((ret = mbedtls_ssl_setup(&conn->ssl, &conn->conf)) != 0) {
        print_mbedtls_error(ret, "smtp ssl_setup");
        return -1;
    }
    if (host && host[0] && mbedtls_ssl_set_hostname(&conn->ssl, host) != 0) {
        engine_log("[SMTP] invalid server hostname");
        return -1;
    }
    mbedtls_ssl_set_bio(&conn->ssl, &conn->net, mbedtls_net_send,
                        mbedtls_net_recv, NULL);
    while ((ret = mbedtls_ssl_handshake(&conn->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_mbedtls_error(ret, "smtp ssl_handshake");
            return -1;
        }
    }
    conn->tls_active = 1;
    return 0;
}

static int smtp_append(char *buf, size_t bufsz, size_t *used,
                       const char *src, size_t len) {
    if (!buf || !used || *used > bufsz || len > bufsz - *used)
        return -1;
    memcpy(buf + *used, src, len);
    *used += len;
    return 0;
}

static int smtp_build_data(char *data, size_t data_sz, const char *from,
                           const char *to, const char *txt) {
    size_t used = 0;
    size_t i;
    int line_start = 1;
    int n;

    n = snprintf(data, data_sz,
                 "From: %s\r\n"
                 "To: %s\r\n"
                 "Subject: Alice Pusher SMS\r\n"
                 "MIME-Version: 1.0\r\n"
                 "Content-Type: text/plain; charset=UTF-8\r\n"
                 "Content-Transfer-Encoding: 8bit\r\n"
                 "\r\n",
                 from, to);
    if (n <= 0 || (size_t)n >= data_sz)
        return -1;
    used = (size_t)n;
    for (i = 0; txt && txt[i]; i++) {
        char ch = txt[i];
        if (line_start && ch == '.') {
            if (smtp_append(data, data_sz, &used, ".", 1) < 0)
                return -1;
        }
        if (ch == '\r') {
            if (txt[i + 1] == '\n')
                i++;
            if (smtp_append(data, data_sz, &used, "\r\n", 2) < 0)
                return -1;
            line_start = 1;
        } else if (ch == '\n') {
            if (smtp_append(data, data_sz, &used, "\r\n", 2) < 0)
                return -1;
            line_start = 1;
        } else {
            if (smtp_append(data, data_sz, &used, &ch, 1) < 0)
                return -1;
            line_start = 0;
        }
    }
    if (!line_start && smtp_append(data, data_sz, &used, "\r\n", 2) < 0)
        return -1;
    if (smtp_append(data, data_sz, &used, ".\r\n", 3) < 0)
        return -1;
    return (int)used;
}

static int smtp_value_safe(const char *value) {
    const unsigned char *p = (const unsigned char *)value;
    if (!value || !value[0])
        return 0;
    while (*p) {
        if (*p == '\r' || *p == '\n' || *p < 0x20 || *p == 0x7f)
            return 0;
        p++;
    }
    return 1;
}

static int smtp_send_message(const char *host, const char *port,
                             const char *user, const char *password,
                             const char *from, const char *to,
                             const char *security, const char *txt) {
    smtp_conn_t conn;
    char port_buf[16];
    char command[768];
    char encoded[512];
    char *data = NULL;
    const char *mode = security && security[0] ? security : "starttls";
    const char *connect_port = port;
    int data_len;
    int code;
    int rc = -1;

    if (!smtp_value_safe(host) || !smtp_value_safe(from) ||
        !smtp_value_safe(to) ||
        (user && user[0] && !smtp_value_safe(user)) ||
        (password && password[0] && !smtp_value_safe(password))) {
        engine_log("[SMTP] invalid configuration value");
        return -1;
    }
    if (strcmp(mode, "plain") != 0 && strcmp(mode, "starttls") != 0 &&
        strcmp(mode, "tls") != 0) {
        engine_log("[SMTP] unsupported security mode=%s", mode);
        return -1;
    }
    if (!connect_port || !connect_port[0]) {
        snprintf(port_buf, sizeof(port_buf), "%s",
                 strcmp(mode, "tls") == 0 ? "465" :
                 (strcmp(mode, "plain") == 0 ? "25" : "587"));
        connect_port = port_buf;
    }
    data = (char *)malloc(SMS_PAYLOAD_MAX);
    if (!data) {
        engine_log("[SMTP] message buffer allocation failed");
        return -1;
    }

    memset(&conn, 0, sizeof(conn));
    mbedtls_net_init(&conn.net);
    mbedtls_ssl_init(&conn.ssl);
    mbedtls_ssl_config_init(&conn.conf);
    mbedtls_entropy_init(&conn.entropy);
    mbedtls_ctr_drbg_init(&conn.ctr_drbg);
    if (mbedtls_net_connect(&conn.net, host, connect_port,
                            MBEDTLS_NET_PROTO_TCP) != 0) {
        engine_log("[SMTP] connect failed host=%s port=%s", host, connect_port);
        goto cleanup;
    }
    engine_log("[SMTP] connected host=%s port=%s security=%s",
               host, connect_port, mode);
    if (strcmp(mode, "tls") == 0 && smtp_enable_tls(&conn, host) < 0)
        goto cleanup;
    if (smtp_expect(&conn, 200, 399) < 0)
        goto cleanup;
    if (smtp_send_text(&conn, "EHLO alice-pusher\r\n") < 0)
        goto cleanup;
    code = smtp_read_response(&conn);
    if (code < 200 || code > 299) {
        if (smtp_command(&conn, "HELO alice-pusher\r\n", 200, 299) < 0)
            goto cleanup;
    }
    if (strcmp(mode, "starttls") == 0) {
        if (smtp_command(&conn, "STARTTLS\r\n", 200, 299) < 0)
            goto cleanup;
        if (smtp_enable_tls(&conn, host) < 0)
            goto cleanup;
        if (smtp_command(&conn, "EHLO alice-pusher\r\n", 200, 299) < 0)
            goto cleanup;
    }
    if (user && user[0]) {
        if (smtp_command(&conn, "AUTH LOGIN\r\n", 300, 399) < 0)
            goto cleanup;
        if (smtp_base64_encode((const unsigned char *)user, strlen(user),
                               encoded, sizeof(encoded)) < 0)
            goto cleanup;
        snprintf(command, sizeof(command), "%s\r\n", encoded);
        if (smtp_command(&conn, command, 300, 399) < 0)
            goto cleanup;
        if (smtp_base64_encode((const unsigned char *)(password ? password : ""),
                               password ? strlen(password) : 0,
                               encoded, sizeof(encoded)) < 0)
            goto cleanup;
        snprintf(command, sizeof(command), "%s\r\n", encoded);
        if (smtp_command(&conn, command, 200, 399) < 0)
            goto cleanup;
    }
    snprintf(command, sizeof(command), "MAIL FROM:<%s>\r\n", from);
    if (smtp_command(&conn, command, 200, 299) < 0)
        goto cleanup;
    snprintf(command, sizeof(command), "RCPT TO:<%s>\r\n", to);
    if (smtp_command(&conn, command, 200, 299) < 0)
        goto cleanup;
    if (smtp_command(&conn, "DATA\r\n", 300, 399) < 0)
        goto cleanup;
    data_len = smtp_build_data(data, SMS_PAYLOAD_MAX, from, to, txt);
    if (data_len < 0 || smtp_conn_write(&conn, (unsigned char *)data,
                                        (size_t)data_len) < 0)
        goto cleanup;
    if (smtp_expect(&conn, 200, 299) < 0)
        goto cleanup;
    smtp_send_text(&conn, "QUIT\r\n");
    rc = 0;

cleanup:
    free(data);
    if (conn.tls_active)
        mbedtls_ssl_close_notify(&conn.ssl);
    mbedtls_net_free(&conn.net);
    mbedtls_ssl_free(&conn.ssl);
    mbedtls_ssl_config_free(&conn.conf);
    mbedtls_ctr_drbg_free(&conn.ctr_drbg);
    mbedtls_entropy_free(&conn.entropy);
    return rc;
}

int alice_engine_send_webhook_msg(const char *webhook, const char *platform,
                                  const char *txt, const char *custom_ctype,
                                  const char *custom_body) {
    char *payload;
    char ctype[160];
    const char *p = platform && platform[0] ? platform : "dingtalk";
    int rc;

    if (!webhook || !webhook[0] || !txt)
        return -1;
    payload = (char *)malloc(SMS_PAYLOAD_MAX);
    if (!payload)
        return -1;
    if (alice_engine_build_webhook_payload(webhook, p, txt, custom_ctype, custom_body,
                              payload, SMS_PAYLOAD_MAX,
                              ctype, sizeof(ctype)) < 0)
        rc = -1;
    else
        rc = post_https_body(webhook, ctype, payload, p);
    free(payload);
    return rc;
}

static int append_message_text(char *out, size_t outsz, const char *text) {
    size_t used;
    size_t text_len;

    if (!out || outsz == 0 || !text || !text[0])
        return 0;
    used = strlen(out);
    text_len = strlen(text);
    if (used >= outsz || text_len >= outsz - used)
        return -1;
    memcpy(out + used, text, text_len + 1);
    return 0;
}

int alice_engine_build_push_message_checked(char *out, size_t outsz,
                                            const char *headtxt,
                                            const char *body,
                                            const char *tailtxt) {
    if (!out || outsz == 0)
        return -1;
    out[0] = 0;
    if (headtxt && headtxt[0]) {
        if (append_message_text(out, outsz, headtxt) < 0 ||
            append_message_text(out, outsz, "\n") < 0)
            return -1;
    }
    if (append_message_text(out, outsz, body) < 0)
        return -1;
    if (tailtxt && tailtxt[0]) {
        if (out[0] && append_message_text(out, outsz, "\n") < 0)
            return -1;
        if (append_message_text(out, outsz, tailtxt) < 0)
            return -1;
    }
    return 0;
}

void alice_engine_build_push_message(char *out, size_t outsz,
                                     const char *headtxt,
                                     const char *body,
                                     const char *tailtxt) {
    (void)alice_engine_build_push_message_checked(out, outsz, headtxt,
                                                  body, tailtxt);
}

static void push_decoded_sms(const sms_info_t *info, const char *text,
                             const alice_engine_push_target_t *targets,
                             size_t target_count) {
    char msg[SMS_PUSH_MESSAGE_MAX];
    int n;

    if (!info || !text || !text[0])
        return;
    if (is_sms_uniq_in_queue(info->sender, info->timestamp, text))
        return;
    add_sms_uniq_to_queue(info->sender, info->timestamp, text);
    n = snprintf(msg, sizeof(msg),
                 "[pdu解码后的信息]\n短消息服务中心:%s\n发件人:%s\n时间戳:%s\n短信内容:%s",
                 info->smsc[0] ? info->smsc : "N/A",
                 info->sender[0] ? info->sender : "N/A",
                 info->timestamp[0] ? info->timestamp : "N/A", text);
    if (n < 0 || n >= (int)sizeof(msg)) {
        engine_log("[PDU] decoded message exceeds push buffer");
        return;
    }

    /* 手机号和前后缀属于任务，分别生成每个任务的最终文本。 */
    {
        size_t i;
        int configured = 0;
        int failed = 0;
        for (i = 0; i < target_count; i++) {
            const alice_engine_push_target_t *target = &targets[i];
            char target_body[SMS_PUSH_MESSAGE_MAX];
            char final_msg[SMS_PUSH_MESSAGE_MAX];
            const char *num;

            if (!target->enabled)
                continue;
            configured = 1;
            num = target->num && target->num[0] ? target->num :
                  device_msisdn[0] ? device_msisdn : "N/A";
            n = snprintf(target_body, sizeof(target_body),
                         "接收短信设备手机号:%s\n%s", num, msg);
            if (n < 0 || n >= (int)sizeof(target_body) ||
                alice_engine_build_push_message_checked(
                    final_msg, sizeof(final_msg), target->headtxt,
                    target_body, target->tailtxt) < 0) {
                engine_log("[PDU][%s] formatted message exceeds push buffer",
                           push_target_name(target, i));
                failed = 1;
                continue;
            }
            if (send_one_target_message(target, i, final_msg) < 0)
                failed = 1;
        }
        if (!configured || failed)
            engine_log("[PDU] one or more target deliveries failed");
    }
}

static void process_strace_line_for_sms(
    const char *line, const alice_engine_push_target_t *targets,
    size_t target_count, int long_sms_reassembly) {
    char local[MAX_BUFFER_LEN];
    strncpy(local, line, sizeof(local) - 1);
    local[sizeof(local) - 1] = 0;

    char *p = strstr(local, "+CMT: ");
    if (p) {
        char *first_crlf = strstr(p, "\\r\\n");
        if (first_crlf) {
            char *pdu_start = first_crlf + 4;
            char *pdu_end = strstr(pdu_start, "\\r\\n");
            char pdu[2048] = "";
            if (pdu_end && pdu_end > pdu_start && (pdu_end - pdu_start) < (int)sizeof(pdu)) {
                strncpy(pdu, pdu_start, pdu_end - pdu_start);
                pdu[pdu_end - pdu_start] = 0;
            } else {
                strncpy(pdu, pdu_start, sizeof(pdu)-1);
                pdu[sizeof(pdu)-1] = 0;
            }
            char *pdubegin = pdu;
            while (*pdubegin && (*pdubegin == ' ' || *pdubegin == '\t')) pdubegin++;
            char *pdu_trim = pdubegin;
            size_t trim_len = strlen(pdu_trim);
            if (trim_len > 0) {
                char *pdutail = pdu_trim + trim_len - 1;
                while (pdutail > pdu_trim && (*pdutail == ' ' || *pdutail == '\t')) {
                    *pdutail-- = 0;
                }
            }
            if (pdu_trim[0]) {
                int valid_pdu = 1;
                size_t pdu_len = strlen(pdu_trim);
                size_t pi;
                if (pdu_len < 20) valid_pdu = 0;
                for (pi = 0; pi < pdu_len; pi++) {
                    char c = pdu_trim[pi];
                    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
                        valid_pdu = 0;
                        break;
                    }
                }
                if (valid_pdu) {
                    sms_info_t info;
                    if (decode_pdu(pdu_trim, &info) < 0) {
                        engine_log("[PDU] decode failed");
                        return;
                    }
                    if (info.text[0]) {
                        if (long_sms_reassembly && info.is_concat) {
                            char assembled[SMS_CONCAT_MAX_TEXT + 1];
                            int concat_rc = add_concat_segment(&info, assembled,
                                                               sizeof(assembled));
                            if (concat_rc == 1)
                                push_decoded_sms(&info, assembled, targets,
                                                 target_count);
                        } else {
                            push_decoded_sms(&info, info.text, targets,
                                             target_count);
                        }
                    }
                }
            }
        }
    }
}

// 打印 mbedtls 错误码的帮助函数
static void print_mbedtls_error(int ret, const char *msg) {
    engine_log("[TLS] %s failed: -0x%x", msg, -ret);
}

// 从 URL 中提取主机名和路径
static void parse_url(const char *url, char **host, char **path) {
    char *start;
    char *end;

    if (strstr(url, "https://") == url) {
        start = (char *)url + strlen("https://");
    } else {
        *host = NULL;
        *path = NULL;
        return;
    }

    end = strchr(start, '/');
    if (end) {
        *host = (char *)malloc(end - start + 1);
        strncpy(*host, start, end - start);
        (*host)[end - start] = '\0';
        *path = strdup(end);
    } else {
        *host = strdup(start);
        *path = strdup("/");
    }
}

// 信号处理函数，用于优雅关闭线程
static void engine_signal_handler(int sig) {
    (void)sig;
    threads_running = 0;
    
    // 给线程一些时间来清理
    sleep(1);
    
    // 强制杀死strace进程
    pid_t strace_pid = get_strace_pid_from_file();
    if (strace_pid > 0) {
        kill(strace_pid, SIGTERM);
        usleep(100*1000);
        if (kill(strace_pid, 0) == 0) {
            kill(strace_pid, SIGKILL);
        }
    }
    sigcont_process_by_path(g_target_path);
    sigcont_process_by_path(TARGET_MIFI_PATH);
    sigcont_process_by_path(TARGET_UFI_PATH);
    
    exit(0);
}
