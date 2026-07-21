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
#define MAX_BUFFER_LEN 4096
#define STRACE_QUEUE_LINES 64
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

// 线程控制变量
static volatile int threads_running = 1;
static pthread_t strace_thread_id;
static pthread_t pdu_thread_id;
static char device_msisdn[64] = "";
static alice_engine_log_fn g_log_fn;
static void *g_log_ctx;

static void process_strace_line_for_sms(const char *line, const char *webhook,
                                        const char *platform,
                                        const char *custom_ctype,
                                        const char *custom_body,
                                        const char *headtxt,
                                        const char *tailtxt);

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

int alice_engine_start_service(const alice_engine_service_config_t *cfg) {
    const char *platform;
    const char *target_path;
    char target_path_buf[256];
    char *pdu_args[6];

    if (!cfg || !cfg->webhook || !cfg->webhook[0]) {
        errno = EINVAL;
        return -1;
    }

    platform = alice_engine_normalize_platform(cfg->platform && cfg->platform[0] ?
                                               cfg->platform :
                                               alice_engine_detect_platform_from_url(cfg->webhook));
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
    pdu_args[0] = (char *)cfg->webhook;
    pdu_args[1] = (char *)platform;
    pdu_args[2] = (char *)cfg->custom_ctype;
    pdu_args[3] = (char *)cfg->custom_body;
    pdu_args[4] = (char *)cfg->headtxt;
    pdu_args[5] = (char *)cfg->tailtxt;
    if (pthread_create(&pdu_thread_id, NULL, pdu_thread_func,
                       pdu_args) != 0) {
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
                            strace_queue_push_line(partial);
                            partial_len = 0;
                        }
                        if (partial_len + 1 >= sizeof(partial)) {
                            partial[partial_len] = 0;
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
    char** args = (char**)arg;
    char* webhook = args[0];
    char* platform = args[1];
    char* custom_ctype = args[2];
    char* custom_body = args[3];
    char* headtxt = args[4];
    char* tailtxt = args[5];

    while (threads_running) {
        char line[MAX_BUFFER_LEN];
        if (strace_queue_pop_line(line, sizeof(line), 1000)) {
            process_strace_line_for_sms(line, webhook, platform,
                                        custom_ctype, custom_body,
                                        headtxt, tailtxt);
        }
    }
    return NULL;
}

// PDU解码信息结构体和解码函数

typedef struct {
    char smsc[32];
    char sender[32];
    char timestamp[32];
    char tp_pid[4];
    char tp_dcs[4];
    char tp_dcs_desc[32];
    char sms_class[8];
    char alphabet[32];
    char text[2048];
    int text_len;
} sms_info_t;

// 新增：基于Sender+TimeStamp+Text的去重队列
#define SMS_UNIQ_QUEUE_SIZE 100
typedef struct {
    char sender[32];
    char timestamp[32];
    char text[2048];
} sms_uniq_t;
static sms_uniq_t sms_uniq_queue[SMS_UNIQ_QUEUE_SIZE];
static int sms_uniq_head = 0;
static int sms_uniq_count = 0;

static int is_sms_uniq_in_queue(const char *sender, const char *timestamp, const char *text) {
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
static void add_sms_uniq_to_queue(const char *sender, const char *timestamp, const char *text) {
    int idx;
    if (sms_uniq_count < SMS_UNIQ_QUEUE_SIZE) {
        idx = (sms_uniq_head + sms_uniq_count) % SMS_UNIQ_QUEUE_SIZE;
        strncpy(sms_uniq_queue[idx].sender, sender, sizeof(sms_uniq_queue[idx].sender)-1);
        sms_uniq_queue[idx].sender[sizeof(sms_uniq_queue[idx].sender)-1] = 0;
        strncpy(sms_uniq_queue[idx].timestamp, timestamp, sizeof(sms_uniq_queue[idx].timestamp)-1);
        sms_uniq_queue[idx].timestamp[sizeof(sms_uniq_queue[idx].timestamp)-1] = 0;
        strncpy(sms_uniq_queue[idx].text, text, sizeof(sms_uniq_queue[idx].text)-1);
        sms_uniq_queue[idx].text[sizeof(sms_uniq_queue[idx].text)-1] = 0;
        sms_uniq_count++;
    } else {
        strncpy(sms_uniq_queue[sms_uniq_head].sender, sender, sizeof(sms_uniq_queue[0].sender)-1);
        sms_uniq_queue[sms_uniq_head].sender[sizeof(sms_uniq_queue[0].sender)-1] = 0;
        strncpy(sms_uniq_queue[sms_uniq_head].timestamp, timestamp, sizeof(sms_uniq_queue[0].timestamp)-1);
        sms_uniq_queue[sms_uniq_head].timestamp[sizeof(sms_uniq_queue[0].timestamp)-1] = 0;
        strncpy(sms_uniq_queue[sms_uniq_head].text, text, sizeof(sms_uniq_queue[0].text)-1);
        sms_uniq_queue[sms_uniq_head].text[sizeof(sms_uniq_queue[0].text)-1] = 0;
        sms_uniq_head = (sms_uniq_head + 1) % SMS_UNIQ_QUEUE_SIZE;
    }
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

// 完整的PDU解码，包含SMSC、发件人、时间戳等信息
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
    char json_txt[3072];
    char url_txt[3072];

    if (!tmpl || !tmpl[0] || !outsz)
        return -1;
    safe_copy(out, outsz, tmpl);
    json_escape(json_txt, sizeof(json_txt), txt);
    form_url_escape(url_txt, sizeof(url_txt), txt);
    if (replace_token(out, outsz, "{{json_text}}", json_txt) < 0)
        return -1;
    if (replace_token(out, outsz, "{{url_text}}", url_txt) < 0)
        return -1;
    if (replace_token(out, outsz, "{{text}}", txt ? txt : "") < 0)
        return -1;
    return 0;
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
    char safe_txt[3072];
    char safe_key[512];
    char enc_txt[3072];
    const char *p = platform && platform[0] ? platform : "dingtalk";

    if (!payload_sz || !ctype_sz)
        return -1;
    payload[0] = 0;
    ctype[0] = 0;

    if (strcmp(p, "serverchan") == 0) {
        form_url_escape(enc_txt, sizeof(enc_txt), txt);
        snprintf(ctype, ctype_sz, "application/x-www-form-urlencoded");
        snprintf(payload, payload_sz, "title=Alice%%20Pusher&desp=%s", enc_txt);
        return payload[0] ? 0 : -1;
    }
    if (strcmp(p, "telegram") == 0) {
        form_url_escape(enc_txt, sizeof(enc_txt), txt);
        snprintf(ctype, ctype_sz, "application/x-www-form-urlencoded");
        snprintf(payload, payload_sz, "text=%s", enc_txt);
        return payload[0] ? 0 : -1;
    }
    if (strcmp(p, "custom") == 0) {
        const char *tmpl = custom_body && custom_body[0] ? custom_body :
                           "{\"text\":\"{{json_text}}\"}";
        snprintf(ctype, ctype_sz, "%s",
                 custom_ctype && custom_ctype[0] ? custom_ctype :
                 "application/json;charset=utf-8");
        if (render_custom_body(tmpl, txt, payload, payload_sz) < 0)
            return -1;
        return payload[0] ? 0 : -1;
    }

    json_escape(safe_txt, sizeof(safe_txt), txt);
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
            return -1;
        json_escape(safe_key, sizeof(safe_key), bark_key);
        snprintf(payload, payload_sz,
                 "{\"title\":\"Alice Pusher\",\"body\":\"%s\",\"device_key\":\"%s\"}",
                 safe_txt, safe_key);
    } else {
        snprintf(payload, payload_sz,
                 "{\"msgtype\":\"text\",\"text\":{\"content\":\"%s\"}}",
                 safe_txt);
    }
    return payload[0] ? 0 : -1;
}

static int post_https_body(const char *webhook, const char *ctype,
                           const char *payload, const char *platform) {
    char *host = NULL, *path = NULL;
    const char *request_path;
    char request_buffer[8192];
    unsigned char read_buf[1024];
    int request_len;
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

    request_len = snprintf(request_buffer, sizeof(request_buffer),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: alice-pusher-bot/1.0\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        request_path, host, ctype, strlen(payload), payload);
    if (request_len <= 0 || request_len >= (int)sizeof(request_buffer)) {
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

int alice_engine_send_webhook_msg(const char *webhook, const char *platform,
                                  const char *txt, const char *custom_ctype,
                                  const char *custom_body) {
    char payload[4096];
    char ctype[160];
    const char *p = platform && platform[0] ? platform : "dingtalk";

    if (!webhook || !webhook[0] || !txt)
        return -1;
    if (alice_engine_build_webhook_payload(webhook, p, txt, custom_ctype, custom_body,
                              payload, sizeof(payload),
                              ctype, sizeof(ctype)) < 0)
        return -1;
    return post_https_body(webhook, ctype, payload, p);
}

static void append_message_text(char *out, size_t outsz, const char *text) {
    size_t used;
    size_t left;

    if (!out || outsz == 0 || !text || !text[0])
        return;
    used = strlen(out);
    if (used >= outsz - 1)
        return;
    left = outsz - used - 1;
    strncat(out, text, left);
}

void alice_engine_build_push_message(char *out, size_t outsz,
                               const char *headtxt,
                               const char *body,
                               const char *tailtxt) {
    if (!out || outsz == 0)
        return;
    out[0] = 0;
    if (headtxt && headtxt[0]) {
        append_message_text(out, outsz, headtxt);
        append_message_text(out, outsz, "\n");
    }
    append_message_text(out, outsz, body);
    if (tailtxt && tailtxt[0]) {
        if (out[0])
            append_message_text(out, outsz, "\n");
        append_message_text(out, outsz, tailtxt);
    }
}

static void process_strace_line_for_sms(const char *line, const char *webhook,
                                        const char *platform,
                                        const char *custom_ctype,
                                        const char *custom_body,
                                        const char *headtxt,
                                        const char *tailtxt) {
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
                    decode_pdu(pdu_trim, &info);
                    size_t textlen = strlen(info.text);
                    if (textlen > 0) {
                        if (!is_sms_uniq_in_queue(info.sender, info.timestamp, info.text)) {
                            add_sms_uniq_to_queue(info.sender, info.timestamp, info.text);
                            char msg[1024];
                            char final_msg[2048];
                            snprintf(msg, sizeof(msg),
                                "接收短信设备手机号:%s\n[pdu解码后的信息]\n短消息服务中心:%s\n发件人:%s\n时间戳:%s\n短信内容:%s",
                                device_msisdn[0] ? device_msisdn : "N/A",
                                info.smsc[0] ? info.smsc : "N/A",
                                info.sender[0] ? info.sender : "N/A",
                                info.timestamp[0] ? info.timestamp : "N/A",
                                info.text);
                            alice_engine_build_push_message(final_msg, sizeof(final_msg),
                                               headtxt, msg, tailtxt);
                            alice_engine_send_webhook_msg(webhook, platform, final_msg,
                                             custom_ctype, custom_body);
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
