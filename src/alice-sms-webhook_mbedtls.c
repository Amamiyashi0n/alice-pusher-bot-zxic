#include <time.h>
#include <regex.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/version.h>
#include <pthread.h>
#include <signal.h>

#define MAX_BUFFER_LEN 4096


// 函数声明
static pid_t get_strace_pid_from_file(void);
static void set_strace_pid_to_file(pid_t pid);
void extract_write_lines_from_log(void);
void decode_pdu_ucs2(const char *pdu, char *out, size_t outlen);
void send_dingtalk_msg(const char *webhook, const char *txt);
void extract_and_send_sms_from_log(const char *webhook, const char *headtxt, const char *tailtxt);
void print_mbedtls_error(int ret, const char *msg);
void parse_url(const char *url, char **host, char **path);
void signal_handler(int sig);
int find_zte_mifi_pid(void);
void trace_zte_mifi(void);
void rerun_strace_zte_mifi(void);

// 线程控制变量
static volatile int threads_running = 1;
static pthread_t strace_thread_id;
static pthread_t pdu_thread_id;


void trace_zte_mifi() {
    int pid = find_zte_mifi_pid();
    if (pid <= 0) {
        fprintf(stderr, "zte_mifi进程未找到\n");
        return;
    }
    pid_t child = fork();
    if (child == 0) {
        char pidstr[16];
        snprintf(pidstr, sizeof(pidstr), "%d", pid);
        execl("/sbin/strace", "strace", "-f", "-e", "trace=read,write", "-s", "1024", "-p", pidstr, "-o", "/tmp/zte_log.txt", (char*)NULL);
        _exit(127);
    } else if (child > 0) {
        set_strace_pid_to_file(child);
        // 新增：后台定时任务，每天0点清空并重启strace
        if (fork() == 0) {
            while (1) {
                time_t now = time(NULL);
                struct tm *tm_now = localtime(&now);
                int sec_to_midnight = (23 - tm_now->tm_hour) * 3600 + (59 - tm_now->tm_min) * 60 + (60 - tm_now->tm_sec);
                if (sec_to_midnight <= 0 || sec_to_midnight > 86400) sec_to_midnight = 1; // 容错
                sleep(sec_to_midnight);
                // 0点到，kill本程序fork的strace，清空文件，重启strace（同样优雅kill）
                pid_t oldpid = get_strace_pid_from_file();
                if (oldpid > 0) {
                    kill(oldpid, SIGTERM);
                    int wait_count = 0;
                    while (wait_count < 10) {
                        if (kill(oldpid, 0) != 0) break;
                        usleep(100*1000);
                        wait_count++;
                    }
                    if (kill(oldpid, 0) == 0) {
                        kill(oldpid, SIGKILL);
                        usleep(200*1000);
                    }
                    int ztepid = find_zte_mifi_pid();
                    if (ztepid > 0) {
                        kill(ztepid, SIGCONT);
                    }
                }
                FILE *fp = fopen("/tmp/zte_log.txt", "w");
                if (fp) fclose(fp);
                int newpid = find_zte_mifi_pid();
                if (newpid > 0) {
                    pid_t c2 = fork();
                    if (c2 == 0) {
                        char pidstr2[16];
                        snprintf(pidstr2, sizeof(pidstr2), "%d", newpid);
                        execl("/sbin/strace", "strace", "-f", "-e", "trace=read,write", "-s", "1024", "-p", pidstr2, "-o", "/tmp/zte_log.txt", (char*)NULL);
                        _exit(127);
                    } else if (c2 > 0) {
                        set_strace_pid_to_file(c2);
                    }
                }
            }
            _exit(0);
        }
        waitpid(child, NULL, 0);
    } else {
        perror("fork");
    }
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

// 立即清空 /tmp/zte_log.txt 并重启 strace 跟踪（优雅kill，保护zte_mifi）
void rerun_strace_zte_mifi() {
    pid_t oldpid = get_strace_pid_from_file();
    if (oldpid > 0) {
        // 优先SIGTERM优雅退出
        kill(oldpid, SIGTERM);
        int wait_count = 0;
        while (wait_count < 10) { // 最多等1秒
            if (kill(oldpid, 0) != 0) break; // 已退出
            usleep(100*1000);
            wait_count++;
        }
        // 若还在则SIGKILL
        if (kill(oldpid, 0) == 0) {
            kill(oldpid, SIGKILL);
            usleep(200*1000);
        }
        // 杀完strace后，给zte_mifi发SIGCONT，防止其被挂起
        int ztepid = find_zte_mifi_pid();
        if (ztepid > 0) {
            kill(ztepid, SIGCONT);
        }
    }
    FILE *fp = fopen("/tmp/zte_log.txt", "w");
    if (fp) fclose(fp);
    int newpid = find_zte_mifi_pid();
    if (newpid > 0) {
        pid_t c2 = fork();
        if (c2 == 0) {
            char pidstr2[16];
            snprintf(pidstr2, sizeof(pidstr2), "%d", newpid);
            execl("/sbin/strace", "strace", "-f", "-e", "trace=read,write", "-s", "1024", "-p", pidstr2, "-o", "/tmp/zte_log.txt", (char*)NULL);
            _exit(127);
        } else if (c2 > 0) {
            set_strace_pid_to_file(c2);
        }
    }
}

// 查找 /sbin/zte_mifi 的进程 pid，返回第一个找到的 pid，找不到返回 -1
int find_zte_mifi_pid() {
    DIR *dir;
    struct dirent *entry;
    char path[256], buf[256];
    FILE *fp;
    int pid = -1;
    dir = opendir("/proc");
    if (!dir) return -1;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        int id = atoi(entry->d_name);
        if (id <= 0) continue;
        snprintf(path, sizeof(path), "/proc/%d/exe", id);
        ssize_t len = readlink(path, buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            if (strcmp(buf, "/sbin/zte_mifi") == 0) {
                pid = id;
                break;
            }
        }
    }
    closedir(dir);
    return pid;
}

// strace线程函数 - 执行 strace 跟踪 zte_mifi 进程的 read/write 系统调用
void* strace_thread_func(void* arg) {
    char* webhook = (char*)arg;
    
    int pid = find_zte_mifi_pid();
    if (pid <= 0) {
        fprintf(stderr, "zte_mifi进程未找到\n");
        return NULL;
    }
    pid_t child = fork();
    if (child == 0) {
        char pidstr[16];
        snprintf(pidstr, sizeof(pidstr), "%d", pid);
        execl("/sbin/strace", "strace", "-f", "-e", "trace=read,write", "-s", "1024", "-p", pidstr, "-o", "/tmp/zte_log.txt", (char*)NULL);
        _exit(127);
    } else if (child > 0) {
        set_strace_pid_to_file(child);
        // 后台定时任务，改为每1分钟重启一次strace
        if (fork() == 0) {
            while (threads_running) {
                // 等待60秒或者主线程退出
                int sec_to_restart = 60; // 改为1分钟
                int slept = 0;
                while (slept < sec_to_restart && threads_running) {
                    int to_sleep = (sec_to_restart - slept) > 10 ? 10 : (sec_to_restart - slept); // 最多睡10秒，以便快速响应主线程退出
                    sleep(to_sleep);
                    slept += to_sleep;
                }
                
                // 如果主线程已退出，则退出循环
                if (!threads_running) break;
                
                // 到时间了，kill本程序fork的strace，清空文件，重启strace
                pid_t oldpid = get_strace_pid_from_file();
                if (oldpid > 0) {
                    kill(oldpid, SIGTERM);
                    int wait_count = 0;
                    while (wait_count < 10) {
                        if (kill(oldpid, 0) != 0) break;
                        usleep(100*1000);
                        wait_count++;
                    }
                    if (kill(oldpid, 0) == 0) {
                        kill(oldpid, SIGKILL);
                        usleep(200*1000);
                    }
                    int ztepid = find_zte_mifi_pid();
                    if (ztepid > 0) {
                        kill(ztepid, SIGCONT);
                    }
                }
                FILE *fp = fopen("/tmp/zte_log.txt", "w");
                if (fp) fclose(fp);
                int newpid = find_zte_mifi_pid();
                if (newpid > 0) {
                    pid_t c2 = fork();
                    if (c2 == 0) {
                        char pidstr2[16];
                        snprintf(pidstr2, sizeof(pidstr2), "%d", newpid);
                        execl("/sbin/strace", "strace", "-f", "-e", "trace=read,write", "-s", "1024", "-p", pidstr2, "-o", "/tmp/zte_log.txt", (char*)NULL);
                        _exit(127);
                    } else if (c2 > 0) {
                        set_strace_pid_to_file(c2);
                    }
                }
            }
            _exit(0);
        }
        // 等待child进程结束
        waitpid(child, NULL, 0);
    } else {
        perror("fork");
    }
    return NULL;
}

// PDU处理线程函数
void* pdu_thread_func(void* arg) {
    char** args = (char**)arg;
    char* webhook = args[0];
    char* headtxt = args[1];
    char* tailtxt = args[2];

    // 添加线程清理处理程序
    pthread_cleanup_push(free, webhook);
    pthread_cleanup_push(free, headtxt);
    pthread_cleanup_push(free, tailtxt);
    pthread_cleanup_push(free, args);

    time_t last_size = 0;
    while (threads_running) {
        FILE *fp = fopen("/tmp/zte_log.txt", "r");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long size = ftell(fp);
            fclose(fp);
            if (size != last_size) {
                last_size = size;
                extract_and_send_sms_from_log(webhook, headtxt, tailtxt);
            }
        }
        usleep(1000*1000); // 1秒轮询
    }
    
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);

    return NULL;
}

// 提取 /tmp/zte_log.txt 中所有 write(数字, "内容", 数字) = 数字 的行
void extract_write_lines_from_log() {
    FILE *fp = fopen("/tmp/zte_log.txt", "r");
    if (!fp) {
        perror("fopen /tmp/zte_log.txt");
        return;
    }
    char line[2048];
    // 匹配 write(数字, "内容", 数字) = 数字
    regex_t reg;
    // 匹配如: write(16, "...", 91) = 91
    regcomp(&reg, "^\\s*write\\([0-9]+, \\\".*\\\", [0-9]+\\) = [0-9]+", REG_EXTENDED);
    while (fgets(line, sizeof(line), fp)) {
        if (regexec(&reg, line, 0, NULL, 0) == 0) {
            printf("%s", line);
        }
    }
    regfree(&reg);
    fclose(fp);
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
    char text[128];
    int text_len;
} sms_info_t;

// 新增：基于Sender+TimeStamp+Text的去重队列
#define SMS_UNIQ_QUEUE_SIZE 100
typedef struct {
    char sender[32];
    char timestamp[32];
    char text[128];
} sms_uniq_t;
static sms_uniq_t sms_uniq_queue[SMS_UNIQ_QUEUE_SIZE];
static int sms_uniq_head = 0;
static int sms_uniq_count = 0;

int is_sms_uniq_in_queue(const char *sender, const char *timestamp, const char *text) {
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
void add_sms_uniq_to_queue(const char *sender, const char *timestamp, const char *text) {
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

static char last_sender[32] = "";
static char last_text[128] = "";
static time_t last_sms_time = 0;
static char last_pdu[256] = "";
static time_t last_pdu_time = 0;
static time_t service_start_time = 0;

// 完整的PDU解码，包含SMSC、发件人、时间戳等信息
void decode_pdu(const char *pdu, sms_info_t *info) {
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
        memmove(info->smsc, info->smsc + 2, strlen(info->smsc) - 1);
    }

    idx += 2; // PDU类型
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
        memmove(info->sender, info->sender + 2, strlen(info->sender) - 1);
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

    int ucs2_len = text_len_oct * 2;
    char ucs2_hex[256] = {0};
    strncpy(ucs2_hex, pdu + idx, ucs2_len);
    ucs2_hex[ucs2_len] = 0;
    k = 0;
    for (i = 0; i < ucs2_len && k + 3 < (int)sizeof(info->text); i += 4) {
        unsigned int ucs2;
        sscanf(ucs2_hex + i, "%4x", &ucs2);
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
}

// 为保持兼容性保留的旧函数
static char last_sms_compat[256] = "";
static time_t last_sms_time_compat = 0;

void decode_pdu_ucs2(const char *pdu, char *out, size_t outlen) {
    // 假设pdu内容全为UCS2编码的16进制字符串
    size_t len = strlen(pdu);
    size_t i = 0, j = 0;
    // 兼容原逻辑：如果长度太短直接返回空
    if (len < 4) { out[0] = 0; return; }
    while (i + 3 < len && j + 3 < outlen) {
        unsigned int ucs2;
        if (sscanf(pdu + i, "%4x", &ucs2) != 1) break;
        if (ucs2 == 0) break;
        if (ucs2 < 0x80) {
            out[j++] = (char)ucs2;
        } else if (ucs2 < 0x800) {
            out[j++] = 0xC0 | (ucs2 >> 6);
            out[j++] = 0x80 | (ucs2 & 0x3F);
        } else {
            out[j++] = 0xE0 | (ucs2 >> 12);
            out[j++] = 0x80 | ((ucs2 >> 6) & 0x3F);
            out[j++] = 0x80 | (ucs2 & 0x3F);
        }
        i += 4;
    }
    out[j] = 0;
}

// 发送钉钉消息接口（只支持text）
void send_dingtalk_msg(const char *webhook, const char *txt) {
    // 构造钉钉 content 字段，带 Msg: 换行和 text:，并做严格JSON安全转义
    char safe_txt[512];
    int i = 0, j = 0;
    while (txt[i] && j < (int)sizeof(safe_txt) - 1) {
        unsigned char c = (unsigned char)txt[i];
        if (c == '"') {
            if (j < (int)sizeof(safe_txt) - 2) { safe_txt[j++] = '\\'; safe_txt[j++] = '"'; }
        } else if (c == '\\') {
            if (j < (int)sizeof(safe_txt) - 2) { safe_txt[j++] = '\\'; safe_txt[j++] = '\\'; }
        } else if (c == '\n') {
            if (j < (int)sizeof(safe_txt) - 2) { safe_txt[j++] = '\\'; safe_txt[j++] = 'n'; }
        } else if (c == '\r') {
            if (j < (int)sizeof(safe_txt) - 2) { safe_txt[j++] = '\\'; safe_txt[j++] = 'r'; }
        } else if (c == '\t') {
            if (j < (int)sizeof(safe_txt) - 2) { safe_txt[j++] = '\\'; safe_txt[j++] = 't'; }
        } else if (c < 0x20) {
            // 其它不可见控制字符直接跳过
        } else {
            safe_txt[j++] = c;
        }
        i++;
    }
    safe_txt[j] = 0;
    char content[1024];
    snprintf(content, sizeof(content), "Msg:\\n%s", safe_txt);
    // 构造完整 JSON
    char json_msg[2048];
    snprintf(json_msg, sizeof(json_msg), "{\"msgtype\":\"text\",\"text\":{\"content\":\"%s\"}}", content);

    // 直接用 mbedtls HTTPS POST 发送 JSON
    char *host = NULL, *path = NULL;
    parse_url(webhook, &host, &path);
    if (!host || !path) {
        if (host) free(host);
        if (path) free(path);
        return;
    }
    int ret = 0;
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *port = "443";
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char *pers = "ssl_client";

    // 使用 goto 语句确保资源在所有路径下都被释放
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        print_mbedtls_error(ret, "mbedtls_ctr_drbg_seed");
        goto cleanup;
    }
    if ((ret = mbedtls_net_connect(&server_fd, host, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
        print_mbedtls_error(ret, "mbedtls_net_connect");
        goto cleanup;
    }
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        print_mbedtls_error(ret, "mbedtls_ssl_config_defaults");
        goto cleanup;
    }
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        print_mbedtls_error(ret, "mbedtls_ssl_setup");
        goto cleanup;
    }
    if ((ret = mbedtls_ssl_set_hostname(&ssl, host)) != 0) {
        print_mbedtls_error(ret, "mbedtls_ssl_set_hostname");
        goto cleanup;
    }
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    if ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        print_mbedtls_error(ret, "mbedtls_ssl_handshake");
        goto cleanup;
    }

    // 发送 HTTP POST 请求
    char request[4096];
    snprintf(request, sizeof(request), "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %lu\r\n\r\n%s",
             path, host, strlen(json_msg), json_msg);
    if ((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)request, strlen(request))) <= 0) {
        print_mbedtls_error(ret, "mbedtls_ssl_write");
        goto cleanup;
    }

    // 读取响应
    unsigned char buffer[4096];
    ret = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer) - 1);
    if (ret <= 0 && ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        print_mbedtls_error(ret, "mbedtls_ssl_read");
        goto cleanup;
    }

cleanup:
    // 确保在所有路径下都释放资源
    free(host);
    free(path);
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

// 提取日志中的PDU短信，解码、去重、发送到钉钉，支持自定义头尾
void extract_and_send_sms_from_log(const char *webhook, const char *headtxt, const char *tailtxt) {
    FILE *fp = fopen("/tmp/zte_log.txt", "r");
    if (!fp) return;
    char line[2048];
    regex_t reg;
    // 匹配如: write(16, "...", 91) = 91，兼容C regex语法，不用\s和\)
    regcomp(&reg, "^[ \t]*write\\([0-9]+, \".*\", [0-9]+\\) = [0-9]+", REG_EXTENDED);
    int line_num = 0;
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        int is_write = (regexec(&reg, line, 0, NULL, 0) == 0);
        char *p = strstr(line, "+CMT: ");
        // printf("[DEBUG] line %d: %s", line_num, line);
        // printf("[DEBUG] is_write: %d\n", is_write);
        // printf("[DEBUG] +CMT: pos: %ld\n", p ? (long)(p-line) : -1L);
        if (p) {
            // 修改这里：在strace输出中，换行符是字符串"\r\n"而不是实际的\r\n字符
            char *first_crlf = strstr(p, "\\r\\n");
            printf("[DEBUG] first_crlf pos: %ld\n", first_crlf ? (long)(first_crlf-line) : -1L);
            if (first_crlf) {
                // 修改这里：跳过"\r\n"字符串（4个字符）
                char *pdu_start = first_crlf + 4;
                printf("[DEBUG] pdu_start offset: %ld\n", (long)(pdu_start-line));
                // 同样查找结束标记也需要查找字符串"\r\n"
                char *pdu_end = strstr(pdu_start, "\\r\\n");
                if (pdu_end) printf("[DEBUG] pdu_end offset: %ld\n", (long)(pdu_end-line));
                char pdu[256] = "";
                if (pdu_end && pdu_end > pdu_start && (pdu_end - pdu_start) < (int)sizeof(pdu)) {
                    strncpy(pdu, pdu_start, pdu_end - pdu_start);
                    pdu[pdu_end - pdu_start] = 0;
                } else {
                    strncpy(pdu, pdu_start, sizeof(pdu)-1);
                    pdu[sizeof(pdu)-1] = 0;
                }
                printf("[DEBUG] pdu_raw: %s\n", pdu);
                printf("[DEBUG] pdu_raw_len: %zu\n", strlen(pdu));
                char *pdubegin = pdu;
                while (*pdubegin && (*pdubegin == ' ' || *pdubegin == '\t')) pdubegin++;
                char *pdu_trim = pdubegin;
                char *pdutail = pdu_trim + strlen(pdu_trim) - 1;
                while (pdutail > pdu_trim && (*pdutail == ' ' || *pdutail == '\t')) *pdutail-- = 0;
                printf("[DEBUG] pdu_trim: %s\n", pdu_trim);
                printf("[DEBUG] pdu_trim_len: %zu\n", strlen(pdu_trim));
                if (pdu_trim[0]) {
                    // 过滤异常PDU：长度至少20且全为十六进制字符
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
                        printf("[DEBUG] sms_decoded: %s\n", info.text);
                        printf("[DEBUG] sms_decoded_len: %zu\n", strlen(info.text));
                        size_t textlen = strlen(info.text);
                        if (textlen > 0) { // 只推送有内容的短信
                            // 新去重机制：Sender+TimeStamp+Text三元组唯一
                            if (!is_sms_uniq_in_queue(info.sender, info.timestamp, info.text)) {
                                add_sms_uniq_to_queue(info.sender, info.timestamp, info.text);
                                char msg[512];
                                snprintf(msg, sizeof(msg),
                                    "SMSC:%s\nSender:%s\nTimeStamp:%s\nText:%s",
                                    info.smsc[0] ? info.smsc : "N/A",
                                    info.sender[0] ? info.sender : "N/A",
                                    info.timestamp[0] ? info.timestamp : "N/A",
                                    info.text);
                                send_dingtalk_msg(webhook, msg);
                            } else {
                                printf("[DEBUG] skip duplicate sms: Sender=%s, TimeStamp=%s, Text=%s\n", info.sender, info.timestamp, info.text);
                            }
                        }
                    } else {
                        printf("[DEBUG] skip invalid pdu: %s\n", pdu_trim);
                    }
                }
            } else {
                printf("[DEBUG] first_crlf not found after +CMT:\n");
            }
        }
    }
    regfree(&reg);
    fclose(fp);
}

// 打印 mbedtls 错误码的帮助函数
void print_mbedtls_error(int ret, const char *msg) {
    fprintf(stderr, "%s failed: -0x%x\n", msg, -ret);
}

// 从 URL 中提取主机名和路径
void parse_url(const char *url, char **host, char **path) {
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
void signal_handler(int sig) {
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
    
    exit(0);
}

int main(int argc, char *argv[]) {
    int only_service_mode = 0;
    int only_strace_mode = 0;
    int only_rerun_mode = 0;
    int only_send_once_mode = 0; // 新增
    char *headtxt = NULL, *tailtxt = NULL;
    int i;
    for (i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--mode=strace_zte_mifi") == 0)) {
            only_strace_mode = 1;
        }
        if ((strcmp(argv[i], "--mode=re-run-strace_zte_mifi") == 0)) {
            only_rerun_mode = 1;
        }
        if ((strcmp(argv[i], "--mode=service_start") == 0)) {
            only_service_mode = 1;
        }
        if ((strcmp(argv[i], "--mode=send_once") == 0)) { // 新增
            only_send_once_mode = 1;
        }
        if (strncmp(argv[i], "--headtxt=", 10) == 0) {
            headtxt = argv[i] + 10;
        }
        if (strncmp(argv[i], "--tailtxt=", 10) == 0) {
            tailtxt = argv[i] + 10;
        }
    }
    if (only_strace_mode && argc == 2) {
        trace_zte_mifi();
        return 0;
    }
    if (only_rerun_mode && argc == 2) {
        rerun_strace_zte_mifi();
        return 0;
    }
    if (only_service_mode) {
        service_start_time = time(NULL);
        char *webhook = NULL;
        for (i = 1; i < argc; i++) {
            if (strncmp(argv[i], "--url=", 6) == 0) {
                webhook = argv[i] + 6;
            }
        }
        if (!webhook || strlen(webhook) == 0) {
            fprintf(stderr, "Error: --mode=service_start 时必须指定 --url=<webhook_url> 参数！\n");
            return 1;
        }
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        if (pthread_create(&strace_thread_id, NULL, strace_thread_func, webhook) != 0) {
            perror("Failed to create strace thread");
            return 1;
        }
        char* pdu_args[3] = {webhook, headtxt, tailtxt};
        if (pthread_create(&pdu_thread_id, NULL, pdu_thread_func, pdu_args) != 0) {
            perror("Failed to create PDU thread");
            return 1;
        }
        pthread_join(strace_thread_id, NULL);
        pthread_join(pdu_thread_id, NULL);
        return 0;
    }
    if (only_send_once_mode) {
        char *url = NULL, *msgtype = NULL, *txt = NULL;
        for (i = 1; i < argc; i++) {
            if (strncmp(argv[i], "--url=", 6) == 0) {
                url = argv[i] + 6;
            } else if (strncmp(argv[i], "--msgtype=", 10) == 0) {
                msgtype = argv[i] + 10;
            } else if (strncmp(argv[i], "--txt=", 6) == 0) {
                txt = argv[i] + 6;
            }
        }
        if (!url || !msgtype || !txt) {
            fprintf(stderr, "Usage: %s --mode=send_once --url=<webhook_url> --msgtype=text --txt=<content>\n", argv[0]);
            return 1;
        }
        char *host = NULL, *path = NULL;
        parse_url(url, &host, &path);
        if (!host || !path) {
            fprintf(stderr, "Invalid webhook URL format.\n");
            if (host) free(host);
            if (path) free(path);
            return 1;
        }
        char data[MAX_BUFFER_LEN];
        if (strcmp(msgtype, "text") == 0) {
            snprintf(data, sizeof(data), "{\"msgtype\":\"text\",\"text\":{\"content\":\"%s\"}}", txt);
        } else {
            fprintf(stderr, "Only msgtype=text is supported.\n");
            free(host); free(path);
            return 1;
        }
        int ret = 0;
        mbedtls_net_context server_fd;
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        const char *port = "443";
        mbedtls_net_init(&server_fd);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        const char *pers = "ssl_client";
        if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
            print_mbedtls_error(ret, "mbedtls_ctr_drbg_seed");
            goto cleanup_once;
        }
        if ((ret = mbedtls_net_connect(&server_fd, host, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
            print_mbedtls_error(ret, "mbedtls_net_connect");
            goto cleanup_once;
        }
        if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            print_mbedtls_error(ret, "mbedtls_ssl_config_defaults");
            goto cleanup_once;
        }
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
            print_mbedtls_error(ret, "mbedtls_ssl_setup");
            goto cleanup_once;
        }
        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print_mbedtls_error(ret, "mbedtls_ssl_handshake");
                goto cleanup_once;
            }
        }
        char request_buffer[MAX_BUFFER_LEN];
        snprintf(request_buffer, sizeof(request_buffer),
                 "POST %s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "Content-Type: application/json;charset=utf-8\r\n"
                 "Content-Length: %zu\r\n"
                 "\r\n"
                 "%s",
                 path, host, strlen(data), data);
        while ((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)request_buffer, strlen(request_buffer))) <= 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print_mbedtls_error(ret, "mbedtls_ssl_write");
                goto cleanup_once;
            }
        }
        unsigned char buf[1024];
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
        if (ret > 0) {
            printf("%s\n", buf);
        } else if (ret < 0) {
            print_mbedtls_error(ret, "mbedtls_ssl_read");
        }
    cleanup_once:
        if (host) free(host);
        if (path) free(path);
        mbedtls_net_free(&server_fd);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return ret;
    }
    // 保持原有兼容模式
    char *url = NULL, *msgtype = NULL, *txt = NULL;
    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--url=", 6) == 0) {
            url = argv[i] + 6;
        } else if (strncmp(argv[i], "--msgtype=", 10) == 0) {
            msgtype = argv[i] + 10;
        } else if (strncmp(argv[i], "--txt=", 6) == 0) {
            txt = argv[i] + 6;
        }
    }
    if (!url || !msgtype || !txt) {
        fprintf(stderr, "Usage: %s --url=<webhook_url> --msgtype=text --txt=<content>\n", argv[0]);
        return 1;
    }
    char *host = NULL, *path = NULL;
    parse_url(url, &host, &path);
    if (!host || !path) {
        fprintf(stderr, "Invalid webhook URL format.\n");
        if (host) free(host);
        if (path) free(path);
        return 1;
    }
    char data[MAX_BUFFER_LEN];
    if (strcmp(msgtype, "text") == 0) {
        snprintf(data, sizeof(data), "{\"msgtype\":\"text\",\"text\":{\"content\":\"%s\"}}", txt);
    } else {
        fprintf(stderr, "Only msgtype=text is supported.\n");
        free(host); free(path);
        return 1;
    }
    int ret = 0;
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *port = "443";
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char *pers = "ssl_client";
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        print_mbedtls_error(ret, "mbedtls_ctr_drbg_seed");
        goto cleanup;
    }
    if ((ret = mbedtls_net_connect(&server_fd, host, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
        print_mbedtls_error(ret, "mbedtls_net_connect");
        goto cleanup;
    }
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        print_mbedtls_error(ret, "mbedtls_ssl_config_defaults");
        goto cleanup;
    }
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        print_mbedtls_error(ret, "mbedtls_ssl_setup");
        goto cleanup;
    }
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_mbedtls_error(ret, "mbedtls_ssl_handshake");
            goto cleanup;
        }
    }
    char request_buffer[MAX_BUFFER_LEN];
    snprintf(request_buffer, sizeof(request_buffer),
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/json;charset=utf-8\r\n"
             "Content-Length: %zu\r\n"
             "\r\n"
             "%s",
             path, host, strlen(data), data);
    while ((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)request_buffer, strlen(request_buffer))) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_mbedtls_error(ret, "mbedtls_ssl_write");
            goto cleanup;
        }
    }
    unsigned char buf[1024];
    memset(buf, 0, sizeof(buf));
    ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
    if (ret > 0) {
        printf("%s\n", buf);
    } else if (ret < 0) {
        print_mbedtls_error(ret, "mbedtls_ssl_read");
    }
cleanup:
    if (host) free(host);
    if (path) free(path);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}
