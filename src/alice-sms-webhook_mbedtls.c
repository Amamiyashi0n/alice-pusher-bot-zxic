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
#include <sys/stat.h>

#define MAX_BUFFER_LEN 4096

// 用于限制PDU的最大长度
#define MAX_PDU_LENGTH 2048

// 添加连续检测结构体
typedef struct {
    char sender[64];
    char timestamp[64];
    char text[1024];
    int count;
    time_t last_seen;
} sms_detection_t;

#define DETECTION_WINDOW_SIZE 10
// 修复拼写错误：DEECTION_WINDOW_SIZE -> DETECTION_WINDOW_SIZE
static sms_detection_t detection_window[DETECTION_WINDOW_SIZE];
static int detection_head = 0;
static int detection_count = 0;
// 接收短信状态变量
static volatile int sms_receiving = 0;  // 标记是否正在接收短信
static time_t last_sms_activity = 0;    // 上次短信活动时间

// SIM卡号相关全局变量
static char global_sim_number[32] = {0};
static int sim_number_initialized = 0;

// 添加PDU片段队列结构体
typedef struct {
    char sender[64];
    char timestamp[64];
    char pdu_fragment[2048];
    time_t received_time;
} pdu_fragment_t;

#define PDU_FRAGMENT_QUEUE_SIZE 20
static pdu_fragment_t pdu_fragment_queue[PDU_FRAGMENT_QUEUE_SIZE];
static int pdu_fragment_head = 0;
static int pdu_fragment_count = 0;

// 添加长短信片段结构体
typedef struct {
    char sender[64];
    char timestamp[64];
    unsigned char ref;      // 参考编号
    unsigned char max;      // 总片段数
    unsigned char seq;      // 当前片段序号
    char text[2048];        // 片段文本内容
    time_t received_time;   // 接收时间
    char pdu[2048];         // 片段PDU内容
} long_sms_fragment_t;

#define LONG_SMS_FRAGMENT_QUEUE_SIZE 50
static long_sms_fragment_t long_sms_fragment_queue[LONG_SMS_FRAGMENT_QUEUE_SIZE];
static int long_sms_fragment_head = 0;
static int long_sms_fragment_count = 0;

// 添加长短信跟踪结构体
typedef struct {
    char sender[64];
    char timestamp[64];
    time_t first_seen;
} long_sms_tracker_t;

#define LONG_SMS_TRACKER_SIZE 20
static long_sms_tracker_t long_sms_tracker[LONG_SMS_TRACKER_SIZE];
static int long_sms_tracker_count = 0;

// 添加临时存储结构体，用于5秒周期检测
typedef struct {
    char sender[64];
    char timestamp[64];
    char text[8192];
    char pdu_list[10][2048]; // 存储最多10个PDU片段
    int pdu_count;
    time_t first_received;
    time_t last_received;
} temp_sms_storage_t;

#define TEMP_SMS_STORAGE_SIZE 20
static temp_sms_storage_t temp_sms_storage[TEMP_SMS_STORAGE_SIZE];
static int temp_sms_storage_count = 0;

// 函数声明
static pid_t get_strace_pid_from_file(void);
static void set_strace_pid_to_file(pid_t pid);
void extract_write_lines_from_log(void);
void decode_pdu_ucs2(const char *pdu, char *out, size_t outlen);
void send_dingtalk_msg(const char *webhook, const char *txt, const char *keyword);
void extract_and_send_sms_from_log(const char *webhook, const char *headtxt, const char *tailtxt, const char *keyword, const char *number);
void print_mbedtls_error(int ret, const char *msg);
void parse_url(const char *url, char **host, char **path);
void signal_handler(int sig);
int find_zte_mifi_pid(void);
char* get_sim_number_from_nv(void);
void init_sim_number(void);
void filter_garbage_chars(char *text); // 新增函数声明

// 线程控制变量
static volatile int threads_running = 1;
static pthread_t strace_thread_id;
static pthread_t pdu_thread_id;
static pid_t monitor_pid = -1;
static void set_monitor_pid(pid_t pid) {
    monitor_pid = pid;
}

// 添加全局变量存储完整的zte_mifi和zte_ufi路径
static char zte_mifi_path[256] = "/sbin/zte_mifi";
static char zte_ufi_path[256] = "/sbin/zte_ufi";
// 添加strace路径变量
static char strace_bin_path[256] = "/sbin/strace";

// 添加用于动态调整重启间隔的变量
static time_t last_sms_detected_time = 0;       // 上次检测到短信的时间
static const int BASE_RESTART_INTERVAL = 30;    // 基础重启间隔(秒)
static const int MAX_RESTART_INTERVAL = 60;     // 最大重启间隔(秒)
static const int INTERVAL_EXTENSION = 5;        // 每次检测到短信时的延长时间(秒)

// 过滤乱码字符的函数 - 按GB2312字符集范围过滤，保留所有GB2312支持的字符包括标点符号
void filter_garbage_chars(char *text) {
    if (!text) return;
    
    size_t len = strlen(text);
    if (len == 0) return;
    
    // 过滤乱码字符序列"Ԁϵ̃"
    char *garbage_seq = "Ԁϵ̃";
    char *pos = strstr(text, garbage_seq);
    if (pos) {
        size_t seq_len = strlen(garbage_seq);
        size_t after_seq = (pos - text) + seq_len;
        memmove(pos, text + after_seq, len - after_seq + 1);
    }
    
    // 过滤单个乱码字符
    // "Ԁ" (U+0500) UTF-8: 0xD4 0x80
    // "ϵ" (U+03F5) UTF-8: 0xCF 0xB5
    // "̃" (U+0303) UTF-8: 0xCC 0x83 (组合字符)
    // "΅" (U+0385) UTF-8: 0xCD 0x85
    // "ȁ" (U+0101) UTF-8: 0xC4 0x81
    
    int i, j;
    for (i = 0, j = 0; text[i] != '\0'; ) {
        unsigned char c = (unsigned char)text[i];
        
        // 检查是否是已知的乱码字符UTF-8序列
        if (c == 0xD4 && (unsigned char)text[i+1] == 0x80) { // Ԁ
            i += 2; // 跳过该字符
            continue;
        } else if (c == 0xCF && (unsigned char)text[i+1] == 0xB5) { // ϵ
            i += 2; // 跳过该字符
            continue;
        } else if (c == 0xCC && (unsigned char)text[i+1] == 0x83) { // ̃
            i += 2; // 跳过该字符
            continue;
        } else if (c == 0xCD && (unsigned char)text[i+1] == 0x85) { // ΅
            i += 2; // 跳过该字符
            continue;
        } else if (c == 0xC4 && (unsigned char)text[i+1] == 0x81) { // ȁ
            i += 2; // 跳过该字符
            continue;
        }
        
        // 检查ASCII字符 (0x00-0x7F) - 完全保留
        if (c < 0x80) {
            // 保留所有ASCII字符（包括控制字符、数字、字母、标点符号等）
            text[j++] = c;
            i++;
        } 
        // 检查UTF-8 2字节字符
        else if ((c & 0xE0) == 0xC0) {
            // 2字节UTF-8字符
            if ((i + 1 < len) && ((text[i+1] & 0xC0) == 0x80)) {
                unsigned char c2 = text[i+1];
                
                // 检查是否在GB2312支持的字符范围内
                // GB2312 2字节字符范围:
                // 1. CJK符号和标点: U+3000-U+303F (0xE3 0x80 0x80 - 0xE3 0x80 0xBF)
                // 2. 全角ASCII、全角片假平假名: U+FF00-U+FFEF (0xEF 0xBC 0x80 - 0xEF 0xBF 0xAF)
                // 3. 半宽片假名: U+FF61-U+FF9F (0xEF 0xBD 0xA1 - 0xEF 0xBE 0x9F)
                int is_valid_gb2312 = 0;
                
                // CJK符号和标点范围 (包括【】《》""''等中文标点)
                if (c == 0xE3 && c2 >= 0x80 && c2 <= 0xBF) {
                    is_valid_gb2312 = 1;
                }
                // 全角字符范围 (包括中文标点符号)
                else if (c == 0xEF) {
                    if ((c2 >= 0xBC && c2 <= 0xBF) ||  // 全角ASCII等
                        (c2 >= 0xBD && c2 <= 0xBE)) {  // 半宽片假名等
                        is_valid_gb2312 = 1;
                    }
                }
                
                if (is_valid_gb2312) {
                    // 保留有效的2字节字符
                    text[j++] = text[i++];
                    text[j++] = text[i++];
                } else {
                    // 跳过不符合GB2312范围的2字节字符（如希腊文等）
                    i += 2;
                }
            } else {
                i++; // 跳过无效序列
            }
        } else if ((c & 0xF0) == 0xE0) {
            // 3字节UTF-8字符（主要是中文等）
            if ((i + 2 < len) && ((text[i+1] & 0xC0) == 0x80) && ((text[i+2] & 0xC0) == 0x80)) {
                unsigned char c2 = text[i+1];
                unsigned char c3 = text[i+2];
                
                // 检查是否在GB2312支持的中文字符范围内
                // GB2312中文字符范围:
                // 一级汉字: U+4E00 to U+9FFF 
                // 二级汉字: U+3400 to U+4DFF
                // 其他兼容字符
                int is_valid_gb2312 = 0;
                
                // 一级汉字区 (常用汉字)
                if ((c == 0xE4 && c2 >= 0xB8 && c2 <= 0xBF) ||
                    (c == 0xE5 && c2 >= 0x80 && c2 <= 0xBF) ||
                    (c == 0xE6 && c2 >= 0x80 && c2 <= 0xBF) ||
                    (c == 0xE7 && c2 >= 0x80 && c2 <= 0xBF) ||
                    (c == 0xE8 && c2 >= 0x80 && c2 <= 0xBF) ||
                    (c == 0xE9 && c2 >= 0x80 && c2 <= 0xBF)) {
                    is_valid_gb2312 = 1;
                }
                // 二级汉字区和其他兼容汉字
                else if ((c == 0xE3 && c2 >= 0x90 && c2 <= 0x9F) ||
                         (c == 0xE4 && c2 >= 0x90 && c2 <= 0xB7)) {
                    is_valid_gb2312 = 1;
                }
                
                if (is_valid_gb2312) {
                    // 保留有效的中文字符
                    text[j++] = text[i++];
                    text[j++] = text[i++];
                    text[j++] = text[i++];
                } else {
                    // 跳过不符合GB2312范围的字符（如希腊文、阿拉伯文等）
                    i += 3;
                }
            } else {
                i++; // 跳过无效序列
            }
        } else if ((c & 0xF8) == 0xF0) {
            // 4字节UTF-8字符（CJK扩展B区等）
            // GB2312不包含4字节字符，直接跳过
            if ((i + 3 < len) && ((text[i+1] & 0xC0) == 0x80) && 
                ((text[i+2] & 0xC0) == 0x80) && ((text[i+3] & 0xC0) == 0x80)) {
                // 跳过4字节字符
                i += 4;
            } else {
                i++; // 跳过无效序列
            }
        } else {
            i++; // 跳过其他无效字节
        }
    }
    text[j] = '\0';
}

// 获取SIM卡号函数
char* get_sim_number_from_nv(void) {
    // 使用popen直接读取nv show命令的输出，避免创建临时文件
    FILE *fp = popen("nv show 2>/dev/null", "r");
    if (!fp) {
        return NULL;
    }
    
    char line[512];
    regex_t regex;
    regmatch_t matches[2];
    char *sim_number = NULL;
    
    // 编译正则表达式匹配msisdn=+86xxxxxxxxxx格式
    if (regcomp(&regex, "msisdn=\\+([0-9]+)", REG_EXTENDED) != 0) {
        pclose(fp);
        return NULL;
    }
    
    // 逐行读取命令输出查找匹配项
    while (fgets(line, sizeof(line), fp)) {
        if (regexec(&regex, line, 2, matches, 0) == 0) {
            int len = matches[1].rm_eo - matches[1].rm_so;
            sim_number = (char*)malloc(len + 1);
            if (sim_number) {
                strncpy(sim_number, line + matches[1].rm_so, len);
                sim_number[len] = '\0';
                break;
            }
        }
    }
    
    // 清理资源
    regfree(&regex);
    pclose(fp);
    
    return sim_number;
}

// 初始化SIM卡号
void init_sim_number(void) {
    if (sim_number_initialized) return;
    
    char* sim_number = get_sim_number_from_nv();
    if (sim_number) {
        if (strlen(sim_number) >= 11 && strlen(sim_number) <= 15) {
            strncpy(global_sim_number, sim_number, sizeof(global_sim_number) - 1);
        }
        free(sim_number);
    }
    sim_number_initialized = 1;
}

// PID文件操作函数实现
static pid_t get_strace_pid_from_file(void) {
    FILE *fp = fopen("/tmp/strace_pid.txt", "r");
    if (!fp) return -1;
    pid_t pid;
    if (fscanf(fp, "%d", &pid) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return pid;
}

static void set_strace_pid_to_file(pid_t pid) {
    FILE *fp = fopen("/tmp/strace_pid.txt", "w");
    if (!fp) return;
    fprintf(fp, "%d", pid);
    fclose(fp);
}

// 查找指定路径的zte_mifi或zte_ufi进程 pid，返回第一个找到的 pid，找不到返回 -1
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
            // 检查是否匹配指定的完整路径
            if (strcmp(buf, zte_mifi_path) == 0 || strcmp(buf, zte_ufi_path) == 0) {
                pid = id;
                break;
            }
        }
    }
    closedir(dir);
    return pid;
}

// 添加长短信到跟踪器
void add_long_sms_to_tracker(const char *sender, const char *timestamp) {
    // 检查是否已存在
    int i;
    for (i = 0; i < long_sms_tracker_count; i++) {
        if (strcmp(long_sms_tracker[i].sender, sender) == 0 &&
            strcmp(long_sms_tracker[i].timestamp, timestamp) == 0) {
            // 更新时间
            long_sms_tracker[i].first_seen = time(NULL);
            return; // 已存在，不需要重复添加
        }
    }
    
    // 添加新的长短信跟踪项
    if (long_sms_tracker_count < LONG_SMS_TRACKER_SIZE) {
        strncpy(long_sms_tracker[long_sms_tracker_count].sender, sender, sizeof(long_sms_tracker[0].sender) - 1);
        long_sms_tracker[long_sms_tracker_count].sender[sizeof(long_sms_tracker[0].sender) - 1] = '\0';
        
        strncpy(long_sms_tracker[long_sms_tracker_count].timestamp, timestamp, sizeof(long_sms_tracker[0].timestamp) - 1);
        long_sms_tracker[long_sms_tracker_count].timestamp[sizeof(long_sms_tracker[0].timestamp) - 1] = '\0';
        
        long_sms_tracker[long_sms_tracker_count].first_seen = time(NULL);
        long_sms_tracker_count++;
    }
}

// 检查是否是已知长短信的片段
int is_known_long_sms(const char *sender, const char *timestamp) {
    int i;
    for (i = 0; i < long_sms_tracker_count; i++) {
        // 检查发件人和时间戳是否匹配
        if (strcmp(long_sms_tracker[i].sender, sender) == 0 &&
            strcmp(long_sms_tracker[i].timestamp, timestamp) == 0) {
            // 检查是否过期（1分钟内认为是同一短信）
            if (time(NULL) - long_sms_tracker[i].first_seen < 60) {
                return 1; // 是已知长短信
            } else {
                // 过期了，移除该项
                int j;  
                for (j = i; j < long_sms_tracker_count - 1; j++) {
                    long_sms_tracker[j] = long_sms_tracker[j + 1];
                }
                long_sms_tracker_count--;
            }
        }
    }
    return 0; // 不是已知长短信
}

// 清理过期的长短信跟踪项
void cleanup_long_sms_tracker() {
    time_t now = time(NULL);
    int i = 0;
    while (i < long_sms_tracker_count) {
        if (now - long_sms_tracker[i].first_seen > 60) { // 60秒过期
            // 移动后续项向前
            int j;
            for (j = i; j < long_sms_tracker_count - 1; j++) {
                long_sms_tracker[j] = long_sms_tracker[j + 1];
            }
            long_sms_tracker_count--;
        } else {
            i++;
        }
    }
}

// 修改strace_thread_func函数，添加更精确的重启前短信接收检查
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
        // 修改为跟踪write系统调用
        execl(strace_bin_path, "strace", "-f", "-e", "trace=write", "-s", "1024", "-p", pidstr, "-o", "/tmp/zte_log.txt", (char*)NULL);
        _exit(127);
    } else if (child > 0) {
        set_strace_pid_to_file(child);
        // 后台定时任务
        if (fork() == 0) {
            const long MAX_LOG_SIZE = 1 * 512 * 1024; // 0.5MB
            int check_count = 0;
            time_t last_restart_time = time(NULL);
            
            while (threads_running) {
                check_count++;
                time_t current_time = time(NULL);
                
                // 计算当前应该使用的重启间隔
                int current_restart_interval = BASE_RESTART_INTERVAL;
                
                // 检查是否在最近检测到短信
                if (last_sms_detected_time > 0) {
                    // 计算从上次检测到短信以来的时间
                    time_t time_since_last_sms = current_time - last_sms_detected_time;
                    
                    // 如果在基础间隔内检测到短信，则延长重启间隔
                    if (time_since_last_sms < BASE_RESTART_INTERVAL) {
                        // 根据距离上次短信的时间计算新的间隔
                        current_restart_interval = BASE_RESTART_INTERVAL + 
                            (BASE_RESTART_INTERVAL - time_since_last_sms) + INTERVAL_EXTENSION;
                        
                        // 确保不超过最大间隔
                        if (current_restart_interval > MAX_RESTART_INTERVAL) {
                            current_restart_interval = MAX_RESTART_INTERVAL;
                        }
                    }
                }
                
                // 检查是否需要重启strace进程
                if ((current_time - last_restart_time) >= current_restart_interval) {
                    // 在重启前检查是否正在接收匹配write(1, ...)格式的短信
                    int should_delay_restart = 0;
                    
                    // 检查/tmp/zte_log.txt中是否存在匹配write(1, ...)格式的短信
                    FILE *fp = fopen("/tmp/zte_log.txt", "r");
                    if (fp) {
                        char line[4096];
                        regex_t reg;
                        regcomp(&reg, "^[ \t]*(\\[pid [0-9]+\\] )?write\\(1, \"(\\\\\\\\n)?\\\\r\\\\n\\+CMT:.*\", [0-9]+", REG_EXTENDED);
                        
                        while (fgets(line, sizeof(line), fp)) {
                            if (regexec(&reg, line, 0, NULL, 0) == 0) {
                                should_delay_restart = 1;
                                printf("[DEBUG] Found write(1, ...) SMS pattern, will delay strace restart\n");
                                break;
                            }
                        }
                        regfree(&reg);
                        fclose(fp);
                    }
                    
                    if (should_delay_restart) {
                        // 如果检测到匹配的短信，延迟5秒再检查
                        printf("检测到正在接收匹配的短信(write(1, ...))，延迟5秒重启strace进程...\n");
                        sleep(5);
                        
                        // 再次检查是否仍在接收短信
                        int still_receiving = 0;
                        fp = fopen("/tmp/zte_log.txt", "r");
                        if (fp) {
                            char line[4096];
                            regex_t reg;
                            regcomp(&reg, "^[ \t]*(\\[pid [0-9]+\\] )?write\\(1, \"(\\\\\\\\n)?\\\\r\\\\n\\+CMT:.*\", [0-9]+", REG_EXTENDED);
                            
                            while (fgets(line, sizeof(line), fp)) {
                                if (regexec(&reg, line, 0, NULL, 0) == 0) {
                                    still_receiving = 1;
                                    break;
                                }
                            }
                            regfree(&reg);
                            fclose(fp);
                        }
                        
                        if (still_receiving) {
                            printf("仍在接收匹配的短信，再延迟5秒重启strace进程...\n");
                            sleep(5);
                        }
                    }
                    
                    // 最终检查并重启strace进程
                    printf("重启strace进程，当前间隔: %d秒...\n", current_restart_interval);
                    // 重启strace
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
                    // 使用truncate强制清空文件（0字节填充）
                    if (truncate("/tmp/zte_log.txt", 0) != 0) {
                        perror("truncate /tmp/zte_log.txt");
                    }
                    int newpid = find_zte_mifi_pid();
                    if (newpid > 0) {
                        pid_t c2 = fork();
                        if (c2 == 0) {
                            char pidstr2[16];
                            snprintf(pidstr2, sizeof(pidstr2), "%d", newpid);
                            // 修改为跟踪write系统调用
                            execl(strace_bin_path, "strace", "-f", "-e", "trace=write", "-s", "1024", "-p", pidstr2, "-o", "/tmp/zte_log.txt", (char*)NULL);
                            _exit(127);
                        } else if (c2 > 0) {
                            set_strace_pid_to_file(c2);
                        }
                    }
                    last_restart_time = current_time;
                }
                
                // 检查日志文件大小（仍然保留此检查作为额外保护）
                struct stat st;
                if (stat("/tmp/zte_log.txt", &st) == 0 && st.st_size > MAX_LOG_SIZE) {
                    // 文件过大，清空文件而不是重启strace
                    printf("日志文件过大(%ld bytes)，清空文件\n", st.st_size);
                    // 使用truncate强制清空文件
                    if (truncate("/tmp/zte_log.txt", 0) != 0) {
                        perror("truncate /tmp/zte_log.txt");
                    }
                }
                
                // 等待1秒或者主线程退出
                int sec_to_wait = 1;
                int slept = 0;
                while (slept < sec_to_wait && threads_running) {
                    int to_sleep = (sec_to_wait - slept) > 10 ? 10 : (sec_to_wait - slept);
                    sleep(to_sleep);
                    slept += to_sleep;
                }
                
                // 如果主线程已退出，则退出循环
                if (!threads_running) break;
            }
            _exit(0);
        }
        // 添加短暂延迟，避免忙等待
        usleep(100000); // 0.1秒
        waitpid(child, NULL, 0);
    } else {
        perror("fork");
    }
    return NULL;
}

// 修改pdu_thread_func函数，只在匹配write(1, ...)格式时更新短信接收状态
void* pdu_thread_func(void* arg) {
    char** args = (char**)arg;
    char* webhook = args[0];
    char* headtxt = args[1];
    char* tailtxt = args[2];
    char* keyword = args[3];
    char* number = args[4]; 

    // 添加线程清理处理程序
    pthread_cleanup_push(free, webhook);
    pthread_cleanup_push(free, headtxt);
    pthread_cleanup_push(free, tailtxt);
    pthread_cleanup_push(free, keyword);
    pthread_cleanup_push(free, number); 
    pthread_cleanup_push(free, args);

    time_t last_size = 0;
    time_t last_check_time = time(NULL);
    while (threads_running) {
        FILE *fp = fopen("/tmp/zte_log.txt", "r");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long size = ftell(fp);
            fclose(fp);
            if (size != last_size) {
                last_size = size;
                
                // 只有在实际处理匹配的短信时才更新接收状态
                // 先检查是否存在匹配write(1, ...)格式的短信
                int has_sms_content = 0;
                fp = fopen("/tmp/zte_log.txt", "r");
                if (fp) {
                    char line[4096];
                    regex_t reg;
                    regcomp(&reg, "^[ \t]*(\\[pid [0-9]+\\] )?write\\(1, \"(\\\\\\\\n)?\\\\r\\\\n\\+CMT:.*\", [0-9]+", REG_EXTENDED);
                    
                    while (fgets(line, sizeof(line), fp)) {
                        if (regexec(&reg, line, 0, NULL, 0) == 0) {
                            has_sms_content = 1;
                            break;
                        }
                    }
                    regfree(&reg);
                    fclose(fp);
                }
                
                if (has_sms_content) {
                    // 标记正在接收短信
                    sms_receiving = 1;
                    last_sms_activity = time(NULL);
                    printf("[DEBUG] SMS receiving detected, updating activity timestamp\n");
                }
                
                extract_and_send_sms_from_log(webhook, headtxt, tailtxt, keyword, number);
                // 当检测到日志文件变化时，更新最后检测到短信的时间
                last_sms_detected_time = time(NULL);
            }
        }
        
        // 每5秒检查一次临时存储中的短信
        time_t current_time = time(NULL);
        if (current_time - last_check_time >= 5) {
            printf("[DEBUG] 5-second check cycle triggered\n");
            
            // 检查是否存在匹配write(1, ...)格式的短信
            int has_sms_content = 0;
            fp = fopen("/tmp/zte_log.txt", "r");
            if (fp) {
                char line[4096];
                regex_t reg;
                regcomp(&reg, "^[ \t]*(\\[pid [0-9]+\\] )?write\\(1, \"(\\\\\\\\n)?\\\\r\\\\n\\+CMT:.*\", [0-9]+", REG_EXTENDED);
                
                while (fgets(line, sizeof(line), fp)) {
                    if (regexec(&reg, line, 0, NULL, 0) == 0) {
                        has_sms_content = 1;
                        break;
                    }
                }
                regfree(&reg);
                fclose(fp);
            }
            
            if (has_sms_content) {
                // 标记正在处理短信
                sms_receiving = 1;
                last_sms_activity = time(NULL);
                printf("[DEBUG] SMS content detected in 5-second check, updating activity timestamp\n");
            }
            
            extract_and_send_sms_from_log(webhook, headtxt, tailtxt, keyword, number);
            last_check_time = current_time;
            // 当触发5秒检查时，也更新最后检测到短信的时间
            last_sms_detected_time = time(NULL);
        }
        
        // 如果超过2秒没有活动，标记为非接收状态
        if (time(NULL) - last_sms_activity > 2) {
            sms_receiving = 0;
        }
        
        usleep(1000*1000); // 1秒轮询
    }
    
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);

    return NULL;
}



// 修改 extract_write_lines_from_log 函数，只匹配特定格式的短信信息
void extract_write_lines_from_log() {
    FILE *fp = fopen("/tmp/zte_log.txt", "r");
    if (!fp) {
        perror("fopen /tmp/zte_log.txt");
        return;
    }
    char line[2048];
    // 修改匹配 write(1, ...) 格式的正则表达式
    regex_t reg;
    // 只匹配write(1, ...)格式的短信信息
    regcomp(&reg, "^\\s*(\\[pid [0-9]+\\] )?write\\(1, \\\".*\\+CMT:.*\\\", [0-9]+\\)", REG_EXTENDED);
    while (fgets(line, sizeof(line), fp)) {
        if (regexec(&reg, line, 0, NULL, 0) == 0) {
            printf("%s", line);
        }
    }
    regfree(&reg);
    fclose(fp);
}

// PDU解码信息结构体和解码函数

// 修改1: 增大text缓冲区以支持更长的短信内容
typedef struct {
    char smsc[64];
    char sender[64];
    char timestamp[64];
    char tp_pid[8];
    char tp_dcs[8];
    char tp_dcs_desc[64];
    char sms_class[16];
    char alphabet[64];
    char text[8192]; // 从4096增加到8192，确保能容纳更长的短信内容
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

// 检查是否在连续检测窗口中
int is_sms_in_detection_window(const char *sender, const char *timestamp, const char *text) {
    int i;
    for (i = 0; i < detection_count; i++) {
        int idx = (detection_head + i) % DETECTION_WINDOW_SIZE;
        if (strcmp(detection_window[idx].sender, sender) == 0 &&
            strcmp(detection_window[idx].timestamp, timestamp) == 0 &&
            strcmp(detection_window[idx].text, text) == 0) {
            return idx; // 返回索引
        }
    }
    return -1; // 未找到
}

// 添加到连续检测窗口
void add_sms_to_detection_window(const char *sender, const char *timestamp, const char *text) {
    int idx = is_sms_in_detection_window(sender, timestamp, text);
    
    // 如果已存在，增加计数
    if (idx != -1) {
        detection_window[idx].count++;
        detection_window[idx].last_seen = time(NULL);
        return;
    }
    
    // 添加新条目
    int new_idx;
    if (detection_count < DETECTION_WINDOW_SIZE) {
        new_idx = (detection_head + detection_count) % DETECTION_WINDOW_SIZE;
        detection_count++;
    } else {
        new_idx = detection_head;
        detection_head = (detection_head + 1) % DETECTION_WINDOW_SIZE;
    }
    
    strncpy(detection_window[new_idx].sender, sender, sizeof(detection_window[new_idx].sender)-1);
    detection_window[new_idx].sender[sizeof(detection_window[new_idx].sender)-1] = 0;
    
    strncpy(detection_window[new_idx].timestamp, timestamp, sizeof(detection_window[new_idx].timestamp)-1);
    detection_window[new_idx].timestamp[sizeof(detection_window[new_idx].timestamp)-1] = 0;
    
    strncpy(detection_window[new_idx].text, text, sizeof(detection_window[new_idx].text)-1);
    detection_window[new_idx].text[sizeof(detection_window[new_idx].text)-1] = 0;
    
    detection_window[new_idx].count = 1;
    detection_window[new_idx].last_seen = time(NULL);
}

// 清理过期的检测条目（超过30秒的条目）
void cleanup_detection_window() {
    time_t now = time(NULL);
    int i = 0;
    while (i < detection_count) {
        int idx = (detection_head + i) % DETECTION_WINDOW_SIZE;
        if (now - detection_window[idx].last_seen > 30) {
            // 移除这个条目
            if (idx == detection_head) {
                detection_head = (detection_head + 1) % DETECTION_WINDOW_SIZE;
                detection_count--;
            } else {
                // 简单处理：只清理头部过期条目
                break;
            }
        } else {
            i++;
        }
    }
}

// 检查PDU片段队列中是否存在匹配的完整PDU
int is_pdu_fragment_in_queue(const char *sender, const char *timestamp, const char *pdu_fragment) {
    int i;
    for (i = 0; i < pdu_fragment_count; i++) {
        int idx = (pdu_fragment_head + i) % PDU_FRAGMENT_QUEUE_SIZE;
        if (strcmp(pdu_fragment_queue[idx].sender, sender) == 0 &&
            strcmp(pdu_fragment_queue[idx].timestamp, timestamp) == 0 &&
            strstr(pdu_fragment_queue[idx].pdu_fragment, pdu_fragment) != NULL) {
            return 1; // 找到匹配的完整PDU
        }
    }
    return 0; // 未找到
}

// 添加PDU片段到队列
void add_pdu_fragment_to_queue(const char *sender, const char *timestamp, const char *pdu_fragment) {
    // 检查是否已存在相同的片段
    int i;
    for (i = 0; i < pdu_fragment_count; i++) {
        int idx = (pdu_fragment_head + i) % PDU_FRAGMENT_QUEUE_SIZE;
        if (strcmp(pdu_fragment_queue[idx].sender, sender) == 0 &&
            strcmp(pdu_fragment_queue[idx].timestamp, timestamp) == 0 &&
            strcmp(pdu_fragment_queue[idx].pdu_fragment, pdu_fragment) == 0) {
            return; // 已存在，不重复添加
        }
    }
    
    // 添加新片段
    int idx;
    if (pdu_fragment_count < PDU_FRAGMENT_QUEUE_SIZE) {
        idx = (pdu_fragment_head + pdu_fragment_count) % PDU_FRAGMENT_QUEUE_SIZE;
        pdu_fragment_count++;
    } else {
        idx = pdu_fragment_head;
        pdu_fragment_head = (pdu_fragment_head + 1) % PDU_FRAGMENT_QUEUE_SIZE;
    }
    
    strncpy(pdu_fragment_queue[idx].sender, sender, sizeof(pdu_fragment_queue[idx].sender)-1);
    pdu_fragment_queue[idx].sender[sizeof(pdu_fragment_queue[idx].sender)-1] = 0;
    
    strncpy(pdu_fragment_queue[idx].timestamp, timestamp, sizeof(pdu_fragment_queue[idx].timestamp)-1);
    pdu_fragment_queue[idx].timestamp[sizeof(pdu_fragment_queue[idx].timestamp)-1] = 0;
    
    strncpy(pdu_fragment_queue[idx].pdu_fragment, pdu_fragment, sizeof(pdu_fragment_queue[idx].pdu_fragment)-1);
    pdu_fragment_queue[idx].pdu_fragment[sizeof(pdu_fragment_queue[idx].pdu_fragment)-1] = 0;
    
    pdu_fragment_queue[idx].received_time = time(NULL);
}

// 清理过期的PDU片段（超过3秒的片段）
void cleanup_pdu_fragment_queue() {
    time_t now = time(NULL);
    int i = 0;
    while (i < pdu_fragment_count) {
        int idx = (pdu_fragment_head + i) % PDU_FRAGMENT_QUEUE_SIZE;
        if (now - pdu_fragment_queue[idx].received_time > 3) {
            // 移除这个条目
            if (idx == pdu_fragment_head) {
                pdu_fragment_head = (pdu_fragment_head + 1) % PDU_FRAGMENT_QUEUE_SIZE;
                pdu_fragment_count--;
            } else {
                // 简单处理：只清理头部过期条目
                break;
            }
        } else {
            i++;
        }
    }
}

// 从PDU中提取长短信信息，严格按照GSM 03.38协议
int extract_long_sms_info(const char *pdu, unsigned char *ref, unsigned char *max, unsigned char *seq) {
    int idx = 0;
    int pdu_len = strlen(pdu);
    
    if (pdu_len < 10) return 0;
    
    // 跳过SMSC信息
    int smsc_len = 0;
    sscanf(pdu, "%2x", &smsc_len);
    idx += 2 + smsc_len * 2;
    
    if (idx + 12 >= pdu_len) return 0;
    
    // 跳过PDU类型和地址信息
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
    idx += sender_bcd_len;
    
    // TP-PID和TP-DCS
    idx += 4;
    
    // 时间戳
    idx += 14;
    
    // 用户数据长度
    if (idx + 2 >= pdu_len) return 0;
    int text_len_oct = 0;
    sscanf(pdu + idx, "%2x", &text_len_oct);
    idx += 2;
    
    // 检查是否有头部信息
    if (idx + 2 >= pdu_len) return 0;
    int udh_len = 0;
    sscanf(pdu + idx, "%2x", &udh_len);
    
    // 检查是否为长短信 (UDH长度至少为6字节)
    // 根据GSM 03.38协议，长短信UDH包含:
    // - UDH长度字段 (1字节)
    // - 信息元素标识符 IEI (1字节，0x00表示连接短信)
    // - 信息元素长度 IEL (1字节，固定为0x03)
    // - 信息参考号 (1字节)
    // - 总片段数 (1字节)
    // - 当前片段序号 (1字节)
    if (udh_len >= 6) {
        int udh_idx = idx + 2;
        while (udh_idx + 6 <= pdu_len && udh_idx < idx + 2 + udh_len * 2) {
            int ie_id = 0, ie_len = 0;
            sscanf(pdu + udh_idx, "%2x", &ie_id);
            udh_idx += 2;
            if (udh_idx >= pdu_len) break;
            sscanf(pdu + udh_idx, "%2x", &ie_len);
            udh_idx += 2;
            
            // 检查是否为连接短信的IEI (0x00) 且长度为0x03
            if (ie_id == 0x00 && ie_len == 0x03) {
                if (udh_idx + 6 <= pdu_len) {
                    sscanf(pdu + udh_idx, "%2hhx", ref);
                    sscanf(pdu + udh_idx + 2, "%2hhx", max);
                    sscanf(pdu + udh_idx + 4, "%2hhx", seq);
                    return 1; // 成功提取长短信信息
                }
            }
            udh_idx += ie_len * 2;
        }
    }
    
    return 0; // 不是长短信
}

// 添加长短信片段到队列，确保按正确顺序存储
void add_long_sms_fragment(const char *sender, const char *timestamp, 
                          unsigned char ref, unsigned char max, unsigned char seq, 
                          const char *text, const char *pdu) {
    // 验证参数有效性
    if (max == 0 || seq == 0 || seq > max) {
        printf("[DEBUG] Invalid long SMS fragment parameters: ref=%d, max=%d, seq=%d\n", ref, max, seq);
        return;
    }
    
    // 检查是否已存在相同的片段（相同发件人、时间戳、参考号、序号）
    int i;
    for (i = 0; i < long_sms_fragment_count; i++) {
        int idx = (long_sms_fragment_head + i) % LONG_SMS_FRAGMENT_QUEUE_SIZE;
        if (strcmp(long_sms_fragment_queue[idx].sender, sender) == 0 &&
            strcmp(long_sms_fragment_queue[idx].timestamp, timestamp) == 0 &&
            long_sms_fragment_queue[idx].ref == ref &&
            long_sms_fragment_queue[idx].seq == seq) {
            // 已存在相同片段，不重复添加
            printf("[DEBUG] Duplicate long SMS fragment ignored: ref=%d, seq=%d/%d\n", ref, seq, max);
            return;
        }
    }
    
    // 添加新片段到队列末尾（保持接收顺序）
    int queue_idx;
    if (long_sms_fragment_count < LONG_SMS_FRAGMENT_QUEUE_SIZE) {
        queue_idx = (long_sms_fragment_head + long_sms_fragment_count) % LONG_SMS_FRAGMENT_QUEUE_SIZE;
        long_sms_fragment_count++;
    } else {
        // 队列已满，移除最旧的片段（队列头部）
        queue_idx = long_sms_fragment_head;
        long_sms_fragment_head = (long_sms_fragment_head + 1) % LONG_SMS_FRAGMENT_QUEUE_SIZE;
    }
    
    strncpy(long_sms_fragment_queue[queue_idx].sender, sender, sizeof(long_sms_fragment_queue[0].sender)-1);
    long_sms_fragment_queue[queue_idx].sender[sizeof(long_sms_fragment_queue[0].sender)-1] = 0;
    
    strncpy(long_sms_fragment_queue[queue_idx].timestamp, timestamp, sizeof(long_sms_fragment_queue[0].timestamp)-1);
    long_sms_fragment_queue[queue_idx].timestamp[sizeof(long_sms_fragment_queue[0].timestamp)-1] = 0;
    
    long_sms_fragment_queue[queue_idx].ref = ref;
    long_sms_fragment_queue[queue_idx].max = max;
    long_sms_fragment_queue[queue_idx].seq = seq;
    
    strncpy(long_sms_fragment_queue[queue_idx].text, text, sizeof(long_sms_fragment_queue[0].text)-1);
    long_sms_fragment_queue[queue_idx].text[sizeof(long_sms_fragment_queue[0].text)-1] = 0;
    
    strncpy(long_sms_fragment_queue[queue_idx].pdu, pdu, sizeof(long_sms_fragment_queue[0].pdu)-1);
    long_sms_fragment_queue[queue_idx].pdu[sizeof(long_sms_fragment_queue[0].pdu)-1] = 0;
    
    long_sms_fragment_queue[queue_idx].received_time = time(NULL);
    
    printf("[DEBUG] Added long SMS fragment: ref=%d, seq=%d/%d\n", ref, seq, max);
}

// 检查是否可以重组长短信
int can_reassemble_long_sms(const char *sender, const char *timestamp, unsigned char ref, unsigned char max) {
    int count = 0;
    int i;
    for (i = 0; i < long_sms_fragment_count; i++) {
        int idx = (long_sms_fragment_head + i) % LONG_SMS_FRAGMENT_QUEUE_SIZE;
        if (strcmp(long_sms_fragment_queue[idx].sender, sender) == 0 &&
            strcmp(long_sms_fragment_queue[idx].timestamp, timestamp) == 0 &&
            long_sms_fragment_queue[idx].ref == ref &&
            long_sms_fragment_queue[idx].max == max) {
            count++;
        }
    }
    return (count == max); // 所有片段都已收到
}

// 重组长短信，按照接收顺序的逆序进行拼接（最先接收到的片段放在最后）
int reassemble_long_sms(const char *sender, const char *timestamp, unsigned char ref, unsigned char max, char *output, size_t output_size, char *combined_pdu, size_t pdu_size) {
    // 验证参数
    if (max == 0 || max > 255) {
        printf("[DEBUG] Invalid max fragments count: %d\n", max);
        return 0;
    }
    
    // 创建数组存储找到的片段索引，按队列中的存储顺序保存
    int fragment_indices[LONG_SMS_FRAGMENT_QUEUE_SIZE];
    int fragment_count = 0;
    int i;
    
    // 收集所有属于当前长短信的片段，按队列中的存储顺序保存索引
    for (i = 0; i < long_sms_fragment_count; i++) {
        int idx = (long_sms_fragment_head + i) % LONG_SMS_FRAGMENT_QUEUE_SIZE;
        if (strcmp(long_sms_fragment_queue[idx].sender, sender) == 0 &&
            strcmp(long_sms_fragment_queue[idx].timestamp, timestamp) == 0 &&
            long_sms_fragment_queue[idx].ref == ref) {
            
            // 验证序号有效性
            unsigned char seq = long_sms_fragment_queue[idx].seq;
            if (seq >= 1 && seq <= max) {
                fragment_indices[fragment_count] = idx;
                fragment_count++;
            } else {
                printf("[DEBUG] Invalid fragment sequence number: %d (max: %d)\n", seq, max);
            }
        }
    }
    
    // 检查是否所有片段都存在
    if (fragment_count != max) {
        printf("[DEBUG] Fragment count mismatch: found %d, expected %d\n", fragment_count, max);
        return 0; // 片段数量不匹配
    }
    
    // 重组文本，按队列存储顺序的逆序进行拼接（最先存储的片段放在最后）
    output[0] = '\0';
    size_t current_len = 0;
    
    // 从最后存储的片段开始向前拼接（逆序处理）
    for (i = fragment_count - 1; i >= 0; i--) {
        int idx = fragment_indices[i];
        size_t fragment_len = strlen(long_sms_fragment_queue[idx].text);
        if (current_len + fragment_len < output_size - 1) {
            strcat(output, long_sms_fragment_queue[idx].text);
            current_len += fragment_len;
        } else {
            printf("[WARN] Output buffer too small for reassembled SMS\n");
            break; // 输出缓冲区不足
        }
    }
    
    // 过滤乱码字符
    filter_garbage_chars(output);
    
    // 组合所有PDU片段，也按队列存储顺序的逆序
    combined_pdu[0] = '\0';
    size_t pdu_len = 0;
    for (i = fragment_count - 1; i >= 0; i--) {
        int idx = fragment_indices[i];
        size_t pdu_fragment_len = strlen(long_sms_fragment_queue[idx].pdu);
        if (pdu_len + pdu_fragment_len < pdu_size - 1) {
            strcat(combined_pdu, long_sms_fragment_queue[idx].pdu);
            pdu_len += pdu_fragment_len;
        } else {
            printf("[WARN] PDU buffer too small for combined PDU\n");
            break;
        }
    }
    
    printf("[DEBUG] Successfully reassembled long SMS with %d fragments in reverse queue order\n", max);
    return 1; // 重组成功
}

// 清理已成功重组的长短信片段
void cleanup_processed_long_sms_fragments(const char *sender, const char *timestamp, unsigned char ref, unsigned char max) {
    int i = 0;
    while (i < long_sms_fragment_count) {
        int idx = (long_sms_fragment_head + i) % LONG_SMS_FRAGMENT_QUEUE_SIZE;
        if (strcmp(long_sms_fragment_queue[idx].sender, sender) == 0 &&
            strcmp(long_sms_fragment_queue[idx].timestamp, timestamp) == 0 &&
            long_sms_fragment_queue[idx].ref == ref) {
            // 移除这个片段
            if (idx == long_sms_fragment_head) {
                long_sms_fragment_head = (long_sms_fragment_head + 1) % LONG_SMS_FRAGMENT_QUEUE_SIZE;
                long_sms_fragment_count--;
            } else {
                // 移动后续项向前
                int j;
                for (j = idx; j < long_sms_fragment_count - 1; j++) {
                    int src_idx = (long_sms_fragment_head + j + 1) % LONG_SMS_FRAGMENT_QUEUE_SIZE;
                    int dst_idx = (long_sms_fragment_head + j) % LONG_SMS_FRAGMENT_QUEUE_SIZE;
                    long_sms_fragment_queue[dst_idx] = long_sms_fragment_queue[src_idx];
                }
                long_sms_fragment_count--;
            }
        } else {
            i++;
        }
    }
    
    printf("[DEBUG] Cleaned up processed long SMS fragments: ref=%d, max=%d\n", ref, max);
}

// 清理过期的长短信片段（超过30秒的片段）
void cleanup_long_sms_fragment_queue() {
    time_t now = time(NULL);
    int i = 0;
    while (i < long_sms_fragment_count) {
        int idx = (long_sms_fragment_head + i) % LONG_SMS_FRAGMENT_QUEUE_SIZE;
        if (now - long_sms_fragment_queue[idx].received_time > 30) {
            // 移除这个条目
            if (idx == long_sms_fragment_head) {
                long_sms_fragment_head = (long_sms_fragment_head + 1) % LONG_SMS_FRAGMENT_QUEUE_SIZE;
                long_sms_fragment_count--;
            } else {
                // 简单处理：只清理头部过期条目
                break;
            }
        } else {
            i++;
        }
    }
}

// 修改后的 add_sms_to_temp_storage 函数
int add_sms_to_temp_storage(const char *sender, const char *timestamp, const char *text, const char *pdu) {
    // 查找是否已存在相同发件人和时间戳的记录
    int i;
    for (i = 0; i < temp_sms_storage_count; i++) {
        if (strcmp(temp_sms_storage[i].sender, sender) == 0 &&
            strcmp(temp_sms_storage[i].timestamp, timestamp) == 0) {
            
            // 检查是否已存在相同的文本内容（完全相同）
            if (strcmp(temp_sms_storage[i].text, text) == 0) {
                printf("[DEBUG] Duplicate SMS content ignored in temp storage\n");
                return 0; // 已存在相同内容
            }
            
            // 检查新内容是否是现有内容的子串
            if (strstr(temp_sms_storage[i].text, text) != NULL) {
                printf("[DEBUG] SMS content is already part of existing message\n");
                return 0;
            }
            
            // 检查现有内容是否是新内容的子串（需要用新内容替换）
            if (strstr(text, temp_sms_storage[i].text) != NULL) {
                printf("[DEBUG] Updating SMS content with more complete version\n");
                strncpy(temp_sms_storage[i].text, text, sizeof(temp_sms_storage[i].text) - 1);
                temp_sms_storage[i].text[sizeof(temp_sms_storage[i].text) - 1] = '\0';
                
                // 更新PDU存储
                if (temp_sms_storage[i].pdu_count < 10) {
                    strncpy(temp_sms_storage[i].pdu_list[temp_sms_storage[i].pdu_count], pdu, sizeof(temp_sms_storage[i].pdu_list[0]) - 1);
                    temp_sms_storage[i].pdu_list[temp_sms_storage[i].pdu_count][sizeof(temp_sms_storage[i].pdu_list[0]) - 1] = '\0';
                    temp_sms_storage[i].pdu_count++;
                }
                
                temp_sms_storage[i].last_received = time(NULL);
                printf("[DEBUG] Updated existing temp storage entry: sender=%s, timestamp=%s\n", sender, timestamp);
                return 1;
            }
            
            // 检查是否内容部分重叠（避免重复拼接）
            size_t existing_len = strlen(temp_sms_storage[i].text);
            size_t new_len = strlen(text);
            
            // 简单的重叠检查：检查新内容的开头是否与现有内容的结尾匹配
            int overlap = 0;
            if (existing_len > 10 && new_len > 10) {
                // 取现有内容的最后10个字符
                char *existing_end = temp_sms_storage[i].text + existing_len - 10;
                // 检查是否在新内容的前10个字符中找到匹配
                if (strncmp(existing_end, text, (new_len > 10 ? 10 : new_len)) == 0) {
                    overlap = 1;
                }
            }
            
            // 添加新的文本内容和PDU（只在没有重叠时）
            if (temp_sms_storage[i].pdu_count < 10) {
                if (!overlap) {
                    // 连接文本内容
                    if (existing_len + new_len < sizeof(temp_sms_storage[i].text) - 1) {
                        strcat(temp_sms_storage[i].text, text);
                    }
                } else {
                    printf("[DEBUG] Overlapping content detected, skipping concatenation\n");
                }
                
                // 存储PDU
                strncpy(temp_sms_storage[i].pdu_list[temp_sms_storage[i].pdu_count], pdu, sizeof(temp_sms_storage[i].pdu_list[0]) - 1);
                temp_sms_storage[i].pdu_list[temp_sms_storage[i].pdu_count][sizeof(temp_sms_storage[i].pdu_list[0]) - 1] = '\0';
                temp_sms_storage[i].pdu_count++;
                
                temp_sms_storage[i].last_received = time(NULL);
                printf("[DEBUG] Added SMS fragment to existing temp storage: sender=%s, timestamp=%s\n", sender, timestamp);
                return 1;
            }
            return 0; // 已达到最大片段数
        }
    }
    
    // 创建新的记录
    if (temp_sms_storage_count < TEMP_SMS_STORAGE_SIZE) {
        int idx = temp_sms_storage_count;
        temp_sms_storage_count++;
        
        strncpy(temp_sms_storage[idx].sender, sender, sizeof(temp_sms_storage[idx].sender) - 1);
        temp_sms_storage[idx].sender[sizeof(temp_sms_storage[idx].sender) - 1] = '\0';
        
        strncpy(temp_sms_storage[idx].timestamp, timestamp, sizeof(temp_sms_storage[idx].timestamp) - 1);
        temp_sms_storage[idx].timestamp[sizeof(temp_sms_storage[idx].timestamp) - 1] = '\0';
        
        strncpy(temp_sms_storage[idx].text, text, sizeof(temp_sms_storage[idx].text) - 1);
        temp_sms_storage[idx].text[sizeof(temp_sms_storage[idx].text) - 1] = '\0';
        
        // 存储第一个PDU
        strncpy(temp_sms_storage[idx].pdu_list[0], pdu, sizeof(temp_sms_storage[idx].pdu_list[0]) - 1);
        temp_sms_storage[idx].pdu_list[0][sizeof(temp_sms_storage[idx].pdu_list[0]) - 1] = '\0';
        temp_sms_storage[idx].pdu_count = 1;
        
        temp_sms_storage[idx].first_received = time(NULL);
        temp_sms_storage[idx].last_received = time(NULL);
        
        printf("[DEBUG] Created new temp storage entry: sender=%s, timestamp=%s\n", sender, timestamp);
        return 1;
    }
    
    return 0; // 存储已满
}

// 修改后的 check_temp_storage_for_processing 函数
int check_temp_storage_for_processing(sms_info_t *combined_info, char *combined_pdu, size_t pdu_size) {
    time_t now = time(NULL);
    int i;
    
    for (i = 0; i < temp_sms_storage_count; i++) {
        // 检查是否超过5秒未收到新片段
        if (now - temp_sms_storage[i].last_received >= 5) {
            printf("[DEBUG] Processing combined SMS from temp storage: sender=%s, timestamp=%s\n", 
                   temp_sms_storage[i].sender, temp_sms_storage[i].timestamp);
            
            // 去除重复内容
            char *text = temp_sms_storage[i].text;
            size_t text_len = strlen(text);
            
            // 如果文本长度超过一定长度，检查是否有重复模式
            if (text_len > 50) {
                // 检查前1/3的内容是否在后面重复出现
                size_t check_len = text_len / 3;
                if (check_len > 50) check_len = 50;
                
                char *second_occurrence = strstr(text + check_len, text);
                if (second_occurrence != NULL) {
                    // 发现重复，截断到第一次出现结束
                    *(second_occurrence) = '\0';
                    printf("[DEBUG] Removed duplicate content from SMS, new length: %zu\n", strlen(text));
                }
            }
            
            // 填充combined_info
            strncpy(combined_info->sender, temp_sms_storage[i].sender, sizeof(combined_info->sender) - 1);
            combined_info->sender[sizeof(combined_info->sender) - 1] = '\0';
            
            strncpy(combined_info->timestamp, temp_sms_storage[i].timestamp, sizeof(combined_info->timestamp) - 1);
            combined_info->timestamp[sizeof(combined_info->timestamp) - 1] = '\0';
            
            strncpy(combined_info->text, temp_sms_storage[i].text, sizeof(combined_info->text) - 1);
            combined_info->text[sizeof(combined_info->text) - 1] = '\0';
            
            // 组合所有PDU
            combined_pdu[0] = '\0';
            size_t current_len = 0;
            int j;
            for (j = 0; j < temp_sms_storage[i].pdu_count; j++) {
                size_t pdu_len = strlen(temp_sms_storage[i].pdu_list[j]);
                if (current_len + pdu_len < pdu_size - 1) {
                    strcat(combined_pdu, temp_sms_storage[i].pdu_list[j]);
                    current_len += pdu_len;
                }
            }
            
            // 显示合并后的结果
            printf("[DEBUG] Combined SMS content: %s\n", combined_info->text);
            printf("[DEBUG] Combined PDU: %s\n", combined_pdu);
            
            // 移除已处理的记录
            for (j = i; j < temp_sms_storage_count - 1; j++) {
                temp_sms_storage[j] = temp_sms_storage[j + 1];
            }
            temp_sms_storage_count--;
            
            return 1; // 找到需要处理的短信
        }
    }
    
    return 0; // 没有需要处理的短信
}

// 清理过期的临时存储记录
void cleanup_temp_storage() {
    time_t now = time(NULL);
    int i = 0;
    
    while (i < temp_sms_storage_count) {
        // 如果超过30秒未更新，则清理
        if (now - temp_sms_storage[i].last_received > 30) {
            printf("[DEBUG] Cleaning up expired temp storage entry: sender=%s, timestamp=%s\n",
                   temp_sms_storage[i].sender, temp_sms_storage[i].timestamp);
            
            // 移动后续项向前
            int j;
            for (j = i; j < temp_sms_storage_count - 1; j++) {
                temp_sms_storage[j] = temp_sms_storage[j + 1];
            }
            temp_sms_storage_count--;
        } else {
            i++;
        }
    }
}

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

// GSM 7-bit 默认字母表到ASCII的映射表
static const char gsm7bit_default[128] = {
    '@', 0x00, '$', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '\n', 0x00, 0x00, '\r', 0x00, 0x00,
    0x00, '_', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x00, 0x00, 0x00,
    ' ', '!', '"', '#', 0x00, '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
    0x00, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 0x00, 0x00, 0x00, 0x00, 0x00
};

// GSM 7-bit 扩展字符表 (需要转义字符)
static const char gsm7bit_ext[128] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '\n', 0x00, 0x00, '\r', 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, '^', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '{', '}', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '[', '~', ']', 0x00,
    '|', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// 解码7-bit编码的短信内容
void decode_7bit_pdu(const char *pdu_data, int data_len_oct, char *output, size_t output_size) {
    // 将十六进制字符串转换为二进制数据
    unsigned char *binary_data = (unsigned char *)malloc(data_len_oct);
    if (!binary_data) {
        output[0] = '\0';
        return;
    }
    
    // 清空输出缓冲区
    memset(output, 0, output_size);
    
    // 将十六进制字符串转换为二进制数据
    int i, j;
    for (i = 0; i < data_len_oct && (i * 2 + 1) < (int)strlen(pdu_data); i++) {
        char hex_byte[3] = {pdu_data[i*2], pdu_data[i*2+1], '\0'};
        unsigned int byte_val;
        sscanf(hex_byte, "%x", &byte_val);
        binary_data[i] = (unsigned char)byte_val;
    }
    
    // 7-bit解码 - 使用位操作方法
    int out_idx = 0;
    int bit_offset = 0;
    
    // 计算实际的7-bit字符数
    int total_bits = data_len_oct * 8;
    int septet_count = total_bits / 7;
    
    for (i = 0; i < septet_count && out_idx < (int)output_size - 1; i++) {
        // 计算当前7-bit字符在数据中的位置
        int byte_index = bit_offset / 8;
        int bit_index = bit_offset % 8;
        
        if (byte_index >= data_len_oct) {
            break;
        }
        
        unsigned char septet;
        if (bit_index <= 1) {
            // 字符完全在当前字节或跨越当前和下一个字节
            if (bit_index == 0) {
                septet = binary_data[byte_index] & 0x7F;
            } else {
                if (byte_index + 1 < data_len_oct) {
                    septet = ((binary_data[byte_index] >> 1) | (binary_data[byte_index + 1] << 7)) & 0x7F;
                } else {
                    septet = (binary_data[byte_index] >> 1) & 0x7F;
                }
            }
        } else {
            // 字符跨越当前和下一个字节
            if (byte_index + 1 < data_len_oct) {
                int shift = 8 - bit_index;
                septet = ((binary_data[byte_index] >> bit_index) | (binary_data[byte_index + 1] << shift)) & 0x7F;
            } else {
                septet = (binary_data[byte_index] >> bit_index) & 0x7F;
            }
        }
        
        // 检查是否是填充字符（在数据末尾）
        if (i == septet_count - 1 && septet == 0) {
            // 这可能是填充，跳过
            break;
        }
        
        // 处理转义字符
        if (septet == 0x1B) {
            // 增加位偏移以获取扩展字符
            bit_offset += 7;
            i++; // 跳过下一个字符的处理
            
            // 获取扩展字符
            byte_index = bit_offset / 8;
            bit_index = bit_offset % 8;
            
            if (byte_index >= data_len_oct) {
                break;
            }
            
            unsigned char ext_septet;
            if (bit_index <= 1) {
                if (bit_index == 0) {
                    ext_septet = binary_data[byte_index] & 0x7F;
                } else {
                    if (byte_index + 1 < data_len_oct) {
                        ext_septet = ((binary_data[byte_index] >> 1) | (binary_data[byte_index + 1] << 7)) & 0x7F;
                    } else {
                        ext_septet = (binary_data[byte_index] >> 1) & 0x7F;
                    }
                }
            } else {
                if (byte_index + 1 < data_len_oct) {
                    int shift = 8 - bit_index;
                    ext_septet = ((binary_data[byte_index] >> bit_index) | (binary_data[byte_index + 1] << shift)) & 0x7F;
                } else {
                    ext_septet = (binary_data[byte_index] >> bit_index) & 0x7F;
                }
            }
            
            if (ext_septet < 128 && out_idx < (int)output_size - 1) {
                char ext_char = gsm7bit_ext[ext_septet];
                if (ext_char != 0) {
                    output[out_idx++] = ext_char;
                }
            }
        } else {
            // 处理普通字符
            if (septet < 128 && out_idx < (int)output_size - 1) {
                char decoded_char = gsm7bit_default[septet];
                if (decoded_char != 0) {
                    output[out_idx++] = decoded_char;
                } else if (septet >= 32 && septet <= 126) {
                    // 如果在标准ASCII范围内，直接使用
                    output[out_idx++] = (char)septet;
                }
            }
        }
        
        bit_offset += 7;
    }
    
    output[out_idx] = '\0';
    free(binary_data);
    
    // 过滤乱码字符
    filter_garbage_chars(output);
}

// 完整的PDU解码，包含SMSC、发件人、时间戳等信息
void decode_pdu(const char *pdu, sms_info_t *info) {
    memset(info, 0, sizeof(*info));
    int idx = 0;
    int pdu_len = strlen(pdu);
    
    // 添加长度检查，防止处理过短的PDU
    if (pdu_len < 10) {
        return;
    }
    
    int smsc_len = 0;
    int i, j, k; // 统一声明循环变量
    
    sscanf(pdu, "%2x", &smsc_len);
    idx += 2;
    
    // 添加边界检查
    if (idx >= pdu_len) return;
    
    int smsc_type = 0;
    sscanf(pdu + idx, "%2x", &smsc_type);
    idx += 2;
    
    if (idx >= pdu_len) return;
    
    int smsc_bcd_len = (smsc_len - 1) * 2;
    char smsc_bcd[64] = {0};
    
    // 确保不会越界复制
    int copy_len = (smsc_bcd_len < (pdu_len - idx)) ? smsc_bcd_len : (pdu_len - idx);
    copy_len = (copy_len < 63) ? copy_len : 63;
    strncpy(smsc_bcd, pdu + idx, copy_len);
    smsc_bcd[copy_len] = 0;
    idx += smsc_bcd_len;
    
    j = 0;
    for (i = 0; i < smsc_bcd_len && i < (int)sizeof(smsc_bcd)-1 && j < (int)sizeof(info->smsc)-1; i += 2) {
        if (idx >= pdu_len) break;
        if (smsc_bcd[i+1] == 'F' || smsc_bcd[i+1] == 'f') {
            info->smsc[j++] = smsc_bcd[i];
        } else {
            info->smsc[j++] = smsc_bcd[i+1];
            if (j < (int)sizeof(info->smsc)-1) {
                info->smsc[j++] = smsc_bcd[i];
            }
        }
    }
    info->smsc[j] = 0;
    
    // 去除SMSC末尾的F/f字符
    if (j > 0 && (info->smsc[j-1] == 'F' || info->smsc[j-1] == 'f')) {
        info->smsc[j-1] = '\0';
    }
    
    // 去除多余+86前缀（只保留一次）
    if (strncmp(info->smsc, "86", 2) == 0) {
        memmove(info->smsc, info->smsc + 2, strlen(info->smsc) - 1);
    }

    // 添加更多边界检查
    if (idx + 2 >= pdu_len) return;
    idx += 2; // PDU类型
    
    if (idx + 2 >= pdu_len) return;
    int sender_len = 0;
    sscanf(pdu + idx, "%2x", &sender_len);
    idx += 2;
    
    if (idx + 2 >= pdu_len) return;
    int sender_type = 0;
    sscanf(pdu + idx, "%2x", &sender_type);
    idx += 2;
    
    int sender_bcd_len = (sender_len % 2 == 0) ? sender_len : sender_len + 1;
    sender_bcd_len /= 2;
    sender_bcd_len *= 2;
    
    char sender_bcd[64] = {0};
    copy_len = (sender_bcd_len < (pdu_len - idx)) ? sender_bcd_len : (pdu_len - idx);
    copy_len = (copy_len < 63) ? copy_len : 63;
    strncpy(sender_bcd, pdu + idx, copy_len);
    sender_bcd[copy_len] = 0;
    idx += sender_bcd_len;
    
    j = 0;
    for (i = 0; i < sender_bcd_len && i < (int)sizeof(sender_bcd)-1 && j < (int)sizeof(info->sender)-1; i += 2) {
        if (idx >= pdu_len) break;
        if (sender_bcd[i+1] == 'F' || sender_bcd[i+1] == 'f') {
            info->sender[j++] = sender_bcd[i];
        } else {
            info->sender[j++] = sender_bcd[i+1];
            if (j < (int)sizeof(info->sender)-1) {
                info->sender[j++] = sender_bcd[i];
            }
        }
    }
    info->sender[j] = 0;
    
    // 去除Sender末尾的F/f字符
    if (j > 0 && (info->sender[j-1] == 'F' || info->sender[j-1] == 'f')) {
        info->sender[j-1] = '\0';
    }
    
    // 去除多余+86前缀（只保留一次）
    if (strncmp(info->sender, "86", 2) == 0) {
        memmove(info->sender, info->sender + 2, strlen(info->sender) - 1);
    }

    // TP_PID
    if (idx + 2 <= pdu_len) {
        strncpy(info->tp_pid, pdu + idx, 2);
        info->tp_pid[2] = 0;
        idx += 2;
    }

    // TP_DCS
    if (idx + 2 <= pdu_len) {
        strncpy(info->tp_dcs, pdu + idx, 2);
        info->tp_dcs[2] = 0;
        idx += 2;
    }
    
    if (strcmp(info->tp_dcs, "00") == 0) {
        strcpy(info->tp_dcs_desc, "7-bit Default Alphabet");
        strcpy(info->sms_class, "0");
        strcpy(info->alphabet, "7-bit");
    } else if (strcmp(info->tp_dcs, "08") == 0) {
        strcpy(info->tp_dcs_desc, "Uncompressed Text");
        strcpy(info->sms_class, "0");
        strcpy(info->alphabet, "UCS2(16)bit");
    } else {
        strcpy(info->tp_dcs_desc, "Unknown");
        strcpy(info->sms_class, "?");
        strcpy(info->alphabet, "Unknown");
    }

    // 时间戳
    if (idx + 14 <= pdu_len) {
        char ts[32] = {0};
        strncpy(ts, pdu + idx, 14);
        ts[14] = 0;
        idx += 14;
        char dt[64] = {0};
        for (i = 0; i < 12 && i < (int)sizeof(ts)-1; i += 2) {
            dt[i] = ts[i+1];
            dt[i+1] = ts[i];
        }
        snprintf(info->timestamp, sizeof(info->timestamp), "%c%c/%c%c/%c%c %c%c:%c%c:%c%c",
            dt[0], dt[1], dt[2], dt[3], dt[4], dt[5], dt[6], dt[7], dt[8], dt[9], dt[10], dt[11]);
    }

    if (idx + 2 > pdu_len) return;
    int text_len_oct = 0;
    sscanf(pdu + idx, "%2x", &text_len_oct);
    idx += 2;
    info->text_len = text_len_oct;

    // 根据TP-DCS决定解码方式，添加边界检查
    if (strcmp(info->tp_dcs, "00") == 0 && idx < pdu_len) {
        // 7-bit编码
        int available_len = (pdu_len - idx) / 2;
        decode_7bit_pdu(pdu + idx, (text_len_oct < available_len) ? text_len_oct : available_len, info->text, sizeof(info->text));
    } else if (strcmp(info->tp_dcs, "08") == 0 && idx < pdu_len) {
        // UCS2编码 - 修改2: 改进处理逻辑
        int ucs2_len = text_len_oct * 2;
        int available_len = pdu_len - idx;
        int process_len = (ucs2_len < available_len) ? ucs2_len : available_len;
        
        if (process_len > 0) {
            // 增大缓冲区以容纳更长的数据
            char ucs2_hex[8192] = {0};
            int copy_len = (process_len < 8191) ? process_len : 8191;
            strncpy(ucs2_hex, pdu + idx, copy_len);
            ucs2_hex[copy_len] = 0;
            
            // 直接使用改进的decode_pdu_ucs2函数
            decode_pdu_ucs2(ucs2_hex, info->text, sizeof(info->text));
        }
    } else if (idx < pdu_len) {
        // 默认处理方式（尝试作为简单十六进制处理）
        int hex_len = text_len_oct * 2;
        int available_len = pdu_len - idx;
        int process_len = (hex_len < available_len) ? hex_len : available_len;
        
        if (process_len > 0 && process_len < sizeof(info->text) - 1) {
            strncpy(info->text, pdu + idx, process_len);
            info->text[process_len] = 0;
        }
    }
}

// 修改3: 改进decode_pdu_ucs2函数以处理更长的内容
void decode_pdu_ucs2(const char *pdu, char *out, size_t outlen) {
    // 假设pdu内容全为UCS2编码的16进制字符串
    size_t len = strlen(pdu);
    size_t i = 0, j = 0;
    
    // 兼容原逻辑：如果长度太短直接返回空
    if (len < 4) { 
        out[0] = 0; 
        return; 
    }
    
    // 清空输出缓冲区
    memset(out, 0, outlen);
    
    while (i + 3 < len && j + 4 < outlen) {
        unsigned int ucs2;
        // 确保我们有足够的字符来读取一个完整的UCS2字符(4个十六进制字符)
        if (i + 4 > len) break;
        
        if (sscanf(pdu + i, "%4x", &ucs2) != 1) break;
        
        // 跳过空字符但继续处理
        if (ucs2 == 0) {
            i += 4;
            continue;
        }
        
        if (ucs2 < 0x80) {
            // ASCII字符 (1字节)
            out[j++] = (char)ucs2;
        } else if (ucs2 < 0x800) {
            // 2字节UTF-8
            if (j + 1 < outlen) {
                out[j++] = 0xC0 | (ucs2 >> 6);
                out[j++] = 0x80 | (ucs2 & 0x3F);
            } else {
                break;
            }
        } else if (ucs2 < 0x10000) {
            // 3字节UTF-8
            if (j + 2 < outlen) {
                out[j++] = 0xE0 | (ucs2 >> 12);
                out[j++] = 0x80 | ((ucs2 >> 6) & 0x3F);
                out[j++] = 0x80 | (ucs2 & 0x3F);
            } else {
                break;
            }
        } else if (ucs2 < 0x110000) {
            // 4字节UTF-8
            if (j + 3 < outlen) {
                out[j++] = 0xF0 | (ucs2 >> 18);
                out[j++] = 0x80 | ((ucs2 >> 12) & 0x3F);
                out[j++] = 0x80 | ((ucs2 >> 6) & 0x3F);
                out[j++] = 0x80 | (ucs2 & 0x3F);
            } else {
                break;
            }
        }
        i += 4;
    }
    out[j] = 0;
    
    // 过滤乱码字符
    filter_garbage_chars(out);
}

// 发送钉钉消息接口（只支持text）
void send_dingtalk_msg(const char *webhook, const char *txt, const char *keyword) {
    // 构造钉钉 content 字段，并做严格JSON安全转义
    char safe_txt[4096]; // 增加缓冲区大小以支持长短信
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
    
    // 构造消息内容，处理keyword为NULL的情况
    char content[6144]; // 增加缓冲区大小
    if (keyword) {
        snprintf(content, sizeof(content), "%s\\n%s", keyword, safe_txt);
    } else {
        // 如果keyword为NULL，直接使用文本内容
        snprintf(content, sizeof(content), "%s", safe_txt);
    }
    
    // 构造完整 JSON
    char json_msg[8192]; // 增加缓冲区大小
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
    char request[16384]; // 增加缓冲区大小
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

// 修改 extract_and_send_sms_from_log 函数，只匹配特定格式的短信信息
void extract_and_send_sms_from_log(const char *webhook, const char *headtxt, const char *tailtxt, const char *keyword, const char *number) {
    FILE *fp = fopen("/tmp/zte_log.txt", "r");
    if (!fp) return;
    char line[4096];
    regex_t reg;
    // 修改正则表达式，只匹配write(1, ...)格式的短信信息
    regcomp(&reg, "^[ \t]*(\\[pid [0-9]+\\] )?write\\(1, \"(\\\\\\\\n)?\\\\r\\\\n\\+CMT:.*\", [0-9]+", REG_EXTENDED);
    int line_num = 0;
    time_t start_time = time(NULL);
    
    // PDU去重队列 - 用于防止相同PDU重复发送
    static char pdu_sent_queue[50][2048];
    static int pdu_sent_count = 0;
    static int pdu_sent_head = 0;
    
    // 在函数开始处声明所有变量
    sms_info_t info;
    char *first_crlf, *pdu_start, *pdu_end;
    char pdu[2048];
    char *pdubegin, *pdu_trim, *pdutail;
    size_t textlen;
    int detection_idx, already_sent;
    int i, idx;
    char decoded_info[3072]; // 增加缓冲区大小
    char msg[4096]; // 增加缓冲区大小
    size_t pdu_len, pi;
    int valid_pdu;
    int is_long_sms_fragment = 0;
    
    // 检查临时存储中是否有需要处理的短信
    sms_info_t combined_info;
    char combined_pdu[16384]; // 增加缓冲区大小以容纳组合后的PDU
    if (check_temp_storage_for_processing(&combined_info, combined_pdu, sizeof(combined_pdu))) {
        printf("[DEBUG] Processing combined SMS from temp storage\n");
        // 处理合并后的短信
        textlen = strlen(combined_info.text);
        if (textlen > 0) {
            // 清理过期的检测条目
            cleanup_detection_window();
            
            // 添加到连续检测窗口并检查是否达到3次
            add_sms_to_detection_window(combined_info.sender, combined_info.timestamp, combined_info.text);
            detection_idx = is_sms_in_detection_window(combined_info.sender, combined_info.timestamp, combined_info.text);
            
            // 检查是否在检测窗口中且计数达到3次
            if (detection_idx != -1 && detection_window[detection_idx].count >= 1) {
                // 检查是否已经发送过相同的PDU
                already_sent = 0;
                for (i = 0; i < pdu_sent_count; i++) {
                    idx = (pdu_sent_head + i) % 50;
                    if (strcmp(pdu_sent_queue[idx], combined_pdu) == 0) {
                        already_sent = 1;
                        printf("[DEBUG] skip already sent pdu: %s\n", combined_pdu);
                        break;
                    }
                }
                
                // 如果未发送过，则发送并添加到已发送队列
                if (!already_sent) {
                    // 处理PDU，显示解码后的信息和原始PDU
                    snprintf(decoded_info, sizeof(decoded_info),
                        "短消息服务中心:%s\n发件人:%s\n时间戳:%s\n短信内容:%s",
                        combined_info.smsc[0] ? combined_info.smsc : "N/A",
                        combined_info.sender[0] ? combined_info.sender : "N/A",
                        combined_info.timestamp[0] ? combined_info.timestamp : "N/A",
                        combined_info.text);
                    
                    // 构造消息内容，确保headtxt在keyword之前，并包含设备编号
                    char full_msg[8192]; // 增加缓冲区大小
                    char headtxt_with_number[2048]; // 增加缓冲区大小
                    
                    // 如果提供了number参数，将其添加到headtxt中
                    if (number) {
                        if (headtxt) {
                            snprintf(headtxt_with_number, sizeof(headtxt_with_number), "[设备编号:%s] %s", number, headtxt);
                        } else {
                            snprintf(headtxt_with_number, sizeof(headtxt_with_number), "[设备编号:%s]", number);
                        }
                    } else {
                        // 未提供number参数时添加SIM卡号信息
                        char sim_info[512]; // 增加缓冲区大小
                        if (global_sim_number[0]) {
                            snprintf(sim_info, sizeof(sim_info), "[SIM卡号:%s]", global_sim_number);
                        } else if (sim_number_initialized) {
                            // SIM卡号获取失败或不支持
                            snprintf(sim_info, sizeof(sim_info), "[SIM卡号:获取失败，设备不支持，请进行手动添加]");
                        }
                        
                        if (headtxt) {
                            if (sim_info[0]) {
                                snprintf(headtxt_with_number, sizeof(headtxt_with_number), "%s %s", sim_info, headtxt);
                            } else {
                                strncpy(headtxt_with_number, headtxt, sizeof(headtxt_with_number) - 1);
                            }
                        } else if (sim_info[0]) {
                            strncpy(headtxt_with_number, sim_info, sizeof(headtxt_with_number) - 1);
                        }
                    }
                    
                    if (headtxt_with_number[0]) {
                        snprintf(full_msg, sizeof(full_msg),
                            "%s\n[pdu解码后的信息]\n%s\n\n原始PDU十六进制码如下(受限字符集，可能会有乱码，如有影响阅读自行解码原始数据)：\n%s",
                            headtxt_with_number,
                            decoded_info,
                            combined_pdu);
                    } else {
                        snprintf(full_msg, sizeof(full_msg),
                            "[pdu解码后的信息]\n%s\n\n原始PDU十六进制码如下(受限字符集，可能会有乱码，如有影响阅读自行解码原始数据)：\n%s",
                            decoded_info,
                            combined_pdu);
                    }
                    
                    send_dingtalk_msg(webhook, full_msg, keyword);
                    
                    // 使用truncate强制清空文件（0字节填充）
                    if (truncate("/tmp/zte_log.txt", 0) != 0) {
                        perror("truncate /tmp/zte_log.txt");
                    }
                    
                    // 添加到已发送PDU队列
                    if (pdu_sent_count < 50) {
                        strcpy(pdu_sent_queue[(pdu_sent_head + pdu_sent_count) % 50], combined_pdu);
                        pdu_sent_count++;
                    } else {
                        strcpy(pdu_sent_queue[pdu_sent_head], combined_pdu);
                        pdu_sent_head = (pdu_sent_head + 1) % 50;
                    }
                }
            } else {
                printf("[DEBUG] sms not yet confirmed (count=%d): Sender=%s, TimeStamp=%s, Text=%s\n", 
                       detection_idx != -1 ? detection_window[detection_idx].count : 0,
                       combined_info.sender, combined_info.timestamp, combined_info.text);
            }
        }
    }
    
    while (fgets(line, sizeof(line), fp)) {
        // 添加超时检查，防止函数执行过久
        if (time(NULL) - start_time > 30) {
            printf("[WARN] extract_and_send_sms_from_log timeout\n");
            break;
        }
        
        line_num++;
        int is_read = (regexec(&reg, line, 0, NULL, 0) == 0);
        char *p = strstr(line, "+CMT: ");
        if (!p) {
            // 尝试另一种格式
            p = strstr(line, "\\+CMT: ");
        }
        
        if (p) {
            first_crlf = strstr(p, "\\r\\n");
            if (first_crlf) {
                pdu_start = first_crlf + 4;
                pdu_end = strstr(pdu_start, "\\r\\n");
                memset(pdu, 0, sizeof(pdu));  // 清空缓冲区
                if (pdu_end && pdu_end > pdu_start && (pdu_end - pdu_start) < (int)sizeof(pdu)) {
                    strncpy(pdu, pdu_start, pdu_end - pdu_start);
                    pdu[pdu_end - pdu_start] = 0;
                } else {
                    strncpy(pdu, pdu_start, sizeof(pdu)-1);
                    pdu[sizeof(pdu)-1] = 0;
                }
                pdubegin = pdu;
                while (*pdubegin && (*pdubegin == ' ' || *pdubegin == '\t')) pdubegin++;
                pdu_trim = pdubegin;
                pdutail = pdu_trim + strlen(pdu_trim) - 1;
                while (pdutail > pdu_trim && (*pdutail == ' ' || *pdutail == '\t')) *pdutail-- = 0;
                if (pdu_trim[0]) {
                    // 过滤异常PDU：长度至少20且全为十六进制字符
                    valid_pdu = 1;
                    pdu_len = strlen(pdu_trim);
                    if (pdu_len < 20) valid_pdu = 0;
                    for (pi = 0; pi < pdu_len; pi++) {
                        char c = pdu_trim[pi];
                        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
                            valid_pdu = 0;
                            break;
                        }
                    }
                    if (valid_pdu) {
                        // 先进行PDU解码以获取基本信息
                        printf("[DEBUG] pdu_trim - %s\n",pdu_trim), 
                        memset(&info, 0, sizeof(info));
                        decode_pdu(pdu_trim, &info);
                        textlen = strlen(info.text);
                        
                        // 添加调试信息输出，显示解码后的中文信息
                        printf("[DEBUG] Decoded SMS - Sender: %s, Timestamp: %s, Text: %s\n", 
                               info.sender, info.timestamp, info.text);
                        
                        // 清理过期的PDU片段
                        cleanup_pdu_fragment_queue();
                        cleanup_long_sms_tracker();
                        cleanup_temp_storage();
                        
                        // 检查当前PDU是否是之前完整PDU的片段
                        if (is_pdu_fragment_in_queue(info.sender, info.timestamp, pdu_trim)) {
                            printf("[DEBUG] Skipping fragment PDU as it's part of a complete PDU already processed\n");
                            continue; // 如果是片段，跳过处理
                        }
                        
                        // 检查是否是已知长短信的片段
                        if (is_known_long_sms(info.sender, info.timestamp)) {
                            printf("[DEBUG] Skipping known long SMS fragment from sender %s at %s\n", 
                                   info.sender, info.timestamp);
                            continue; // 如果是已知长短信的片段，跳过处理
                        }
                        
                        // 将当前PDU添加到片段队列中
                        add_pdu_fragment_to_queue(info.sender, info.timestamp, pdu_trim);
                        
                        // 检查是否为长短信片段
                        unsigned char ref, max, seq;
                        is_long_sms_fragment = extract_long_sms_info(pdu_trim, &ref, &max, &seq);
                        if (is_long_sms_fragment) {
                            printf("[DEBUG] Long SMS fragment detected - Ref: %d, Max: %d, Seq: %d\n", ref, max, seq);
                            // 添加到跟踪器，后续相同发件人和时间戳的片段会被过滤
                            add_long_sms_to_tracker(info.sender, info.timestamp);
                            
                            // 添加长短信片段到队列
                            add_long_sms_fragment(info.sender, info.timestamp, ref, max, seq, info.text, pdu_trim);
                            
                            // 检查是否可以重组长短信
                            if (can_reassemble_long_sms(info.sender, info.timestamp, ref, max)) {
                                char reassembled_text[8192];
                                char combined_pdu[16384];
                                if (reassemble_long_sms(info.sender, info.timestamp, ref, max, reassembled_text, sizeof(reassembled_text), combined_pdu, sizeof(combined_pdu))) {
                                    printf("[DEBUG] Successfully reassembled long SMS: %s\n", reassembled_text);
                                    printf("[DEBUG] Combined PDU: %s\n", combined_pdu);
                                    // 使用重组后的完整短信内容
                                    strncpy(info.text, reassembled_text, sizeof(info.text) - 1);
                                    info.text[sizeof(info.text) - 1] = '\0';
                                    textlen = strlen(info.text);
                                    
                                    // 清理已处理的片段，避免重复处理
                                    cleanup_processed_long_sms_fragments(info.sender, info.timestamp, ref, max);
                                }
                            } else {
                                printf("[DEBUG] Long SMS not yet complete, waiting for more fragments\n");
                                continue; // 等待更多片段
                            }
                        } else {
                            // 不是长短信片段，添加到临时存储中等待5秒超时合并
                            printf("[DEBUG] Adding SMS to temp storage for 5-second check cycle\n");
                            add_sms_to_temp_storage(info.sender, info.timestamp, info.text, pdu_trim);
                            continue; // 等待周期检查
                        }
                        
                        if (textlen > 0) {
                            // 清理过期的检测条目
                            cleanup_detection_window();
                            
                            // 添加到连续检测窗口并检查是否达到3次
                            add_sms_to_detection_window(info.sender, info.timestamp, info.text);
                            detection_idx = is_sms_in_detection_window(info.sender, info.timestamp, info.text);
                            
                            // 检查是否在检测窗口中且计数达到3次
                            if (detection_idx != -1 && detection_window[detection_idx].count >= 3) {
                                // 检查是否已经发送过相同的PDU
                                already_sent = 0;
                                for (i = 0; i < pdu_sent_count; i++) {
                                    idx = (pdu_sent_head + i) % 50;
                                    if (strcmp(pdu_sent_queue[idx], pdu_trim) == 0) {
                                        already_sent = 1;
                                        printf("[DEBUG] skip already sent pdu: %s\n", pdu_trim);
                                        break;
                                    }
                                }
                                
                                // 如果未发送过，则发送并添加到已发送队列
                                if (!already_sent) {
                                    // 处理PDU，显示解码后的信息和原始PDU
                                    snprintf(decoded_info, sizeof(decoded_info),
                                        "短消息服务中心:%s\n发件人:%s\n时间戳:%s\n短信内容:%s",
                                        info.smsc[0] ? info.smsc : "N/A",
                                        info.sender[0] ? info.sender : "N/A",
                                        info.timestamp[0] ? info.timestamp : "N/A",
                                        info.text);
                                    
                                    // 构造消息内容，确保headtxt在keyword之前，并包含设备编号
                                    char full_msg[4096]; // 增加缓冲区大小
                                    char headtxt_with_number[2048]; // 增加缓冲区大小
                                    
                                    // 如果提供了number参数，将其添加到headtxt中
                                    if (number) {
                                        if (headtxt) {
                                            snprintf(headtxt_with_number, sizeof(headtxt_with_number), "[设备编号:%s] %s", number, headtxt);
                                        } else {
                                            snprintf(headtxt_with_number, sizeof(headtxt_with_number), "[设备编号:%s]", number);
                                        }
                                    } else {
                                        // 未提供number参数时添加SIM卡号信息
                                        char sim_info[512]; // 增加缓冲区大小
                                        if (global_sim_number[0]) {
                                            snprintf(sim_info, sizeof(sim_info), "[SIM卡号:%s]", global_sim_number);
                                        } else if (sim_number_initialized) {
                                            // SIM卡号获取失败或不支持
                                            snprintf(sim_info, sizeof(sim_info), "[SIM卡号:获取失败，设备不支持，请进行手动添加]");
                                        }
                                        
                                        if (headtxt) {
                                            if (sim_info[0]) {
                                                snprintf(headtxt_with_number, sizeof(headtxt_with_number), "%s %s", sim_info, headtxt);
                                            } else {
                                                strncpy(headtxt_with_number, headtxt, sizeof(headtxt_with_number) - 1);
                                            }
                                        } else if (sim_info[0]) {
                                            strncpy(headtxt_with_number, sim_info, sizeof(headtxt_with_number) - 1);
                                        }
                                    }
                                    
                                    if (headtxt_with_number[0]) {
                                        snprintf(full_msg, sizeof(full_msg),
                                            "%s\n[pdu解码后的信息]\n%s\n\n原始PDU十六进制码如下(受限字符集，可能会有乱码，如有影响阅读自行解码原始数据)：\n%s",
                                            headtxt_with_number,
                                            decoded_info,
                                            pdu_trim);
                                    } else {
                                        snprintf(full_msg, sizeof(full_msg),
                                            "[pdu解码后的信息]\n%s\n\n原始PDU十六进制码如下(受限字符集，可能会有乱码，如有影响阅读自行解码原始数据)：\n%s",
                                            decoded_info,
                                            pdu_trim);
                                    }
                                    
                                    send_dingtalk_msg(webhook, full_msg, keyword);
                                    
                                    // 使用truncate强制清空文件（0字节填充）
                                    if (truncate("/tmp/zte_log.txt", 0) != 0) {
                                        perror("truncate /tmp/zte_log.txt");
                                    }
                                    
                                    // 添加到已发送PDU队列
                                    if (pdu_sent_count < 50) {
                                        strcpy(pdu_sent_queue[(pdu_sent_head + pdu_sent_count) % 50], pdu_trim);
                                        pdu_sent_count++;
                                    } else {
                                        strcpy(pdu_sent_queue[pdu_sent_head], pdu_trim);
                                        pdu_sent_head = (pdu_sent_head + 1) % 50;
                                    }
                                }
                            } else {
                                printf("[DEBUG] sms not yet confirmed (count=%d): Sender=%s, TimeStamp=%s, Text=%s\n", 
                                       detection_idx != -1 ? detection_window[detection_idx].count : 0,
                                       info.sender, info.timestamp, info.text);
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
    
    // 强制杀死监控进程
    if (monitor_pid > 0) {
        kill(monitor_pid, SIGTERM);
        usleep(100*1000);
        if (kill(monitor_pid, 0) == 0) {
            kill(monitor_pid, SIGKILL);
        }
    }
    
    exit(0);
}


int main(int argc, char *argv[]) {
    int only_service_mode = 0;
    int only_send_once_mode = 0;
    char *headtxt = NULL, *tailtxt = NULL;
    char *keyword = NULL;
    char *number = NULL; // 添加number变量
    char *activekey = NULL; // 添加activekey变量
    int i;
    
    // 解析命令行参数
    for (i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--mode=service_start") == 0)) {
            only_service_mode = 1;
        }
        if ((strcmp(argv[i], "--mode=send_once") == 0)) {
            only_send_once_mode = 1;
        }
        if (strncmp(argv[i], "--headtxt=", 10) == 0) {
            headtxt = argv[i] + 10;
        }
        if (strncmp(argv[i], "--tailtxt=", 10) == 0) {
            tailtxt = argv[i] + 10;
        }
        // 添加对--keyword参数的解析
        if (strncmp(argv[i], "--keyword=", 10) == 0) {
            keyword = argv[i] + 10;
        }
        // 添加对--number参数的解析
        if (strncmp(argv[i], "--number=", 9) == 0) {
            number = argv[i] + 9;
        }
        // 添加对--activekey参数的解析
        if (strncmp(argv[i], "--activekey=", 12) == 0) {
            activekey = argv[i] + 12;
        }
        // 添加对--targetbin参数的解析
        if (strncmp(argv[i], "--targetbin=", 12) == 0) {
            const char *mifi_path = argv[i] + 12;
            if (strlen(mifi_path) < sizeof(zte_mifi_path) - 1) {
                strncpy(zte_mifi_path, mifi_path, sizeof(zte_mifi_path) - 1);
                zte_mifi_path[sizeof(zte_mifi_path) - 1] = '\0';
            }
        }
        // 添加对--tracebin参数的解析
        if (strncmp(argv[i], "--tracebin=", 11) == 0) {
            const char *path = argv[i] + 11;
            if (strlen(path) < sizeof(strace_bin_path) - 1) {
                strncpy(strace_bin_path, path, sizeof(strace_bin_path) - 1);
                strace_bin_path[sizeof(strace_bin_path) - 1] = '\0';
            }
        }
    }
    
    // 如果提供了activekey参数，显示激活信息
    if (activekey) {
        printf("当前设备已经激活 激活码为%s\n", activekey);
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
        
        // 初始化SIM卡号（仅在未指定number参数时）
        if (!number) {
            init_sim_number();
        }
        
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        if (pthread_create(&strace_thread_id, NULL, strace_thread_func, webhook) != 0) {
            perror("Failed to create strace thread");
            return 1;
        }
        // 修改传递给PDU线程的参数，包含keyword
        char* pdu_args[5] = {webhook, headtxt, tailtxt, keyword, number};
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
            } else if (strncmp(argv[i], "--number=", 9) == 0) { 
                number = argv[i] + 9;
            }
        }
        if (!url || !msgtype || !txt) {
            fprintf(stderr, "Usage: %s --mode=send_once --url=<webhook_url> --msgtype=text --txt=<content> [--number=<value>]\n", argv[0]);
            return 1;
        }
        // 可以在这里使用number参数，并在尾部添加"设备提醒"
        if (number) {
            printf("Number parameter provided: %s\n", number);
            // 在尾部添加"设备提醒"
            char new_txt[4096];
            snprintf(new_txt, sizeof(new_txt), "%s设备提醒", txt);
            txt = strdup(new_txt); // 更新txt指针指向新字符串
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
        } else if (strncmp(argv[i], "--number=", 9) == 0) { 
            number = argv[i] + 9;
        }
    }
    if (!url || !msgtype || !txt) {
        fprintf(stderr, "Usage: %s --url=<webhook_url> --msgtype=text --txt=<content> [--number=<value>]\n", argv[0]);
        return 1;
    }
    // 可以在这里使用number参数，并在尾部添加"设备提醒"
    if (number) {
        printf("Number parameter provided: %s\n", number);
        // 在尾部添加"设备提醒"
        char new_txt[4096];
        snprintf(new_txt, sizeof(new_txt), "%s设备提醒", txt);
        txt = strdup(new_txt); // 更新txt指针指向新字符串
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
