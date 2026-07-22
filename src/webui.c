#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <limits.h>
#include "alice-pusher-bot.h"
#include "../.build/avatar_asset.h"
#include "../.build/sponsor_asset.h"

#define DEFAULT_WEBUI_PORT 51402
#define DEFAULT_CONFIG_PATH "/mnt/userdata/etc_rw/alice_pusher.conf"
#define DEFAULT_SERVICE_PID "/tmp/alice_pusher_service.pid"
#define DEFAULT_LOG_PATH "/tmp/alice_pusher.log"
#define DEFAULT_LOG_LOCK_PATH "/tmp/alice_pusher.log.lock"
#define USERDATA_DIR "/mnt/userdata"
#define WONDER_DIR USERDATA_DIR "/alice_rescue"
#define WONDER_RUN_PATH WONDER_DIR "/alice-rc.run"
#define WONDER_MANIFEST_PATH WONDER_DIR "/manifest"
#define WONDER_GLOBAL_PATH WONDER_DIR "/global.sh"
#define WONDER_AUTOSTART_MAIN USERDATA_DIR "/alice_wonder_autostart.sh"
#define WONDER_SYSTEM_STARTUP WONDER_DIR "/system_startup.sh"
#define WONDER_PUSHER_SCRIPT WONDER_DIR "/autostart/alice-pusher-bot.sh"
#define PUSHER_DIR USERDATA_DIR "/alice_pusher"
#define PUSHER_RUN_PATH PUSHER_DIR "/alice-pusher-bot.run"
#define PUSHER_BIN_PATH PUSHER_DIR "/alice-pusher-bot"
#define PUSHER_GLOBAL_PATH PUSHER_DIR "/global.sh"
#define PUSHER_MANIFEST_PATH PUSHER_DIR "/manifest"
#define PUSHER_START_LOG "/tmp/alice_pusher_autostart.out"
#define PUSHER_START_MARKER "/tmp/alice_pusher_autostart.started"
#define PUSHER_PATH_SH_MARKER "/tmp/alice_pusher_path_sh_started"
#define PUSHER_AUTOSTART_BEGIN "# alice-pusher-bot path_sh begin"
#define PUSHER_AUTOSTART_END "# alice-pusher-bot path_sh end"
#define DELIVERY_WEBHOOK "webhook"
#define DELIVERY_EMAIL "email"
#define TARGET_TYPE_WEBHOOK "webhook"
#define TARGET_TYPE_EMAIL "email"
#define TARGET_NAME_MAX 64
#define PERSIST_RESERVE_BYTES (16UL * 1024UL)
#define LEGACY_RUN_PATH USERDATA_DIR "/alice-pusher-bot.run"
#define LEGACY_BIN_PATH USERDATA_DIR "/alice-pusher-bot"
#define LEGACY_AUTOSTART_SCRIPT USERDATA_DIR "/alice_pusher_autostart.sh"
#define WEB_BODY_MAX 65536
#define WEB_REQ_MAX 16384
#define LOG_RING_MAX 1024
#define LOG_TAIL_MAX LOG_RING_MAX
#define LOG_EXPORT_NAME "alice_pusher.log"
#define TARGET_MIFI_PATH ALICE_TARGET_MIFI_PATH
#define TARGET_UFI_PATH ALICE_TARGET_UFI_PATH

static int g_webui_port = DEFAULT_WEBUI_PORT;
static volatile sig_atomic_t g_webui_restart_requested;
static int g_webui_restart_port;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static int run_webui(const char *self_path, int port);
static void json_escape(char *out, size_t outsz, const char *in);
static void safe_copy(char *dst, size_t dstsz, const char *src);
static void config_escape(char *out, size_t outsz, const char *in);
static void config_unescape(char *out, size_t outsz, const char *in);

typedef struct {
    int enabled;
    char name[TARGET_NAME_MAX];
    char num[128];
    char headtxt[256];
    char tailtxt[256];
    char type[16];
    char webhook[1024];
    char platform[32];
    char custom_ctype[128];
    char custom_body[2048];
    char smtp_host[256];
    char smtp_port[16];
    char smtp_user[256];
    char smtp_password[256];
    char smtp_from[256];
    char smtp_to[256];
    char smtp_security[16];
} web_push_target_t;

typedef struct {
    web_push_target_t targets[ALICE_ENGINE_MAX_TARGETS];
    int target_count;
    char delivery[16];
    char webhook[1024];
    char platform[32];
    char target_mode[32];
    char target_path[256];
    char custom_ctype[128];
    char custom_body[2048];
    char num[128];
    char headtxt[256];
    char tailtxt[256];
    char smtp_host[256];
    char smtp_port[16];
    char smtp_user[256];
    char smtp_password[256];
    char smtp_from[256];
    char smtp_to[256];
    char smtp_security[16];
    int port;
    int long_sms_reassembly;
} web_config_t;

typedef struct {
    int wonder_detected;
    int payload_ready;
    int script_ready;
    int entry_ready;
    int installed;
    int startup_running;
    int mode;
    unsigned long free_bytes;
    unsigned long required_bytes;
    char mode_label[64];
    char payload_path[256];
    char script_path[256];
    char error[256];
} autostart_status_t;

static char g_autostart_error[256];

static void safe_copy(char *dst, size_t dstsz, const char *src) {
    if (!dstsz) return;
    if (!src) src = "";
    strncpy(dst, src, dstsz - 1);
    dst[dstsz - 1] = 0;
}

static int email_configured(const web_config_t *cfg);
static const char *normalize_smtp_security(const char *security);

static const char *normalize_platform(const char *platform) {
    return alice_engine_normalize_platform(platform);
}

static const char *normalize_delivery(const char *delivery) {
    return delivery && strcmp(delivery, DELIVERY_EMAIL) == 0 ?
           DELIVERY_EMAIL : DELIVERY_WEBHOOK;
}

static const char *normalize_target_type(const char *type) {
    return type && strcmp(type, TARGET_TYPE_EMAIL) == 0 ?
           TARGET_TYPE_EMAIL : TARGET_TYPE_WEBHOOK;
}

static int target_is_email(const web_push_target_t *target) {
    return target && strcmp(normalize_target_type(target->type),
                            TARGET_TYPE_EMAIL) == 0;
}

static void init_push_target(web_push_target_t *target, int index) {
    if (!target) return;
    memset(target, 0, sizeof(*target));
    snprintf(target->name, sizeof(target->name), "任务 %d", index + 1);
    safe_copy(target->type, sizeof(target->type), TARGET_TYPE_WEBHOOK);
    safe_copy(target->platform, sizeof(target->platform), "dingtalk");
    safe_copy(target->custom_ctype, sizeof(target->custom_ctype),
              "application/json;charset=utf-8");
    safe_copy(target->custom_body, sizeof(target->custom_body),
              "{\"text\":\"{{json_text}}\"}");
    safe_copy(target->smtp_port, sizeof(target->smtp_port), "587");
    safe_copy(target->smtp_security, sizeof(target->smtp_security), "starttls");
}

static void normalize_push_target(web_push_target_t *target, int index) {
    if (!target) return;
    safe_copy(target->type, sizeof(target->type), normalize_target_type(target->type));
    safe_copy(target->platform, sizeof(target->platform),
              normalize_platform(target->platform));
    safe_copy(target->smtp_security, sizeof(target->smtp_security),
              normalize_smtp_security(target->smtp_security));
    if (!target->name[0])
        snprintf(target->name, sizeof(target->name), "任务 %d", index + 1);
    if (!target->custom_ctype[0])
        safe_copy(target->custom_ctype, sizeof(target->custom_ctype),
                  "application/json;charset=utf-8");
    if (!target->custom_body[0])
        safe_copy(target->custom_body, sizeof(target->custom_body),
                  "{\"text\":\"{{json_text}}\"}");
    if (!target->smtp_port[0])
        safe_copy(target->smtp_port, sizeof(target->smtp_port), "587");
    target->enabled = target->enabled ? 1 : 0;
}

static void clear_target_inactive_fields(web_push_target_t *target) {
    if (!target) return;
    if (target_is_email(target)) {
        target->webhook[0] = 0;
        target->custom_ctype[0] = 0;
        target->custom_body[0] = 0;
    } else {
        target->smtp_host[0] = 0;
        target->smtp_user[0] = 0;
        target->smtp_password[0] = 0;
        target->smtp_from[0] = 0;
        target->smtp_to[0] = 0;
    }
}

static int target_configured(const web_push_target_t *target) {
    if (!target) return 0;
    if (target_is_email(target))
        return target->smtp_host[0] && target->smtp_from[0] && target->smtp_to[0];
    return target->webhook[0] != 0;
}

static int enabled_target_count(const web_config_t *cfg) {
    int i;
    int count = 0;
    if (!cfg) return 0;
    for (i = 0; i < cfg->target_count && i < ALICE_ENGINE_MAX_TARGETS; i++)
        if (cfg->targets[i].enabled && target_configured(&cfg->targets[i]))
            count++;
    return count;
}

static const char *platform_label(const char *platform) {
    platform = normalize_platform(platform);
    if (strcmp(platform, "feishu") == 0) return "飞书";
    if (strcmp(platform, "wecom") == 0) return "企业微信";
    if (strcmp(platform, "serverchan") == 0) return "Server 酱";
    if (strcmp(platform, "discord") == 0) return "Discord";
    if (strcmp(platform, "telegram") == 0) return "Telegram Bot";
    if (strcmp(platform, "bark") == 0) return "Bark";
    if (strcmp(platform, "custom") == 0) return "自定义";
    return "钉钉";
}

static const char *configured_platform_label(const web_config_t *cfg) {
    int i;
    int enabled = 0;
    const web_push_target_t *only = NULL;

    if (!cfg) return "未配置";
    for (i = 0; i < cfg->target_count && i < ALICE_ENGINE_MAX_TARGETS; i++) {
        if (cfg->targets[i].enabled && target_configured(&cfg->targets[i])) {
            enabled++;
            only = &cfg->targets[i];
        }
    }
    if (enabled == 0) return "未配置";
    if (enabled > 1) return "多平台";
    return target_is_email(only) ? "邮箱" : platform_label(only->platform);
}

static const char *configured_delivery_mode(const web_config_t *cfg) {
    int i;
    int webhook_count = 0;
    int email_count = 0;

    if (!cfg) return "none";
    for (i = 0; i < cfg->target_count && i < ALICE_ENGINE_MAX_TARGETS; i++) {
        if (!cfg->targets[i].enabled || !target_configured(&cfg->targets[i]))
            continue;
        if (target_is_email(&cfg->targets[i])) email_count++;
        else webhook_count++;
    }
    if (webhook_count && email_count) return "multiple";
    if (email_count) return "email";
    if (webhook_count) return "webhook";
    return "none";
}

static const char *normalize_smtp_security(const char *security) {
    if (security && strcmp(security, "plain") == 0)
        return "plain";
    if (security && strcmp(security, "tls") == 0)
        return "tls";
    return "starttls";
}

static int email_configured(const web_config_t *cfg) {
    return cfg && cfg->smtp_host[0] && cfg->smtp_from[0] && cfg->smtp_to[0];
}

static int any_target_configured(const web_config_t *cfg) {
    return enabled_target_count(cfg) > 0;
}

static size_t build_engine_target_list(const web_config_t *cfg,
                                       alice_engine_push_target_t *out,
                                       size_t out_count) {
    size_t i;
    size_t count;

    if (!cfg || !out || out_count == 0) return 0;
    count = cfg->target_count;
    if (count > out_count) count = out_count;
    memset(out, 0, out_count * sizeof(*out));
    for (i = 0; i < count; i++) {
        const web_push_target_t *target = &cfg->targets[i];
        out[i].enabled = target->enabled;
        out[i].name = target->name;
        out[i].num = target->num;
        out[i].headtxt = target->headtxt;
        out[i].tailtxt = target->tailtxt;
        out[i].type = target->type;
        out[i].platform = target->platform;
        out[i].webhook = target->webhook;
        out[i].custom_ctype = target->custom_ctype;
        out[i].custom_body = target->custom_body;
        out[i].smtp_host = target->smtp_host;
        out[i].smtp_port = target->smtp_port;
        out[i].smtp_user = target->smtp_user;
        out[i].smtp_password = target->smtp_password;
        out[i].smtp_from = target->smtp_from;
        out[i].smtp_to = target->smtp_to;
        out[i].smtp_security = target->smtp_security;
    }
    return count;
}

static int target_key_parts(const char *key, int *index, const char **field) {
    char *end;
    long value;

    if (!key || strncmp(key, "target_", 7) != 0)
        return 0;
    errno = 0;
    value = strtol(key + 7, &end, 10);
    if (errno || end == key + 7 || *end != '_' ||
        value < 0 || value >= ALICE_ENGINE_MAX_TARGETS || !end[1])
        return 0;
    if (index) *index = (int)value;
    if (field) *field = end + 1;
    return 1;
}

static int load_target_field(web_push_target_t *target, const char *field,
                             const char *value) {
    long enabled;
    char *end;

    if (!target || !field || !value) return 0;
    if (strcmp(field, "enabled") == 0) {
        errno = 0;
        enabled = strtol(value, &end, 10);
        target->enabled = !errno && end != value && enabled != 0;
    } else if (strcmp(field, "name") == 0)
        config_unescape(target->name, sizeof(target->name), value);
    else if (strcmp(field, "num") == 0)
        config_unescape(target->num, sizeof(target->num), value);
    else if (strcmp(field, "headtxt") == 0)
        config_unescape(target->headtxt, sizeof(target->headtxt), value);
    else if (strcmp(field, "tailtxt") == 0)
        config_unescape(target->tailtxt, sizeof(target->tailtxt), value);
    else if (strcmp(field, "type") == 0)
        safe_copy(target->type, sizeof(target->type), normalize_target_type(value));
    else if (strcmp(field, "platform") == 0)
        safe_copy(target->platform, sizeof(target->platform), normalize_platform(value));
    else if (strcmp(field, "webhook") == 0)
        config_unescape(target->webhook, sizeof(target->webhook), value);
    else if (strcmp(field, "custom_ctype") == 0)
        config_unescape(target->custom_ctype, sizeof(target->custom_ctype), value);
    else if (strcmp(field, "custom_body") == 0)
        config_unescape(target->custom_body, sizeof(target->custom_body), value);
    else if (strcmp(field, "smtp_host") == 0)
        config_unescape(target->smtp_host, sizeof(target->smtp_host), value);
    else if (strcmp(field, "smtp_port") == 0)
        config_unescape(target->smtp_port, sizeof(target->smtp_port), value);
    else if (strcmp(field, "smtp_user") == 0)
        config_unescape(target->smtp_user, sizeof(target->smtp_user), value);
    else if (strcmp(field, "smtp_password") == 0)
        config_unescape(target->smtp_password, sizeof(target->smtp_password), value);
    else if (strcmp(field, "smtp_from") == 0)
        config_unescape(target->smtp_from, sizeof(target->smtp_from), value);
    else if (strcmp(field, "smtp_to") == 0)
        config_unescape(target->smtp_to, sizeof(target->smtp_to), value);
    else if (strcmp(field, "smtp_security") == 0)
        safe_copy(target->smtp_security, sizeof(target->smtp_security),
                  normalize_smtp_security(value));
    else
        return 0;
    return 1;
}

static void migrate_legacy_targets(web_config_t *cfg) {
    web_push_target_t *target;
    int count = 0;

    if (!cfg) return;
    if (cfg->webhook[0]) {
        target = &cfg->targets[count++];
        init_push_target(target, count - 1);
        target->enabled = 1;
        safe_copy(target->name, sizeof(target->name), "Webhook");
        safe_copy(target->num, sizeof(target->num), cfg->num);
        safe_copy(target->headtxt, sizeof(target->headtxt), cfg->headtxt);
        safe_copy(target->tailtxt, sizeof(target->tailtxt), cfg->tailtxt);
        safe_copy(target->webhook, sizeof(target->webhook), cfg->webhook);
        safe_copy(target->platform, sizeof(target->platform), cfg->platform);
        safe_copy(target->custom_ctype, sizeof(target->custom_ctype),
                  cfg->custom_ctype);
        safe_copy(target->custom_body, sizeof(target->custom_body),
                  cfg->custom_body);
    }
    if ((cfg->smtp_host[0] || cfg->smtp_user[0] || cfg->smtp_password[0] ||
         cfg->smtp_from[0] || cfg->smtp_to[0]) &&
        count < ALICE_ENGINE_MAX_TARGETS) {
        target = &cfg->targets[count++];
        init_push_target(target, count - 1);
        target->enabled = 1;
        safe_copy(target->name, sizeof(target->name), "邮箱");
        safe_copy(target->num, sizeof(target->num), cfg->num);
        safe_copy(target->headtxt, sizeof(target->headtxt), cfg->headtxt);
        safe_copy(target->tailtxt, sizeof(target->tailtxt), cfg->tailtxt);
        safe_copy(target->type, sizeof(target->type), TARGET_TYPE_EMAIL);
        safe_copy(target->smtp_host, sizeof(target->smtp_host), cfg->smtp_host);
        safe_copy(target->smtp_port, sizeof(target->smtp_port), cfg->smtp_port);
        safe_copy(target->smtp_user, sizeof(target->smtp_user), cfg->smtp_user);
        safe_copy(target->smtp_password, sizeof(target->smtp_password),
                  cfg->smtp_password);
        safe_copy(target->smtp_from, sizeof(target->smtp_from), cfg->smtp_from);
        safe_copy(target->smtp_to, sizeof(target->smtp_to), cfg->smtp_to);
        safe_copy(target->smtp_security, sizeof(target->smtp_security),
                  cfg->smtp_security);
    }
    cfg->target_count = count;
}

static const char *normalize_target_mode(const char *mode) {
    if (!mode || !mode[0]) return "mifi";
    if (strcmp(mode, "mifi") == 0) return "mifi";
    if (strcmp(mode, "ufi") == 0) return "ufi";
    if (strcmp(mode, "custom") == 0) return "custom";
    return "mifi";
}

static const char *target_mode_label(const char *mode) {
    mode = normalize_target_mode(mode);
    if (strcmp(mode, "ufi") == 0) return "ZTE UFI";
    if (strcmp(mode, "custom") == 0) return "自定义";
    return "ZTE MiFi";
}

static const char *target_default_path(const char *mode) {
    mode = normalize_target_mode(mode);
    if (strcmp(mode, "ufi") == 0) return TARGET_UFI_PATH;
    return TARGET_MIFI_PATH;
}

static const char *target_selected_attr(const char *mode, const char *value) {
    return strcmp(normalize_target_mode(mode), value) == 0 ? " selected" : "";
}

static void resolve_target_path(const web_config_t *cfg, char *out, size_t outsz) {
    const char *mode = cfg ? normalize_target_mode(cfg->target_mode) : "mifi";

    if (!outsz) return;
    if (strcmp(mode, "custom") == 0 && cfg && cfg->target_path[0])
        safe_copy(out, outsz, cfg->target_path);
    else
        safe_copy(out, outsz, target_default_path(mode));
    if (!out[0])
        safe_copy(out, outsz, TARGET_MIFI_PATH);
}

static const char *detect_platform_from_url(const char *url) {
    return alice_engine_detect_platform_from_url(url);
}

static const char *selected_attr(const char *platform, const char *value) {
    return strcmp(normalize_platform(platform), value) == 0 ? " selected" : "";
}

static void strip_line(char *s) {
    size_t len;
    if (!s) return;
    len = strlen(s);
    while (len && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[--len] = 0;
    }
}

static void remove_newlines(char *s) {
    while (s && *s) {
        if (*s == '\r' || *s == '\n')
            *s = ' ';
        s++;
    }
}

static void config_escape(char *out, size_t outsz, const char *in) {
    size_t used = 0;

    if (!outsz) return;
    if (!in) in = "";
    while (*in && used + 1 < outsz) {
        unsigned char c = (unsigned char)*in++;
        if (c == '\\' || c == '\n' || c == '\r') {
            if (used + 2 >= outsz) break;
            out[used++] = '\\';
            out[used++] = c == '\n' ? 'n' : (c == '\r' ? 'r' : '\\');
        } else {
            out[used++] = (char)c;
        }
    }
    out[used] = 0;
}

static void config_unescape(char *out, size_t outsz, const char *in) {
    size_t used = 0;

    if (!outsz) return;
    if (!in) in = "";
    while (*in && used + 1 < outsz) {
        char c = *in++;
        if (c == '\\' && *in) {
            char n = *in++;
            if (n == 'n') c = '\n';
            else if (n == 'r') c = '\r';
            else if (n == '\\') c = '\\';
            else {
                if (used + 2 >= outsz) break;
                out[used++] = '\\';
                c = n;
            }
        }
        out[used++] = c;
    }
    out[used] = 0;
}

static int mkdir_p(const char *path) {
    char tmp[512];
    char *p;

    safe_copy(tmp, sizeof(tmp), path);
    if (!tmp[0]) return -1;
    for (p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        mkdir(tmp, 0755);
        *p = '/';
    }
    if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int mkdir_parent_file(const char *path) {
    char tmp[512];
    char *slash;

    safe_copy(tmp, sizeof(tmp), path);
    slash = strrchr(tmp, '/');
    if (!slash) return 0;
    *slash = 0;
    if (!tmp[0]) return 0;
    return mkdir_p(tmp);
}

static char *read_file_alloc(const char *path, size_t max_size, size_t *len_out) {
    struct stat st;
    char *buf;
    int fd;
    size_t off = 0;

    if (stat(path, &st) < 0 || st.st_size < 0 ||
        (size_t)st.st_size > max_size)
        return NULL;
    buf = (char *)malloc((size_t)st.st_size + 1);
    if (!buf)
        return NULL;
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        free(buf);
        return NULL;
    }
    while (off < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + off, (size_t)st.st_size - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            free(buf);
            return NULL;
        }
        if (n == 0) break;
        off += (size_t)n;
    }
    close(fd);
    buf[off] = 0;
    if (len_out) *len_out = off;
    return buf;
}

static int file_contains(const char *path, const char *needle) {
    char *buf = read_file_alloc(path, 128 * 1024, NULL);
    int found;

    if (!buf) return 0;
    found = strstr(buf, needle) != NULL;
    free(buf);
    return found;
}

static void shell_quote(FILE *fp, const char *s) {
    fputc('\'', fp);
    for (; s && *s; s++) {
        if (*s == '\'')
            fputs("'\\''", fp);
        else
            fputc(*s, fp);
    }
    fputc('\'', fp);
}

static int write_all_fd(int fd, const char *buf, size_t len) {
    while (len) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static int path_is_regular_readable(const char *path) {
    struct stat st;

    if (!path || !path[0]) {
        errno = EINVAL;
        return 0;
    }
    if (stat(path, &st) < 0)
        return 0;
    if (!S_ISREG(st.st_mode)) {
        errno = EINVAL;
        return 0;
    }
    return access(path, R_OK) == 0;
}

static int path_is_same_file(const char *a, const char *b) {
    struct stat sa, sb;

    if (!a || !b || stat(a, &sa) < 0 || stat(b, &sb) < 0)
        return 0;
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

static int copy_regular_file(const char *src, const char *dst, mode_t mode) {
    unsigned char buf[16384];
    char tmp[PATH_MAX];
    struct stat st;
    ssize_t n;
    int in = -1;
    int out = -1;
    int saved_errno;
    int rc = -1;

    if (!path_is_regular_readable(src))
        return -1;
    if (stat(src, &st) < 0 || !S_ISREG(st.st_mode)) {
        errno = EINVAL;
        return -1;
    }
    if (path_is_same_file(src, dst))
        return chmod(dst, mode);
    if (mkdir_parent_file(dst) < 0)
        return -1;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", dst, (long)getpid()) >=
        (int)sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    in = open(src, O_RDONLY);
    if (in < 0) goto out;
    out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out < 0) goto out;
    for (;;) {
        n = read(in, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            goto out;
        }
        if (n == 0) break;
        if (write_all_fd(out, (const char *)buf, (size_t)n) < 0)
            goto out;
    }
    if (fsync(out) < 0) goto out;
    if (close(out) < 0) {
        out = -1;
        goto out;
    }
    out = -1;
    if (chmod(tmp, mode) < 0) goto out;
    if (rename(tmp, dst) < 0) goto out;
    rc = 0;

out:
    saved_errno = errno;
    if (out >= 0) close(out);
    if (in >= 0) close(in);
    if (rc < 0) unlink(tmp);
    errno = saved_errno;
    return rc;
}

static int current_exe_path(char *out, size_t outsz) {
    ssize_t n;

    if (!out || outsz == 0) {
        errno = EINVAL;
        return -1;
    }
    n = readlink("/proc/self/exe", out, outsz - 1);
    if (n < 0)
        return -1;
    out[n] = 0;
    return 0;
}

static void remount_userdata_rw(void) {
    system("mount -o remount,rw,exec " USERDATA_DIR " 2>/dev/null || "
           "mount -o remount,rw " USERDATA_DIR " 2>/dev/null");
}

enum {
    PERSIST_NONE = 0,
    PERSIST_WONDER = 1,
    PERSIST_STANDALONE = 2
};

static void set_autostart_error(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(g_autostart_error, sizeof(g_autostart_error), fmt, ap);
    va_end(ap);
}

static int read_nv_path_sh(char *out, size_t outsz) {
    FILE *fp;
    size_t len;

    if (!out || outsz == 0) return -1;
    out[0] = 0;
    fp = popen("nv get path_sh 2>/dev/null", "r");
    if (!fp) return -1;
    if (!fgets(out, (int)outsz, fp)) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    len = strcspn(out, "\r\n \t");
    out[len] = 0;
    return out[0] ? 0 : -1;
}

static int wonder_deployed(void) {
    char path_sh[256];

    if (read_nv_path_sh(path_sh, sizeof(path_sh)) < 0 ||
        strcmp(path_sh, WONDER_DIR) != 0)
        return 0;
    return access(WONDER_DIR, X_OK) == 0 &&
           path_is_regular_readable(WONDER_RUN_PATH) &&
           path_is_regular_readable(WONDER_GLOBAL_PATH) &&
           path_is_regular_readable(WONDER_AUTOSTART_MAIN) &&
           path_is_regular_readable(WONDER_SYSTEM_STARTUP) &&
           file_contains(WONDER_MANIFEST_PATH, "name=alice-wonder") &&
           file_contains(WONDER_GLOBAL_PATH, "alice-wonder path_sh begin");
}

static int standalone_entry_ready(void) {
    char path_sh[256];

    if (read_nv_path_sh(path_sh, sizeof(path_sh)) < 0 ||
        strcmp(path_sh, PUSHER_DIR) != 0)
        return 0;
    return path_is_regular_readable(PUSHER_GLOBAL_PATH) &&
           file_contains(PUSHER_GLOBAL_PATH, PUSHER_AUTOSTART_BEGIN) &&
           file_contains(PUSHER_GLOBAL_PATH, ". /sbin/global.sh");
}

static int persistence_mode(void) {
    if (wonder_deployed()) return PERSIST_WONDER;
    if (standalone_entry_ready()) return PERSIST_STANDALONE;
    return PERSIST_NONE;
}

static const char *persistence_mode_label(int mode) {
    if (mode == PERSIST_WONDER) return "Wonder 集成模式";
    if (mode == PERSIST_STANDALONE) return "独立 path_sh 模式";
    return "未安装";
}

static int userdata_free_bytes(unsigned long *out) {
    struct statvfs st;
    unsigned long long bytes;

    if (!out || statvfs(USERDATA_DIR, &st) < 0) return -1;
    bytes = (unsigned long long)st.f_bavail * (unsigned long long)st.f_frsize;
    *out = bytes > ULONG_MAX ? ULONG_MAX : (unsigned long)bytes;
    return 0;
}

static int choose_payload_source(char *out, size_t outsz) {
    const char *run_src = getenv("ALICE_PUSHER_RUN_SOURCE");

    if (path_is_regular_readable(run_src)) {
        safe_copy(out, outsz, run_src);
        return 1;
    }
    if (current_exe_path(out, outsz) == 0 &&
        path_is_regular_readable(out))
        return 2;
    errno = ENOENT;
    return 0;
}

static unsigned long file_size_or_zero(const char *path) {
    struct stat st;
    if (!path || stat(path, &st) < 0 || st.st_size < 0)
        return 0;
    return (unsigned long)st.st_size;
}

static int payload_space_ok(const char *source, unsigned long *free_out,
                            unsigned long *required_out) {
    unsigned long free_bytes = 0;
    unsigned long source_size = file_size_or_zero(source);
    unsigned long existing_size = file_size_or_zero(PUSHER_RUN_PATH);
    unsigned long required;

    if (!source_size || userdata_free_bytes(&free_bytes) < 0) {
        set_autostart_error("无法读取 Pushbot payload 或 userdata 可用空间。 ");
        errno = EIO;
        return -1;
    }
    required = source_size + PERSIST_RESERVE_BYTES;
    if (free_out) *free_out = free_bytes;
    if (required_out) *required_out = required;
    if (free_bytes + existing_size < required) {
        set_autostart_error("userdata 空间不足：需要约 %lu KB，可用约 %lu KB。",
                            (required + 1023UL) / 1024UL,
                            (free_bytes + 1023UL) / 1024UL);
        errno = ENOSPC;
        return -1;
    }
    return 0;
}

static int write_text_file(const char *path, const char *text, mode_t mode) {
    char tmp[PATH_MAX];
    int fd;
    int saved_errno;
    int rc = -1;

    if (mkdir_parent_file(path) < 0) return -1;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >=
        (int)sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;
    if (write_all_fd(fd, text, strlen(text)) < 0) goto out;
    if (fsync(fd) < 0) goto out;
    if (close(fd) < 0) {
        fd = -1;
        goto out;
    }
    fd = -1;
    if (chmod(tmp, mode) < 0 || rename(tmp, path) < 0)
        goto out;
    rc = 0;

out:
    saved_errno = errno;
    if (fd >= 0) close(fd);
    if (rc < 0) unlink(tmp);
    errno = saved_errno;
    return rc;
}

static int install_autostart_payload(int *payload_kind) {
    char source[PATH_MAX];
    int source_kind;

    if (payload_kind) *payload_kind = 0;
    source_kind = choose_payload_source(source, sizeof(source));
    if (!source_kind) {
        set_autostart_error("找不到当前 Pushbot 运行包。 ");
        return -1;
    }
    if (payload_space_ok(source, NULL, NULL) < 0)
        return -1;
    remount_userdata_rw();
    if (source_kind == 1) {
        if (copy_regular_file(source, PUSHER_RUN_PATH, 0755) < 0) {
            set_autostart_error("写入 Pushbot .run payload 失败：errno=%d。", errno);
            return -1;
        }
        unlink(PUSHER_BIN_PATH);
        if (payload_kind) *payload_kind = 1;
    } else {
        if (copy_regular_file(source, PUSHER_BIN_PATH, 0755) < 0) {
            set_autostart_error("写入 Pushbot 二进制 payload 失败：errno=%d。", errno);
            return -1;
        }
        unlink(PUSHER_RUN_PATH);
        if (payload_kind) *payload_kind = 2;
    }
    sync();
    return 0;
}

static int write_wonder_startup_script(int port) {
    char script[4096];

    snprintf(script, sizeof(script),
        "#!/bin/sh\n"
        "# generated by alice-pusher-bot-wonder\n"
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin\n"
        "trap '' HUP\n"
        "mount -o remount,exec /tmp 2>/dev/null || true\n"
        "RUN='%s'\n"
        "LOG='%s'\n"
        "trim_log() {\n"
        "    [ -f \"$1\" ] || return 0\n"
        "    size=$(wc -c < \"$1\" 2>/dev/null || echo 0)\n"
        "    [ \"$size\" -le 1024 ] && return 0\n"
        "    tmp=\"$1.trim\"\n"
        "    tail -c 1024 \"$1\" > \"$tmp\" 2>/dev/null || { rm -f \"$tmp\"; return 0; }\n"
        "    cat \"$tmp\" > \"$1\" 2>/dev/null || true\n"
        "    rm -f \"$tmp\"\n"
        "}\n"
        "trim_log \"$LOG\"\n"
        "if ! mkdir /tmp/alice_pusher_wonder_started 2>/dev/null; then\n"
        "    exit 0\n"
        "fi\n"
        "if [ -r \"$RUN\" ]; then\n"
        "    echo \"event=starting mode=wonder port=%d\" >> \"$LOG\"\n"
        "    ALICE_PUSHER_AUTOSTART=1 ALICE_PUSHER_EXTRACT=/tmp/alice-pusher-bot /bin/sh \"$RUN\" -w -L %d >> \"$LOG\" 2>&1 &\n"
        "    echo \"event=started pid=$!\" >> \"$LOG\"\n"
        "    trim_log \"$LOG\"\n"
        "else\n"
        "    echo \"event=missing_payload path=$RUN\" >> \"$LOG\"\n"
        "fi\n"
        "exit 0\n",
        PUSHER_RUN_PATH, PUSHER_START_LOG, port, port);
    if (write_text_file(WONDER_PUSHER_SCRIPT, script, 0755) < 0) {
        set_autostart_error("写入 Wonder 启动项失败：errno=%d。", errno);
        return -1;
    }
    return 0;
}

static int write_standalone_path_sh(int port) {
    char script[4096];

    snprintf(script, sizeof(script),
        "#!/bin/sh\n"
        "%s\n"
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin\n"
        "trap '' HUP\n"
        "mount -o remount,exec /tmp 2>/dev/null || true\n"
        "trim_log() {\n"
        "    [ -f \"$1\" ] || return 0\n"
        "    size=$(wc -c < \"$1\" 2>/dev/null || echo 0)\n"
        "    [ \"$size\" -le 1024 ] && return 0\n"
        "    tmp=\"$1.trim\"\n"
        "    tail -c 1024 \"$1\" > \"$tmp\" 2>/dev/null || { rm -f \"$tmp\"; return 0; }\n"
        "    cat \"$tmp\" > \"$1\" 2>/dev/null || true\n"
        "    rm -f \"$tmp\"\n"
        "}\n"
        "if mkdir '%s' 2>/dev/null; then\n"
        "    RUN='%s'\n"
        "    BIN='%s'\n"
        "    if [ -r \"$RUN\" ]; then\n"
        "        ALICE_PUSHER_AUTOSTART=1 ALICE_PUSHER_EXTRACT=/tmp/alice-pusher-bot /bin/sh \"$RUN\" -w -L %d >> '%s' 2>&1 &\n"
        "    elif [ -x \"$BIN\" ]; then\n"
        "        ALICE_PUSHER_AUTOSTART=1 \"$BIN\" -w -L %d >> '%s' 2>&1 &\n"
        "    else\n"
        "        echo \"missing alice-pusher-bot payload\" >> '%s'\n"
        "    fi\n"
        "fi\n"
        "path_sh=/sbin\n"
        ". /sbin/global.sh\n"
        "path_sh=/sbin\n"
        "%s\n",
        PUSHER_AUTOSTART_BEGIN, PUSHER_PATH_SH_MARKER,
        PUSHER_RUN_PATH, PUSHER_BIN_PATH, port, PUSHER_START_LOG,
        port, PUSHER_START_LOG, PUSHER_START_LOG,
        PUSHER_AUTOSTART_END);
    if (write_text_file(PUSHER_GLOBAL_PATH, script, 0755) < 0) {
        set_autostart_error("写入 Pushbot path_sh wrapper 失败：errno=%d。", errno);
        return -1;
    }
    if (system("nv set path_sh=" PUSHER_DIR " >/tmp/alice_pusher_nv.out 2>&1 && "
               "nv save >>/tmp/alice_pusher_nv.out 2>&1") != 0) {
        set_autostart_error("保存 Pushbot path_sh 入口失败。 ");
        return -1;
    }
    return 0;
}

static int write_pusher_manifest(int mode, int payload_kind, int port) {
    char manifest[1024];

    snprintf(manifest, sizeof(manifest),
             "name=alice-pusher-bot\nversion=2\nmode=%s\n"
             "payload=%s\nstartup=%s\nport=%d\n",
             mode == PERSIST_WONDER ? "wonder" : "standalone",
             payload_kind == 1 ? PUSHER_RUN_PATH : PUSHER_BIN_PATH,
             mode == PERSIST_WONDER ? WONDER_PUSHER_SCRIPT : PUSHER_GLOBAL_PATH,
             port);
    if (write_text_file(PUSHER_MANIFEST_PATH, manifest, 0644) < 0) {
        set_autostart_error("写入 Pushbot manifest 失败：errno=%d。", errno);
        return -1;
    }
    return 0;
}

static void get_autostart_status(autostart_status_t *st) {
    char source[PATH_MAX];
    unsigned long source_size = 0;
    int source_kind;

    memset(st, 0, sizeof(*st));
    st->wonder_detected = wonder_deployed();
    st->mode = persistence_mode();
    st->payload_ready = access(PUSHER_RUN_PATH, R_OK) == 0 ||
                        access(PUSHER_BIN_PATH, X_OK) == 0;
    st->script_ready = st->mode == PERSIST_WONDER ?
        path_is_regular_readable(WONDER_PUSHER_SCRIPT) &&
        file_contains(WONDER_PUSHER_SCRIPT, "generated by alice-pusher-bot-wonder") :
        st->mode == PERSIST_STANDALONE ? standalone_entry_ready() : 0;
    st->entry_ready = st->mode == PERSIST_WONDER ?
        st->wonder_detected && path_is_regular_readable(WONDER_SYSTEM_STARTUP) :
        st->mode == PERSIST_STANDALONE ? standalone_entry_ready() : 0;
    st->installed = st->payload_ready && st->script_ready && st->entry_ready;
    st->startup_running = getenv("ALICE_PUSHER_AUTOSTART") &&
                          strcmp(getenv("ALICE_PUSHER_AUTOSTART"), "1") == 0;
    safe_copy(st->mode_label, sizeof(st->mode_label),
              persistence_mode_label(st->mode));
    if (st->payload_ready) {
        safe_copy(st->payload_path, sizeof(st->payload_path),
                  access(PUSHER_RUN_PATH, R_OK) == 0 ?
                  PUSHER_RUN_PATH : PUSHER_BIN_PATH);
    } else {
        safe_copy(st->payload_path, sizeof(st->payload_path), "-");
    }
    safe_copy(st->script_path, sizeof(st->script_path),
              st->mode == PERSIST_WONDER ? WONDER_PUSHER_SCRIPT :
              st->mode == PERSIST_STANDALONE ? PUSHER_GLOBAL_PATH : "-");
    source_kind = choose_payload_source(source, sizeof(source));
    if (source_kind) source_size = file_size_or_zero(source);
    st->required_bytes = source_size + PERSIST_RESERVE_BYTES;
    userdata_free_bytes(&st->free_bytes);
    safe_copy(st->error, sizeof(st->error), g_autostart_error);
}

static int disable_autostart(void) {
    int rc = 0;
    char path_sh[256];

    remount_userdata_rw();
    if (unlink(WONDER_PUSHER_SCRIPT) < 0 && errno != ENOENT) rc = -1;
    if (unlink(PUSHER_GLOBAL_PATH) < 0 && errno != ENOENT) rc = -1;
    if (unlink(PUSHER_RUN_PATH) < 0 && errno != ENOENT) rc = -1;
    if (unlink(PUSHER_BIN_PATH) < 0 && errno != ENOENT) rc = -1;
    if (unlink(PUSHER_MANIFEST_PATH) < 0 && errno != ENOENT) rc = -1;
    if (unlink(LEGACY_RUN_PATH) < 0 && errno != ENOENT) rc = -1;
    if (unlink(LEGACY_BIN_PATH) < 0 && errno != ENOENT) rc = -1;
    if (unlink(LEGACY_AUTOSTART_SCRIPT) < 0 && errno != ENOENT) rc = -1;
    if (read_nv_path_sh(path_sh, sizeof(path_sh)) == 0 &&
        strcmp(path_sh, PUSHER_DIR) == 0 &&
        system("nv set path_sh=/sbin >/tmp/alice_pusher_nv.out 2>&1 && "
               "nv save >>/tmp/alice_pusher_nv.out 2>&1") != 0)
        rc = -1;
    sync();
    return rc;
}

static int install_persistent_autostart(const web_config_t *cfg) {
    int mode = wonder_deployed() ? PERSIST_WONDER : PERSIST_STANDALONE;
    int payload_kind = 0;
    int port = cfg && cfg->port > 0 ? cfg->port : DEFAULT_WEBUI_PORT;

    g_autostart_error[0] = 0;
    if (install_autostart_payload(&payload_kind) < 0)
        return -1;
    if (mode == PERSIST_WONDER) {
        if (write_wonder_startup_script(port) < 0)
            return -1;
    } else if (write_standalone_path_sh(port) < 0) {
        return -1;
    }
    if (write_pusher_manifest(mode, payload_kind, port) < 0)
        return -1;
    sync();
    return 0;
}

static void load_web_config(web_config_t *cfg) {
    FILE *fp;
    char line[5000];
    int saw_delivery = 0;
    int saw_platform = 0;
    int saw_targets = 0;
    int saw_target_text[ALICE_ENGINE_MAX_TARGETS] = {0};
    int i;

    memset(cfg, 0, sizeof(*cfg));
    cfg->port = DEFAULT_WEBUI_PORT;
    for (i = 0; i < ALICE_ENGINE_MAX_TARGETS; i++)
        init_push_target(&cfg->targets[i], i);
    safe_copy(cfg->delivery, sizeof(cfg->delivery), DELIVERY_WEBHOOK);
    safe_copy(cfg->platform, sizeof(cfg->platform), "dingtalk");
    safe_copy(cfg->target_mode, sizeof(cfg->target_mode), "mifi");
    safe_copy(cfg->target_path, sizeof(cfg->target_path), TARGET_MIFI_PATH);
    safe_copy(cfg->custom_ctype, sizeof(cfg->custom_ctype),
              "application/json;charset=utf-8");
    safe_copy(cfg->custom_body, sizeof(cfg->custom_body),
              "{\"text\":\"{{json_text}}\"}");
    safe_copy(cfg->smtp_port, sizeof(cfg->smtp_port), "587");
    safe_copy(cfg->smtp_security, sizeof(cfg->smtp_security), "starttls");
    cfg->long_sms_reassembly = 1;
    fp = fopen(DEFAULT_CONFIG_PATH, "r");
    if (!fp) return;
    while (fgets(line, sizeof(line), fp)) {
        char *eq;
        strip_line(line);
        eq = strchr(line, '=');
        if (!eq) continue;
        *eq++ = 0;
        if (strcmp(line, "target_count") == 0) {
            long count;
            char *end;
            errno = 0;
            count = strtol(eq, &end, 10);
            if (!errno && end != eq && count >= 0 &&
                count <= ALICE_ENGINE_MAX_TARGETS)
                cfg->target_count = (int)count;
            saw_targets = 1;
        } else {
            int target_index;
            const char *target_field;
            if (target_key_parts(line, &target_index, &target_field)) {
                if (load_target_field(&cfg->targets[target_index],
                                      target_field, eq)) {
                    if (strcmp(target_field, "num") == 0)
                        saw_target_text[target_index] |= 1;
                    else if (strcmp(target_field, "headtxt") == 0)
                        saw_target_text[target_index] |= 2;
                    else if (strcmp(target_field, "tailtxt") == 0)
                        saw_target_text[target_index] |= 4;
                    if (cfg->target_count <= target_index)
                        cfg->target_count = target_index + 1;
                    saw_targets = 1;
                }
                continue;
            }
        }
        if (strcmp(line, "delivery") == 0) {
            safe_copy(cfg->delivery, sizeof(cfg->delivery),
                      normalize_delivery(eq));
            saw_delivery = 1;
        }
        else if (strcmp(line, "webhook") == 0)
            safe_copy(cfg->webhook, sizeof(cfg->webhook), eq);
        else if (strcmp(line, "platform") == 0)
        {
            safe_copy(cfg->platform, sizeof(cfg->platform),
                      normalize_platform(eq));
            saw_platform = 1;
        }
        else if (strcmp(line, "target_mode") == 0)
            safe_copy(cfg->target_mode, sizeof(cfg->target_mode),
                      normalize_target_mode(eq));
        else if (strcmp(line, "target_path") == 0)
            safe_copy(cfg->target_path, sizeof(cfg->target_path), eq);
        else if (strcmp(line, "custom_ctype") == 0)
            safe_copy(cfg->custom_ctype, sizeof(cfg->custom_ctype), eq);
        else if (strcmp(line, "custom_body") == 0)
            config_unescape(cfg->custom_body, sizeof(cfg->custom_body), eq);
        else if (strcmp(line, "num") == 0)
            safe_copy(cfg->num, sizeof(cfg->num), eq);
        else if (strcmp(line, "headtxt") == 0)
            config_unescape(cfg->headtxt, sizeof(cfg->headtxt), eq);
        else if (strcmp(line, "tailtxt") == 0)
            config_unescape(cfg->tailtxt, sizeof(cfg->tailtxt), eq);
        else if (strcmp(line, "smtp_host") == 0)
            config_unescape(cfg->smtp_host, sizeof(cfg->smtp_host), eq);
        else if (strcmp(line, "smtp_port") == 0)
            config_unescape(cfg->smtp_port, sizeof(cfg->smtp_port), eq);
        else if (strcmp(line, "smtp_user") == 0)
            config_unescape(cfg->smtp_user, sizeof(cfg->smtp_user), eq);
        else if (strcmp(line, "smtp_password") == 0)
            config_unescape(cfg->smtp_password, sizeof(cfg->smtp_password), eq);
        else if (strcmp(line, "smtp_from") == 0)
            config_unescape(cfg->smtp_from, sizeof(cfg->smtp_from), eq);
        else if (strcmp(line, "smtp_to") == 0)
            config_unescape(cfg->smtp_to, sizeof(cfg->smtp_to), eq);
        else if (strcmp(line, "smtp_security") == 0)
            safe_copy(cfg->smtp_security, sizeof(cfg->smtp_security),
                      normalize_smtp_security(eq));
        else if (strcmp(line, "port") == 0) {
            long port;
            char *end;
            errno = 0;
            port = strtol(eq, &end, 10);
            if (!errno && end != eq && port > 0 && port <= 65535)
                cfg->port = (int)port;
        }
        else if (strcmp(line, "long_sms_reassembly") == 0)
            cfg->long_sms_reassembly = strcmp(eq, "0") != 0;
    }
    fclose(fp);
    if (!saw_platform) {
        safe_copy(cfg->platform, sizeof(cfg->platform),
                  normalize_platform(detect_platform_from_url(cfg->webhook)));
    }
    if (!saw_delivery) {
        safe_copy(cfg->delivery, sizeof(cfg->delivery),
                  cfg->webhook[0] ? DELIVERY_WEBHOOK :
                  email_configured(cfg) ? DELIVERY_EMAIL : DELIVERY_WEBHOOK);
    }
    safe_copy(cfg->delivery, sizeof(cfg->delivery),
              normalize_delivery(cfg->delivery));
    safe_copy(cfg->target_mode, sizeof(cfg->target_mode),
              normalize_target_mode(cfg->target_mode));
    safe_copy(cfg->smtp_security, sizeof(cfg->smtp_security),
              normalize_smtp_security(cfg->smtp_security));
    if (!cfg->smtp_port[0])
        safe_copy(cfg->smtp_port, sizeof(cfg->smtp_port), "587");
    if (!saw_targets)
        migrate_legacy_targets(cfg);
    if (cfg->target_count < 0 || cfg->target_count > ALICE_ENGINE_MAX_TARGETS)
        cfg->target_count = 0;
    for (i = 0; i < cfg->target_count; i++) {
        if (!(saw_target_text[i] & 1))
            safe_copy(cfg->targets[i].num, sizeof(cfg->targets[i].num), cfg->num);
        if (!(saw_target_text[i] & 2))
            safe_copy(cfg->targets[i].headtxt, sizeof(cfg->targets[i].headtxt),
                      cfg->headtxt);
        if (!(saw_target_text[i] & 4))
            safe_copy(cfg->targets[i].tailtxt, sizeof(cfg->targets[i].tailtxt),
                      cfg->tailtxt);
        normalize_push_target(&cfg->targets[i], i);
        clear_target_inactive_fields(&cfg->targets[i]);
    }
    remove_newlines(cfg->target_path);
    if (!cfg->target_path[0] || strcmp(cfg->target_mode, "custom") != 0)
        safe_copy(cfg->target_path, sizeof(cfg->target_path),
                  target_default_path(cfg->target_mode));
}

static void write_target_config(FILE *fp, int index,
                                const web_push_target_t *target) {
    char esc_name[256];
    char esc_num[512];
    char esc_head[1024];
    char esc_tail[1024];
    char esc_webhook[2048];
    char esc_ctype[512];
    char esc_body[4096];
    char esc_host[512];
    char esc_port[64];
    char esc_user[512];
    char esc_password[512];
    char esc_from[512];
    char esc_to[512];

    config_escape(esc_name, sizeof(esc_name), target->name);
    config_escape(esc_num, sizeof(esc_num), target->num);
    config_escape(esc_head, sizeof(esc_head), target->headtxt);
    config_escape(esc_tail, sizeof(esc_tail), target->tailtxt);
    config_escape(esc_webhook, sizeof(esc_webhook), target->webhook);
    config_escape(esc_ctype, sizeof(esc_ctype), target->custom_ctype);
    config_escape(esc_body, sizeof(esc_body), target->custom_body);
    config_escape(esc_host, sizeof(esc_host), target->smtp_host);
    config_escape(esc_port, sizeof(esc_port), target->smtp_port);
    config_escape(esc_user, sizeof(esc_user), target->smtp_user);
    config_escape(esc_password, sizeof(esc_password), target->smtp_password);
    config_escape(esc_from, sizeof(esc_from), target->smtp_from);
    config_escape(esc_to, sizeof(esc_to), target->smtp_to);
    fprintf(fp, "target_%d_enabled=%d\n", index, target->enabled ? 1 : 0);
    fprintf(fp, "target_%d_name=%s\n", index, esc_name);
    fprintf(fp, "target_%d_num=%s\n", index, esc_num);
    fprintf(fp, "target_%d_headtxt=%s\n", index, esc_head);
    fprintf(fp, "target_%d_tailtxt=%s\n", index, esc_tail);
    fprintf(fp, "target_%d_type=%s\n", index, normalize_target_type(target->type));
    fprintf(fp, "target_%d_platform=%s\n", index, normalize_platform(target->platform));
    fprintf(fp, "target_%d_webhook=%s\n", index, esc_webhook);
    fprintf(fp, "target_%d_custom_ctype=%s\n", index, esc_ctype);
    fprintf(fp, "target_%d_custom_body=%s\n", index, esc_body);
    fprintf(fp, "target_%d_smtp_host=%s\n", index, esc_host);
    fprintf(fp, "target_%d_smtp_port=%s\n", index, esc_port);
    fprintf(fp, "target_%d_smtp_user=%s\n", index, esc_user);
    fprintf(fp, "target_%d_smtp_password=%s\n", index, esc_password);
    fprintf(fp, "target_%d_smtp_from=%s\n", index, esc_from);
    fprintf(fp, "target_%d_smtp_to=%s\n", index, esc_to);
    fprintf(fp, "target_%d_smtp_security=%s\n", index,
            normalize_smtp_security(target->smtp_security));
}

static int save_web_config(const web_config_t *cfg) {
    FILE *fp;
    char esc_head[1024];
    char esc_tail[1024];
    int i;
    int count;

    if (mkdir_parent_file(DEFAULT_CONFIG_PATH) < 0)
        return -1;
    fp = fopen(DEFAULT_CONFIG_PATH, "w");
    if (!fp) return -1;
    config_escape(esc_head, sizeof(esc_head), cfg->headtxt);
    config_escape(esc_tail, sizeof(esc_tail), cfg->tailtxt);
    count = cfg->target_count;
    if (count < 0) count = 0;
    if (count > ALICE_ENGINE_MAX_TARGETS) count = ALICE_ENGINE_MAX_TARGETS;
    fprintf(fp, "target_count=%d\n", count);
    fprintf(fp, "target_mode=%s\n", normalize_target_mode(cfg->target_mode));
    fprintf(fp, "target_path=%s\n", cfg->target_path);
    fprintf(fp, "num=%s\n", count > 0 ? cfg->targets[0].num : cfg->num);
    if (count > 0) {
        config_escape(esc_head, sizeof(esc_head), cfg->targets[0].headtxt);
        config_escape(esc_tail, sizeof(esc_tail), cfg->targets[0].tailtxt);
    }
    fprintf(fp, "headtxt=%s\n", esc_head);
    fprintf(fp, "tailtxt=%s\n", esc_tail);
    fprintf(fp, "port=%d\n", cfg->port > 0 ? cfg->port : DEFAULT_WEBUI_PORT);
    fprintf(fp, "long_sms_reassembly=%d\n", cfg->long_sms_reassembly ? 1 : 0);
    for (i = 0; i < count; i++)
        write_target_config(fp, i, &cfg->targets[i]);
    if (fclose(fp) != 0)
        return -1;
    chmod(DEFAULT_CONFIG_PATH, 0600);
    return 0;
}

static void buf_append(char *buf, size_t bufsz, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void buf_append(char *buf, size_t bufsz, const char *fmt, ...) {
    size_t used;
    va_list ap;

    if (!bufsz) return;
    used = strlen(buf);
    if (used >= bufsz - 1) return;
    va_start(ap, fmt);
    vsnprintf(buf + used, bufsz - used, fmt, ap);
    va_end(ap);
}

static void html_escape(char *out, size_t outsz, const char *in) {
    size_t used = 0;
    if (!outsz) return;
    if (!in) in = "";
    while (*in && used + 1 < outsz) {
        const char *rep = NULL;
        char c = *in++;
        if (c == '&') rep = "&amp;";
        else if (c == '<') rep = "&lt;";
        else if (c == '>') rep = "&gt;";
        else if (c == '"') rep = "&quot;";
        else if (c == '\'') rep = "&#39;";
        if (rep) {
            size_t n = strlen(rep);
            if (used + n >= outsz) break;
            memcpy(out + used, rep, n);
            used += n;
        } else {
            out[used++] = c;
        }
    }
    out[used] = 0;
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

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void url_decode(char *out, size_t outsz, const char *in, size_t inlen) {
    size_t used = 0;
    size_t i;

    if (!outsz) return;
    for (i = 0; i < inlen && used + 1 < outsz; i++) {
        if (in[i] == '+') {
            out[used++] = ' ';
        } else if (in[i] == '%' && i + 2 < inlen) {
            int a = hexval((unsigned char)in[i + 1]);
            int b = hexval((unsigned char)in[i + 2]);
            if (a >= 0 && b >= 0) {
                out[used++] = (char)((a << 4) | b);
                i += 2;
            } else {
                out[used++] = in[i];
            }
        } else {
            out[used++] = in[i];
        }
    }
    out[used] = 0;
}

static int form_value(const char *body, const char *key, char *out, size_t outsz) {
    const char *p = body;
    size_t keylen = strlen(key);

    if (outsz) out[0] = 0;
    while (p && *p) {
        const char *amp = strchr(p, '&');
        const char *eq = strchr(p, '=');
        size_t pair_len = amp ? (size_t)(amp - p) : strlen(p);
        if (eq && eq < p + pair_len &&
            (size_t)(eq - p) == keylen && strncmp(p, key, keylen) == 0) {
            url_decode(out, outsz, eq + 1, pair_len - keylen - 1);
            return 1;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

static int parse_port_text(const char *text, int *port) {
    char *end;
    long value;

    if (!text || !*text)
        return -1;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno || end == text)
        return -1;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
        end++;
    if (*end || value <= 0 || value > 65535)
        return -1;
    *port = (int)value;
    return 0;
}

static void request_webui_restart(int port) {
    g_webui_restart_port = port;
    g_webui_restart_requested = 1;
}

static void restart_webui_process(const char *self_path, int port) {
    pid_t pid = fork();

    if (pid == 0) {
        char port_arg[16];
        const char *self = self_path && self_path[0] ? self_path : "/tmp/alice-pusher-bot";

        snprintf(port_arg, sizeof(port_arg), "%d", port);
        usleep(200000);
        execl(self, self, "-w", "-L", port_arg, (char *)NULL);
        _exit(127);
    }
}

static pid_t read_pid_file(const char *path) {
    FILE *fp = fopen(path, "r");
    long pid = 0;

    if (!fp) return 0;
    fscanf(fp, "%ld", &pid);
    fclose(fp);
    if (pid <= 0 || pid > 999999)
        return 0;
    return (pid_t)pid;
}

static void write_pid_file(const char *path, pid_t pid) {
    FILE *fp = fopen(path, "w");
    if (!fp) return;
    fprintf(fp, "%ld\n", (long)pid);
    fclose(fp);
}

static int process_alive(pid_t pid) {
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    return errno == EPERM;
}

static pid_t service_pid(void) {
    pid_t pid = read_pid_file(DEFAULT_SERVICE_PID);
    int status = 0;

    if (pid > 0 && waitpid(pid, &status, WNOHANG) == pid) {
        unlink(DEFAULT_SERVICE_PID);
        return 0;
    }
    if (!process_alive(pid)) {
        unlink(DEFAULT_SERVICE_PID);
        return 0;
    }
    return pid;
}

static int log_lock_acquire(void) {
    int fd = open(DEFAULT_LOG_LOCK_PATH, O_WRONLY | O_CREAT, 0600);
    struct flock fl;

    pthread_mutex_lock(&g_log_mutex);
    if (fd < 0) {
        pthread_mutex_unlock(&g_log_mutex);
        return -1;
    }
    fchmod(fd, 0600);
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    while (fcntl(fd, F_SETLKW, &fl) < 0) {
        if (errno == EINTR)
            continue;
        close(fd);
        pthread_mutex_unlock(&g_log_mutex);
        return -1;
    }
    return fd;
}

static void log_lock_release(int fd) {
    struct flock fl;

    if (fd < 0)
        return;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fcntl(fd, F_SETLK, &fl);
    close(fd);
    pthread_mutex_unlock(&g_log_mutex);
}

static void trim_log_file_unlocked(void) {
    struct stat st;
    char *buf = NULL;
    int in = -1;
    int out = -1;
    size_t used = 0;
    size_t offset = 0;
    off_t start;

    if (stat(DEFAULT_LOG_PATH, &st) < 0)
        return;
    if (!S_ISREG(st.st_mode) || st.st_size <= (off_t)LOG_RING_MAX)
        return;

    buf = malloc(LOG_RING_MAX);
    if (!buf)
        return;

    in = open(DEFAULT_LOG_PATH, O_RDONLY);
    if (in < 0)
        goto out;
    start = st.st_size - (off_t)LOG_RING_MAX;
    if (lseek(in, start, SEEK_SET) < 0)
        goto out;
    while (used < LOG_RING_MAX) {
        ssize_t n = read(in, buf + used, LOG_RING_MAX - used);
        if (n < 0) {
            if (errno == EINTR) continue;
            goto out;
        }
        if (n == 0)
            break;
        used += (size_t)n;
    }
    if (used > 0) {
        char *nl = memchr(buf, '\n', used);
        if (nl && (size_t)(nl - buf + 1) < used)
            offset = (size_t)(nl - buf + 1);
    }
    close(in);
    in = -1;

    out = open(DEFAULT_LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0)
        goto out;
    fchmod(out, 0600);
    if (used > offset)
        write_all_fd(out, buf + offset, used - offset);

out:
    if (in >= 0) close(in);
    if (out >= 0) close(out);
    free(buf);
}

static void trim_log_file(void) {
    int lock_fd = log_lock_acquire();

    if (lock_fd < 0)
        return;
    trim_log_file_unlocked();
    log_lock_release(lock_fd);
}

static void ring_log_append(const char *fmt, ...) {
    char msg[1024];
    char line[1280];
    char ts[32];
    time_t now;
    struct tm tmv;
    va_list ap;
    int fd;
    int len;
    int lock_fd;
    size_t line_len;

    if (!fmt)
        return;

    now = time(NULL);
    if (localtime_r(&now, &tmv))
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
    else
        safe_copy(ts, sizeof(ts), "0000-00-00 00:00:00");

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    len = snprintf(line, sizeof(line), "[%s] %s\n", ts, msg);
    if (len < 0)
        return;
    if (len >= (int)sizeof(line)) {
        line[sizeof(line) - 2] = '\n';
        line[sizeof(line) - 1] = 0;
        line_len = sizeof(line) - 1;
    } else {
        line_len = (size_t)len;
    }

    lock_fd = log_lock_acquire();
    if (lock_fd < 0)
        return;

    fd = open(DEFAULT_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        log_lock_release(lock_fd);
        return;
    }
    fchmod(fd, 0600);
    write_all_fd(fd, line, line_len);
    close(fd);
    trim_log_file_unlocked();
    log_lock_release(lock_fd);
}

static void engine_ring_log_callback(void *ctx, const char *line) {
    (void)ctx;
    ring_log_append("%s", line ? line : "");
}

static int clear_log_file(void) {
    int lock_fd = log_lock_acquire();
    int fd;

    if (lock_fd < 0)
        return -1;
    fd = open(DEFAULT_LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        log_lock_release(lock_fd);
        return -1;
    }
    fchmod(fd, 0600);
    close(fd);
    log_lock_release(lock_fd);
    return 0;
}

static void cleanup_strace_child(void) {
    web_config_t cfg;
    char target_path[256];

    load_web_config(&cfg);
    resolve_target_path(&cfg, target_path, sizeof(target_path));
    alice_engine_cleanup_strace_child(target_path);
}

static int stop_service(void) {
    pid_t pid = read_pid_file(DEFAULT_SERVICE_PID);
    int i;

    if (!process_alive(pid)) {
        unlink(DEFAULT_SERVICE_PID);
        ring_log_append("[WEBUI] stop requested, service already stopped");
        return 0;
    }
    ring_log_append("[WEBUI] stopping service pid=%ld", (long)pid);
    kill(pid, SIGTERM);
    for (i = 0; i < 30; i++) {
        if (!process_alive(pid)) {
            unlink(DEFAULT_SERVICE_PID);
            ring_log_append("[WEBUI] service stopped pid=%ld", (long)pid);
            return 0;
        }
        usleep(100 * 1000);
    }
    kill(pid, SIGKILL);
    usleep(200 * 1000);
    cleanup_strace_child();
    unlink(DEFAULT_SERVICE_PID);
    ring_log_append("[WEBUI] service killed pid=%ld", (long)pid);
    return 0;
}

static int start_service(const char *self_path, const web_config_t *cfg) {
    pid_t pid;
    char target_path_for_log[256];

    (void)self_path;
    if (!any_target_configured(cfg)) {
        errno = EINVAL;
        ring_log_append("[WEBUI] service start failed: no push target configured");
        return -1;
    }
    if (service_pid() > 0) {
        ring_log_append("[WEBUI] start requested, service already running");
        return 0;
    }

    resolve_target_path(cfg, target_path_for_log, sizeof(target_path_for_log));
    trim_log_file();

    pid = fork();
    if (pid < 0) {
        ring_log_append("[WEBUI] service start failed: fork error errno=%d", errno);
        return -1;
    }
    if (pid == 0) {
        alice_engine_service_config_t engine_cfg;
        alice_engine_push_target_t engine_targets[ALICE_ENGINE_MAX_TARGETS];
        char target_path[256];
        int rc;

        signal(SIGCHLD, SIG_DFL);
        signal(SIGHUP, SIG_IGN);
        setsid();

        resolve_target_path(cfg, target_path, sizeof(target_path));
        alice_engine_set_log_callback(engine_ring_log_callback, NULL);
        ring_log_append("[WEBUI] service child started target=%s platform=%s",
                        target_path, configured_platform_label(cfg));
        memset(&engine_cfg, 0, sizeof(engine_cfg));
        engine_cfg.target_path = target_path;
        engine_cfg.num = cfg->num;
        engine_cfg.headtxt = cfg->headtxt;
        engine_cfg.tailtxt = cfg->tailtxt;
        engine_cfg.targets = engine_targets;
        engine_cfg.target_count = build_engine_target_list(
            cfg, engine_targets, ALICE_ENGINE_MAX_TARGETS);
        engine_cfg.long_sms_reassembly = cfg->long_sms_reassembly ? 1 : 0;
        rc = alice_engine_start_service(&engine_cfg);
        _exit(rc == 0 ? 0 : 1);
    }
    write_pid_file(DEFAULT_SERVICE_PID, pid);
    ring_log_append("[WEBUI] service started pid=%ld target=%s platform=%s",
                    (long)pid, target_path_for_log,
                    configured_platform_label(cfg));
    return 0;
}

static void read_log_tail(char *out, size_t outsz) {
	FILE *fp;
	long size;
	long start = 0;
	size_t n;
    size_t limit;
    int lock_fd;

    if (outsz) out[0] = 0;
    if (outsz <= 1)
        return;
    limit = outsz - 1;
    if (limit > LOG_RING_MAX)
        limit = LOG_RING_MAX;
    lock_fd = log_lock_acquire();
    if (lock_fd < 0)
        return;
    trim_log_file_unlocked();
    fp = fopen(DEFAULT_LOG_PATH, "r");
    if (!fp) {
        log_lock_release(lock_fd);
        return;
    }
    if (fseek(fp, 0, SEEK_END) == 0) {
        size = ftell(fp);
        if (size > (long)limit)
            start = size - (long)limit;
        fseek(fp, start, SEEK_SET);
    }
	n = fread(out, 1, limit, fp);
	if (outsz) out[n] = 0;
	fclose(fp);
    log_lock_release(lock_fd);
}

static void resolve_self_path(char *out, size_t outsz, const char *argv0) {
	ssize_t n;

	if (!outsz) return;
	out[0] = 0;
	n = readlink("/proc/self/exe", out, outsz - 1);
	if (n > 0) {
		out[n] = 0;
		return;
	}
	if (argv0 && argv0[0] == '/') {
		safe_copy(out, outsz, argv0);
		return;
	}
	if (argv0 && strchr(argv0, '/')) {
		char cwd[512];
		if (getcwd(cwd, sizeof(cwd))) {
			snprintf(out, outsz, "%s/%s", cwd, argv0);
			return;
		}
	}
	safe_copy(out, outsz, argv0 ? argv0 : "alice-pusher-bot");
}

static int send_all_plain(int fd, const char *buf, size_t len) {
	while (len) {
		ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static void http_send(int fd, int code, const char *status,
                      const char *ctype, const char *body) {
    char header[256];
    size_t body_len = strlen(body);
    int len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n"
        "\r\n",
        code, status, ctype, (unsigned long)body_len);
    if (len > 0)
        send_all_plain(fd, header, (size_t)len);
    send_all_plain(fd, body, body_len);
}

static void http_send_data(int fd, int code, const char *status,
                           const char *ctype, const unsigned char *data,
                           size_t data_len, const char *cache) {
    char header[320];
    int len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "Cache-Control: %s\r\n"
        "\r\n",
        code, status, ctype, (unsigned long)data_len,
        cache ? cache : "no-store");
    if (len > 0)
        send_all_plain(fd, header, (size_t)len);
    send_all_plain(fd, (const char *)data, data_len);
}

static void http_send_download(int fd, const char *ctype, const char *filename,
                               const char *body, size_t body_len) {
    char header[384];
    int len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lu\r\n"
        "Content-Disposition: attachment; filename=\"%s\"\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n"
        "\r\n",
        ctype, (unsigned long)body_len, filename);
    if (len > 0)
        send_all_plain(fd, header, (size_t)len);
    if (body_len)
        send_all_plain(fd, body, body_len);
}

static void append_page_start(char *body, size_t bodysz, const char *active,
                              const char *title, const char *subtitle,
                              const char *message) {
    char esc_msg[1024];
    const char *msg_class = "";
    if (message && message[0])
        html_escape(esc_msg, sizeof(esc_msg), message);
    else
        esc_msg[0] = 0;
    if (message && (strstr(message, "失败") || strstr(message, "无效") ||
                    strstr(message, "错误")))
        msg_class = " error";
    buf_append(body, bodysz,
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>%s - Alice Pusher</title><style>"
        "*{box-sizing:border-box}body{margin:0;font-family:Arial,'Microsoft YaHei',sans-serif;background:#f4f8f2;color:#18251d}a{color:inherit;text-decoration:none}"
        "@keyframes rise{from{opacity:.62;transform:translateY(7px)}to{opacity:1;transform:none}}"
        ".shell{min-height:100vh;display:grid;grid-template-columns:218px minmax(0,1fr)}.side{position:sticky;top:0;height:100vh;background:#fbfdf9;border-right:1px solid #dbe8dc;padding:18px 14px;display:flex;flex-direction:column;gap:16px}"
        ".brand{font-size:19px;font-weight:800}.sub,.hint{font-size:12px;color:#67786b;margin-top:3px;line-height:1.45}.nav{display:flex;flex-direction:column;gap:6px}.nav a{border-radius:8px;padding:10px 11px;color:#405246;font-size:14px;font-weight:700}.nav a.active,.nav a:hover{background:#dcefe2;color:#1e5e3a}.sidecard{margin-top:auto;border:1px solid #dbe8dc;border-radius:8px;background:#fff;padding:12px}"
        ".pill{display:inline-block;border-radius:999px;padding:6px 10px;background:#2f7d4f;color:#fff;font-size:13px;font-weight:800;white-space:nowrap}.pill.off{background:#7b8a80}"
        "main.page{max-width:1120px;width:100%%;margin:0 auto;padding:22px}.topline{display:flex;justify-content:space-between;gap:14px;margin-bottom:16px}.h1{font-size:25px;font-weight:800}.msg{background:#eef8f0;border:1px solid #c9dfd0;border-radius:8px;color:#235a39;padding:12px 14px;margin-bottom:14px;animation:rise .18s ease-out}.msg.error{background:#fff0ef;border-color:#e6aaa5;color:#a12620}"
        ".grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.panel{background:#fff;border:1px solid #d9e5dc;border-radius:8px;margin-bottom:14px;box-shadow:0 5px 16px rgba(24,37,29,.045);overflow:hidden;animation:rise .22s ease-out}.formtop{border-bottom:1px solid #e7eee8;padding:14px 16px}.title{font-size:16px;font-weight:800}.pad{padding:16px}.kv{border-bottom:1px solid #edf2ee;padding:8px 0}.k{font-size:12px;color:#6d7b71}.v{font-size:14px;font-weight:800;word-break:break-all;margin-top:3px}"
        "label{display:block;font-size:13px;font-weight:800;margin:11px 0 5px}input,textarea,select{width:100%%;border:1px solid #b8c7bb;border-radius:6px;padding:9px 10px;font-size:14px;background:#fff;outline:none}input,select{height:40px}textarea{min-height:84px;resize:vertical}input:focus,textarea:focus,select:focus{border-color:#2f7d4f;box-shadow:0 0 0 3px #dfeee5}.fieldrow{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center}.fieldrow button{margin:0}.hint.ok{color:#236a40}.hint.warn{color:#9a5a10}"
        ".custombox{display:none;margin-top:10px;padding:12px;border:1px solid #e0eadf;border-radius:8px;background:#fbfdf9;animation:rise .18s ease-out}.custombox.show{display:block}.conditionalbox{display:none;margin-top:10px}.conditionalbox.show{display:block}.editorsection{padding:0 16px 16px}.editorsection+.editorsection{border-top:1px solid #e7eee8;padding-top:16px}.targetpanel{display:none}.targetpanel.show{display:block}.targetgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 12px}.targetwide{grid-column:1/-1}.sectionhead{border-top:1px solid #e7eee8;margin-top:16px;padding-top:14px}.sectionhead:first-child{border-top:0;margin-top:0;padding-top:0}.sectiontitle{font-size:14px;font-weight:800}.sectionhint{font-size:12px;color:#67786b;margin-top:3px;line-height:1.45}.startuptable{width:100%%;border-collapse:collapse;min-width:780px}.startuptable th{padding:9px 10px;text-align:left;border-bottom:1px solid #b8c9ba;color:#4d6353;font-size:12px;white-space:nowrap}.startuptable td{padding:10px;border-bottom:1px solid #e7eee8;vertical-align:top;font-size:13px}.startuptable tbody tr:hover{background:#fbfdf9}.startuptable .hint{margin-top:4px}.status{display:inline-block;border-radius:999px;padding:5px 9px;background:#eef2ef;color:#58675c;font-size:12px;font-weight:800;white-space:nowrap}.status.ok{background:#e2f2e6;color:#236a40}.status.warn{background:#fff0dc;color:#9a5a10}.status.off{background:#edf0ed;color:#68786d}.rowactions{display:flex;gap:6px;flex-wrap:wrap;margin:0}.rowactions form{margin:0}.rowactions button{height:32px;padding:0 11px;font-size:12px}.emptyrow{text-align:center;color:#68786d}.targetbar{display:flex;align-items:center;justify-content:space-between;gap:8px}.targetstatus{font-size:12px;color:#68786d}.targetstatus.ok{color:#236a40}.targetstatus.warn{color:#9a5a10}"
        ".actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:14px}button,.button{height:40px;border:1px solid #2f7d4f;border-radius:6px;background:#2f7d4f;color:#fff;font-size:14px;font-weight:800;padding:0 17px;cursor:pointer}.button{display:inline-flex;align-items:center;justify-content:center}button.alt,.button.alt{background:#fff;color:#2f7d4f}button.testbutton{background:#d99a18;border-color:#c2870d;color:#fff}button.warn,.button.warn{background:#fff0ef;border-color:#d67d77;color:#a12620}button:disabled{opacity:.45;cursor:not-allowed}pre,.preview{white-space:pre-wrap;word-break:break-word;background:#101811;color:#d9f5df;border-radius:8px;padding:12px;max-height:520px;overflow:auto}.preview{margin-top:8px;min-height:116px;color:#e3f8e7}"
        ".templates{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.tpl{border:1px solid #e0eadf;border-radius:8px;background:#fbfdf9;padding:12px}.tplname{font-size:14px;font-weight:800}.tpltext{font-size:12px;color:#56695e;line-height:1.6;margin-top:5px;word-break:break-all}.tplcode{font-family:monospace;background:#eef6ef;border-radius:6px;padding:5px 6px;color:#234732}"
        ".about{display:grid;grid-template-columns:148px minmax(0,1fr);gap:18px;align-items:center}.avatar{width:132px;height:132px;border-radius:8px;object-fit:cover;border:1px solid #d9e5dc;box-shadow:0 8px 22px rgba(24,37,29,.08)}.aboutname{font-size:20px;font-weight:800;margin-bottom:7px}.signature{margin-top:13px;color:#2f5f40;font-size:15px;font-weight:800;line-height:1.7}.repo{display:inline-block;margin-top:13px;color:#1f6d42;font-weight:800;word-break:break-all}.labelrow{margin-top:13px;color:#5f7166;font-size:13px;font-weight:800}.labelrow .repo{margin-top:0}.supporthead{display:block}.supportdesc{color:#405246;font-size:14px;font-weight:700;line-height:1.75;margin-top:7px}.supportgrid{display:grid;grid-template-columns:220px minmax(0,1fr);gap:14px;align-items:stretch}.supportcard{border:1px solid #e0eadf;border-radius:8px;background:#fbfdf9;padding:14px;min-width:0}.supporttitle{font-size:15px;font-weight:800;margin-bottom:7px}.plainlink{display:inline-block;color:#1f6d42;font-weight:800;word-break:break-all}.qrbox{display:flex;justify-content:center;align-items:center}.qr{display:block;width:100%%;max-width:190px;height:auto;border-radius:8px;border:1px solid #e5dff0;background:#fff;box-shadow:0 8px 18px rgba(24,37,29,.06)}"
        "@media(max-width:820px){.shell{display:block}.side{position:static;height:auto;border-right:0;border-bottom:1px solid #dbe8dc}.nav{flex-direction:row;overflow:auto}.sidecard{display:none}main.page{padding:16px}.grid,.about,.supportgrid,.templates,.targetgrid{grid-template-columns:1fr}.startuptable{min-width:700px}.rowactions{flex-direction:column;align-items:stretch}.rowactions button{width:100%%}.topline{display:block}.qr{max-width:220px}}"
        "</style></head><body><div class=\"shell\"><aside class=\"side\">"
        "<div><div class=\"brand\">Alice Pusher</div><div class=\"sub\">短信推送控制台</div></div>"
        "<nav class=\"nav\"><a class=\"%s\" href=\"/\">控制台</a><a class=\"%s\" href=\"/config\">配置</a><a class=\"%s\" href=\"/logs\">运行日志</a><a class=\"%s\" href=\"/experimental\">实验功能</a><a class=\"%s\" href=\"/about\">关于</a></nav>"
        "<div class=\"sidecard\"><div class=\"hint\">WebUI</div><div class=\"pill\">%d</div></div></aside><main class=\"page\">"
        "<div class=\"topline\"><div><div class=\"h1\">%s</div><div class=\"hint\">%s</div></div></div>",
        title,
        strcmp(active, "home") == 0 ? "active" : "",
        strcmp(active, "config") == 0 ? "active" : "",
        strcmp(active, "logs") == 0 ? "active" : "",
        strcmp(active, "experimental") == 0 ? "active" : "",
        strcmp(active, "about") == 0 ? "active" : "",
        g_webui_port, title, subtitle);
    if (esc_msg[0])
        buf_append(body, bodysz, "<div class=\"msg%s\">%s</div>",
                   msg_class, esc_msg);
}

static void append_page_end(char *body, size_t bodysz) {
    buf_append(body, bodysz,
        "</main></div><script>"
        "function targetValue(i,n){var e=document.getElementById('target_'+i+'_'+n);return e?e.value:'';}"
        "function targetCount(){var e=document.getElementById('targetCount');return e?parseInt(e.value||'0',10):0;}"
        "function targetIndex(){var e=document.getElementById('targetIndex');return e?parseInt(e.value||'0',10):0;}"
        "function toggleTargetType(i){var email=targetValue(i,'type')==='email',w=document.getElementById('target_'+i+'_webhook_fields'),e=document.getElementById('target_'+i+'_email_fields'),c=document.getElementById('target_'+i+'_custom_fields'),p=targetValue(i,'platform');if(w)w.className=email?'conditionalbox':'conditionalbox show';if(e)e.className=email?'conditionalbox show':'conditionalbox';if(c)c.className=!email&&p==='custom'?'conditionalbox show':'conditionalbox';}"
        "function toggleTargetProcess(){var s=document.getElementById('targetModeSelect'),b=document.getElementById('targetCustomFields');if(!s||!b)return;b.className=s.value==='custom'?'conditionalbox show':'conditionalbox';}"
        "function fetchMsisdn(b){var i=document.getElementById('numInput'),m=document.getElementById('numMsg');"
        "if(m){m.textContent='正在读取 nv show...';m.className='hint';}"
        "if(b){b.disabled=true;b.textContent='获取中';}"
        "fetch('/msisdn',{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){"
        "if(i&&j.num){i.value=j.num;i.focus();updatePreview();if(m){m.textContent='已读取手机号。';m.className='hint ok';}}"
        "else{if(m){m.textContent='未从 nv show 读取到手机号，请手动填写或留空。';m.className='hint warn';}}"
        "}).catch(function(){if(m){m.textContent='读取失败，请检查设备是否支持 nv show。';m.className='hint warn';}})"
        ".finally(function(){if(b){b.disabled=false;b.textContent='获取';}});}"
        "function enc(s){return encodeURIComponent(s).replace(/[!'()*]/g,function(c){return '%%'+c.charCodeAt(0).toString(16).toUpperCase();});}"
        "function jesc(s){return JSON.stringify(s||'').slice(1,-1);}"
        "function barkKey(u){var s=(u||''),i=s.indexOf('://');if(i>=0)s=s.slice(i+3);i=s.indexOf('/');if(i<0)return '';s=s.slice(i+1);if(!s||s.indexOf('push')===0)return '';return s.split(/[/?#]/)[0];}"
        "function sampleText(){var n=document.getElementById('numInput'),num=n&&n.value?n.value:'N/A';return '接收短信设备手机号:'+num+'\\n[pdu解码后的信息]\\n短消息服务中心:+8613800755500\\n发件人:10086\\n时间戳:26/06/30 12:00:00\\n短信内容:Alice Pusher Bot 示例短信';}"
        "function updatePreview(){var h=document.getElementById('headInput'),t=document.getElementById('tailInput'),p=document.getElementById('msgPreview'),i=targetIndex();if(!p)return;var a=[],text,plat=targetValue(i,'platform'),type=targetValue(i,'type'),ctype='application/json;charset=utf-8',payload='',jt,key,tmpl;if(h&&h.value)a.push(h.value);a.push(sampleText());if(t&&t.value)a.push(t.value);text=a.join('\\n');if(type==='email'){p.textContent='任务: '+(targetValue(i,'name')||('任务 '+(i+1)))+'\\n\\n最终文本:\\n'+text+'\\n\\n邮箱服务器:\\n'+(targetValue(i,'smtp_host')||'未配置')+':'+(targetValue(i,'smtp_port')||'587')+'\\n安全模式:\\n'+(targetValue(i,'smtp_security')||'starttls')+'\\n发件人:\\n'+(targetValue(i,'smtp_from')||'未配置')+'\\n收件人:\\n'+(targetValue(i,'smtp_to')||'未配置');return;}var w=targetValue(i,'webhook'),ct=targetValue(i,'custom_ctype'),cb=targetValue(i,'custom_body');if(!w){p.textContent='任务: '+(targetValue(i,'name')||('任务 '+(i+1)))+'\\n\\n最终文本:\\n'+text+'\\n\\n推送方式:\\nWebhook\\n\\n请填写 Webhook URL';return;}if(plat==='serverchan'){ctype='application/x-www-form-urlencoded';payload='title=Alice%%20Pusher&desp='+enc(text);}else if(plat==='telegram'){ctype='application/x-www-form-urlencoded';payload='text='+enc(text);}else if(plat==='custom'){ctype=ct||'application/json;charset=utf-8';tmpl=cb||'{\"text\":\"{{json_text}}\"}';payload=tmpl.split('{{json_text}}').join(jesc(text)).split('{{url_text}}').join(enc(text)).split('{{text}}').join(text);}else{jt=jesc(text);if(plat==='feishu')payload='{\"msg_type\":\"text\",\"content\":{\"text\":\"'+jt+'\"}}';else if(plat==='discord')payload='{\"content\":\"'+jt+'\"}';else if(plat==='bark'){key=barkKey(w);payload=key?'{\"title\":\"Alice Pusher\",\"body\":\"'+jt+'\",\"device_key\":\"'+jesc(key)+'\"}':'需要填写 Bark URL 以提取 device_key';}else payload='{\"msgtype\":\"text\",\"text\":{\"content\":\"'+jt+'\"}}';}p.textContent='任务: '+(targetValue(i,'name')||('任务 '+(i+1)))+'\\n\\n最终文本:\\n'+text+'\\n\\nContent-Type:\\n'+ctype+'\\n\\nPayload:\\n'+payload;}"
        "toggleTargetProcess();if(targetCount()>0){toggleTargetType(targetIndex());updatePreview();}"
        "</script></body></html>");
}

static void render_home(int fd, const char *message) {
    web_config_t cfg;
    autostart_status_t ast;
    char *body = calloc(1, WEB_BODY_MAX);
    pid_t spid, strpid;
    int target_pid;
    char target_path[256];
    char esc_num[256], esc_delivery[128], esc_platform[128];
    char esc_target_label[128], esc_target_path[512];
    char esc_auto_mode[128], esc_auto_payload[512], esc_auto_script[512];
    char esc_auto_error[512];
    char delivery_summary[128];
    const char *auto_label;
    const char *auto_detail;
    const char *auto_payload;

    if (!body) {
        http_send(fd, 500, "Internal Server Error", "text/plain", "out of memory\n");
        return;
    }
    load_web_config(&cfg);
    get_autostart_status(&ast);
    spid = service_pid();
    strpid = alice_engine_get_strace_pid();
    if (!process_alive(strpid)) strpid = 0;
    resolve_target_path(&cfg, target_path, sizeof(target_path));
    target_pid = alice_engine_find_process_by_exe_path(target_path);
    html_escape(esc_num, sizeof(esc_num), cfg.num[0] ? cfg.num : "-");
    html_escape(esc_platform, sizeof(esc_platform), configured_platform_label(&cfg));
    snprintf(delivery_summary, sizeof(delivery_summary), "%d / %d 个任务",
             enabled_target_count(&cfg), cfg.target_count);
    html_escape(esc_delivery, sizeof(esc_delivery), delivery_summary);
    html_escape(esc_target_label, sizeof(esc_target_label),
                target_mode_label(cfg.target_mode));
    html_escape(esc_target_path, sizeof(esc_target_path), target_path);
    if (ast.payload_ready)
        auto_payload = ast.payload_path;
    else
        auto_payload = "待安装";
    if (ast.installed && ast.startup_running) {
        auto_label = "自启动已成功";
        auto_detail = "当前 WebUI 实例由持久化启动项拉起";
    } else if (ast.installed) {
        auto_label = "已安装，等待开机";
        auto_detail = "持久化启动项和 payload 已就绪";
    } else if (ast.script_ready || ast.payload_ready) {
        auto_label = "未完整安装";
        auto_detail = ast.error[0] ? ast.error : "payload 或启动项不完整";
    } else {
        auto_label = "未启用";
        auto_detail = "点击安装会根据 Wonder 部署状态选择启动模式";
    }
    html_escape(esc_auto_mode, sizeof(esc_auto_mode), ast.mode_label);
    html_escape(esc_auto_payload, sizeof(esc_auto_payload), auto_payload);
    html_escape(esc_auto_script, sizeof(esc_auto_script), ast.script_path);
    html_escape(esc_auto_error, sizeof(esc_auto_error),
                ast.error[0] ? ast.error : "-");

    append_page_start(body, WEB_BODY_MAX, "home", "控制台",
                      "管理短信推送服务、strace 状态和测试推送", message);
    buf_append(body, WEB_BODY_MAX,
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">运行状态</div></div><div class=\"pad\"><div class=\"grid\">"
        "<div class=\"kv\"><div class=\"k\">服务状态</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">服务 PID</div><div class=\"v\">%ld</div></div>"
        "<div class=\"kv\"><div class=\"k\">strace PID</div><div class=\"v\">%ld</div></div>"
        "<div class=\"kv\"><div class=\"k\">短信进程</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">进程路径</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">短信进程 PID</div><div class=\"v\">%d</div></div>"
        "<div class=\"kv\"><div class=\"k\">推送平台</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">启用任务</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">设备手机号</div><div class=\"v\">%s</div></div>"
        "</div><div class=\"actions\">"
        "<form method=\"post\" action=\"/start\"><button type=\"submit\">启动服务</button></form>"
        "<form method=\"post\" action=\"/stop\"><button class=\"alt\" type=\"submit\">停止服务</button></form>"
        "<form method=\"post\" action=\"/restart\"><button class=\"alt\" type=\"submit\">重启服务</button></form>"
        "</div></div></section>"
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">测试推送</div></div><div class=\"pad\"><form method=\"post\" action=\"/test\">"
        "<label>测试消息</label><textarea name=\"txt\">Alice Pusher Bot 测试消息</textarea>"
        "<div class=\"actions\"><button type=\"submit\">发送测试消息</button></div></form></div></section>"
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">开机自启动</div></div><div class=\"pad\"><div class=\"grid\">"
        "<div class=\"kv\"><div class=\"k\">状态</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">说明</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">持久化模式</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">Wonder 检测</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">Payload</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">启动项脚本</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">脚本状态</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">安装错误</div><div class=\"v\">%s</div></div>"
        "</div><div class=\"actions\">"
        "<form method=\"post\" action=\"/autostart_on\"><button type=\"submit\"%s>安装自启动</button></form>"
        "<form method=\"post\" action=\"/autostart_off\"><button class=\"alt\" type=\"submit\"%s>卸载自启动</button></form>"
        "</div><div class=\"hint\">当前入口只使用 userdata；不会修改 rootfs 或 /etc/rc。</div></div></section>",
        spid > 0 ? "运行中" : "未运行", (long)spid, (long)strpid,
        esc_target_label, esc_target_path, target_pid > 0 ? target_pid : 0,
        esc_platform, esc_delivery, esc_num,
        auto_label, auto_detail, esc_auto_mode,
        ast.wonder_detected ? "已部署" : "未部署",
        esc_auto_payload, esc_auto_script,
        ast.script_ready && ast.entry_ready ? "可正常启动" : "未就绪",
        esc_auto_error,
        ast.installed ? " disabled" : "",
        (ast.payload_ready || ast.script_ready) ? "" : " disabled");
    append_page_end(body, WEB_BODY_MAX);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", body);
    free(body);
}

#if 0
static void render_config_legacy(int fd, const char *message) {
    web_config_t cfg;
    char *body = calloc(1, WEB_BODY_MAX);
    char *custom_body = calloc(1, 12288);
    char webhook[2048], num[256], head[1024], tail[1024];
    char smtp_host[512], smtp_port[64], smtp_user[512];
    char smtp_password[512], smtp_from[512], smtp_to[512];
    char target_path[512];
    char sample_body[1024], sample_final[2048], sample_payload[4096];
    char sample_ctype[160], sample_preview[8192], sample_preview_esc[20000];
    char custom_ctype[256];
    int port;

    if (!body || !custom_body) {
        free(body);
        free(custom_body);
        http_send(fd, 500, "Internal Server Error", "text/plain", "out of memory\n");
        return;
    }
    load_web_config(&cfg);
    html_escape(webhook, sizeof(webhook), cfg.webhook);
    html_escape(num, sizeof(num), cfg.num);
    html_escape(head, sizeof(head), cfg.headtxt);
    html_escape(tail, sizeof(tail), cfg.tailtxt);
    html_escape(target_path, sizeof(target_path), cfg.target_path);
    html_escape(custom_ctype, sizeof(custom_ctype), cfg.custom_ctype);
    html_escape(custom_body, 12288, cfg.custom_body);
    html_escape(smtp_host, sizeof(smtp_host), cfg.smtp_host);
    html_escape(smtp_port, sizeof(smtp_port), cfg.smtp_port);
    html_escape(smtp_user, sizeof(smtp_user), cfg.smtp_user);
    html_escape(smtp_password, sizeof(smtp_password), cfg.smtp_password);
    html_escape(smtp_from, sizeof(smtp_from), cfg.smtp_from);
    html_escape(smtp_to, sizeof(smtp_to), cfg.smtp_to);
    snprintf(sample_body, sizeof(sample_body),
             "接收短信设备手机号:%s\n[pdu解码后的信息]\n短消息服务中心:+8613800755500\n发件人:10086\n时间戳:26/06/30 12:00:00\n短信内容:Alice Pusher Bot 示例短信",
             cfg.num[0] ? cfg.num : "N/A");
    alice_engine_build_push_message(sample_final, sizeof(sample_final),
                       cfg.headtxt, sample_body, cfg.tailtxt);
    if (!delivery_is_email(&cfg) && cfg.webhook[0] &&
        alice_engine_build_webhook_payload(cfg.webhook, cfg.platform, sample_final,
                                  cfg.custom_ctype, cfg.custom_body,
                                  sample_payload, sizeof(sample_payload),
                                  sample_ctype, sizeof(sample_ctype)) == 0) {
        /* Keep the webhook preview when a webhook is configured. */
    } else if (delivery_is_email(&cfg) && email_configured(&cfg)) {
        safe_copy(sample_ctype, sizeof(sample_ctype), "SMTP message/rfc822");
        snprintf(sample_payload, sizeof(sample_payload),
                 "服务器: %s:%s\n安全模式: %s\n发件人: %s\n收件人: %s\n\n%s",
                 cfg.smtp_host, cfg.smtp_port,
                 normalize_smtp_security(cfg.smtp_security),
                 cfg.smtp_from, cfg.smtp_to, sample_final);
    } else {
        safe_copy(sample_ctype, sizeof(sample_ctype), "-");
        safe_copy(sample_payload, sizeof(sample_payload),
                  "请选择 Webhook 或邮箱，并完成对应配置。");
    }
    snprintf(sample_preview, sizeof(sample_preview),
             "最终文本:\n%s\n\nContent-Type:\n%s\n\nPayload:\n%s",
             sample_final, sample_ctype, sample_payload);
    html_escape(sample_preview_esc, sizeof(sample_preview_esc), sample_preview);
    port = cfg.port > 0 ? cfg.port : DEFAULT_WEBUI_PORT;
    append_page_start(body, WEB_BODY_MAX, "config", "配置",
                      "选择 Webhook 或邮箱作为短信推送方式", message);
    buf_append(body, WEB_BODY_MAX,
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">WebUI 设置</div></div><div class=\"pad\">"
        "<form method=\"post\" action=\"/set_port\">"
        "<label>WebUI 端口</label><input name=\"port\" value=\"%d\" inputmode=\"numeric\" pattern=\"[0-9]*\" required>"
        "<div class=\"actions\"><button type=\"submit\">保存并切换端口</button></div>"
        "</form><div class=\"hint\">端口默认保存到 " DEFAULT_CONFIG_PATH "。修改后 WebUI 会立即切换到新端口。</div>"
        "</div></section>"
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">推送配置</div></div><div class=\"pad\">"
        "<form method=\"post\" action=\"/save_config\">"
        "<label>短信进程</label><select id=\"targetModeSelect\" name=\"target_mode\" onchange=\"toggleTarget()\">"
        "<option value=\"mifi\"%s>ZTE MiFi（/sbin/zte_mifi）</option>"
        "<option value=\"ufi\"%s>ZTE UFI（/sbin/zte_ufi）</option>"
        "<option value=\"custom\"%s>自定义路径</option>"
        "</select>"
        "<div id=\"targetCustomFields\" class=\"custombox\">"
        "<label>自定义进程路径</label><input name=\"target_path\" value=\"%s\" placeholder=\"/sbin/zte_mifi\">"
        "<div class=\"hint\">填写 /proc/&lt;pid&gt;/exe 指向的可执行文件路径。保存后重启服务生效。</div>"
        "</div>"
        "<label>推送方式</label><select id=\"deliverySelect\" name=\"delivery\" onchange=\"toggleDelivery();updatePreview()\">"
        "<option value=\"webhook\"%s>Webhook</option>"
        "<option value=\"email\"%s>邮箱</option>"
        "</select>"
        "<div id=\"webhookFields\" class=\"custombox%s\">"
        "<label>Webhook 平台</label><select id=\"platformSelect\" name=\"platform\" onchange=\"toggleCustom();updatePreview()\">"
        "<option value=\"dingtalk\"%s>钉钉</option>"
        "<option value=\"feishu\"%s>飞书</option>"
        "<option value=\"wecom\"%s>企业微信</option>"
        "<option value=\"serverchan\"%s>Server 酱</option>"
        "<option value=\"discord\"%s>Discord</option>"
        "<option value=\"telegram\"%s>Telegram Bot</option>"
        "<option value=\"bark\"%s>Bark</option>"
        "<option value=\"custom\"%s>自定义</option>"
        "</select>"
        "<label>Webhook URL</label><textarea id=\"webhookInput\" name=\"webhook\" oninput=\"updatePreview()\">%s</textarea>"
        "<div id=\"customFields\" class=\"custombox\">"
        "<label>自定义 Content-Type</label><input id=\"ctypeInput\" name=\"custom_ctype\" value=\"%s\" oninput=\"updatePreview()\">"
        "<label>自定义消息体模板</label><textarea id=\"customBodyInput\" name=\"custom_body\" rows=\"8\" oninput=\"updatePreview()\">%s</textarea>"
        "<div class=\"hint\">占位符：{{json_text}} 适合 JSON 字符串，{{url_text}} 适合表单或 URL 编码，{{text}} 为原文。</div>"
        "</div>"
        "</div>"
        "<div id=\"emailFields\" class=\"custombox%s\">"
        "<label>SMTP 服务器</label><input name=\"smtp_host\" value=\"%s\" placeholder=\"smtp.example.com\" oninput=\"updatePreview()\">"
        "<label>SMTP 端口</label><input name=\"smtp_port\" value=\"%s\" inputmode=\"numeric\" pattern=\"[0-9]*\" oninput=\"updatePreview()\">"
        "<label>连接安全</label><select name=\"smtp_security\" onchange=\"updatePreview()\">"
        "<option value=\"starttls\"%s>STARTTLS（推荐）</option>"
        "<option value=\"tls\"%s>隐式 TLS</option>"
        "<option value=\"plain\"%s>明文</option>"
        "</select>"
        "<label>SMTP 用户名（可选）</label><input name=\"smtp_user\" value=\"%s\" autocomplete=\"username\">"
        "<label>SMTP 密码（可选）</label><input type=\"password\" name=\"smtp_password\" value=\"%s\" autocomplete=\"current-password\">"
        "<label>发件人地址</label><input name=\"smtp_from\" value=\"%s\" placeholder=\"sender@example.com\" oninput=\"updatePreview()\">"
        "<label>收件人地址</label><input name=\"smtp_to\" value=\"%s\" placeholder=\"receiver@example.com\" oninput=\"updatePreview()\">"
        "<div class=\"hint\">Webhook 与邮箱为二选一的推送方式。邮箱需要完整填写 SMTP 服务器、发件人和收件人；证书校验关闭，建议使用 STARTTLS 或隐式 TLS。</div>"
        "</div>"
        "<label>设备手机号，可留空自动读取 nv show</label><div class=\"fieldrow\"><input id=\"numInput\" name=\"num\" value=\"%s\" oninput=\"updatePreview()\"><button class=\"alt\" type=\"button\" onclick=\"fetchMsisdn(this)\">获取</button></div><div id=\"numMsg\" class=\"hint\">获取不到时可手动填写，也可以留空。</div>"
        "<label>消息前缀</label><textarea id=\"headInput\" name=\"headtxt\" rows=\"3\" oninput=\"updatePreview()\">%s</textarea>"
        "<label>消息后缀</label><textarea id=\"tailInput\" name=\"tailtxt\" rows=\"3\" oninput=\"updatePreview()\">%s</textarea>"
        "<label>发送内容示例（按当前推送方式）</label><div id=\"msgPreview\" class=\"preview\">%s</div>"
        "<div class=\"actions\"><button type=\"submit\">保存配置</button></div>"
        "</form><div class=\"hint\">配置保存到 " DEFAULT_CONFIG_PATH "，权限 0600。</div></div></section>"
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">Webhook 模板</div></div><div class=\"pad templates\">"
        "<div class=\"tpl\"><div class=\"tplname\">钉钉</div><div class=\"tpltext\">机器人地址一般形如 <span class=\"tplcode\">https://oapi.dingtalk.com/robot/send?access_token=...</span>。消息体使用 text 类型：<span class=\"tplcode\">msgtype/text/content</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">飞书</div><div class=\"tpltext\">自定义机器人地址一般形如 <span class=\"tplcode\">https://open.feishu.cn/open-apis/bot/v2/hook/...</span>。消息体使用 text 类型：<span class=\"tplcode\">msg_type/content/text</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">企业微信</div><div class=\"tpltext\">群机器人地址一般形如 <span class=\"tplcode\">https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...</span>。消息体使用 text 类型：<span class=\"tplcode\">msgtype/text/content</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">Server 酱</div><div class=\"tpltext\">SendKey 地址一般形如 <span class=\"tplcode\">https://sctapi.ftqq.com/SENDKEY.send</span>。消息体使用表单字段：<span class=\"tplcode\">title/desp</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">Discord</div><div class=\"tpltext\">Webhook 地址形如 <span class=\"tplcode\">https://discord.com/api/webhooks/...</span>。消息体使用 JSON 字段：<span class=\"tplcode\">content</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">Telegram Bot</div><div class=\"tpltext\">URL 写成 <span class=\"tplcode\">https://api.telegram.org/botTOKEN/sendMessage?chat_id=CHAT_ID</span>。消息体使用表单字段：<span class=\"tplcode\">text</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">Bark</div><div class=\"tpltext\">URL 写成 <span class=\"tplcode\">https://api.day.app/your_key</span>。程序会提取 key 并向 <span class=\"tplcode\">/push</span> 发送 JSON：<span class=\"tplcode\">device_key/title/body</span>。</div></div>"
        "<div class=\"tpl\"><div class=\"tplname\">自定义</div><div class=\"tpltext\">自行填写 Content-Type 与消息体模板。JSON 示例：<span class=\"tplcode\">{&quot;text&quot;:&quot;{{json_text}}&quot;}</span>；表单示例：<span class=\"tplcode\">title=Alice&amp;desp={{url_text}}</span>。</div></div>"
        "</div></section>",
        port,
        target_selected_attr(cfg.target_mode, "mifi"),
        target_selected_attr(cfg.target_mode, "ufi"),
        target_selected_attr(cfg.target_mode, "custom"),
        target_path,
        selected_attr(cfg.delivery, DELIVERY_WEBHOOK),
        selected_attr(cfg.delivery, DELIVERY_EMAIL),
        selected_attr(cfg.platform, "dingtalk"),
        selected_attr(cfg.platform, "feishu"),
        selected_attr(cfg.platform, "wecom"),
        selected_attr(cfg.platform, "serverchan"),
        selected_attr(cfg.platform, "discord"),
        selected_attr(cfg.platform, "telegram"),
        selected_attr(cfg.platform, "bark"),
        selected_attr(cfg.platform, "custom"),
        delivery_is_email(&cfg) ? "" : " show",
        webhook, custom_ctype, custom_body,
        delivery_is_email(&cfg) ? " show" : "",
        smtp_host, smtp_port,
        strcmp(normalize_smtp_security(cfg.smtp_security), "starttls") == 0 ? " selected" : "",
        strcmp(normalize_smtp_security(cfg.smtp_security), "tls") == 0 ? " selected" : "",
        strcmp(normalize_smtp_security(cfg.smtp_security), "plain") == 0 ? " selected" : "",
        smtp_user, smtp_password, smtp_from, smtp_to,
        num,
        head, tail, sample_preview_esc);
    append_page_end(body, WEB_BODY_MAX);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", body);
    free(custom_body);
    free(body);
}
#endif

static void append_target_panel(char *body, size_t bodysz,
                                const web_push_target_t *target, int index,
                                int active) {
    char name[256], webhook[2048], ctype[256], custom_body[4096];
    char smtp_host[512], smtp_port[64], smtp_user[512], smtp_password[512];
    char smtp_from[512], smtp_to[512];
    const char *type = normalize_target_type(target->type);
    const char *type_webhook = strcmp(type, TARGET_TYPE_WEBHOOK) == 0 ? " selected" : "";
    const char *type_email = target_is_email(target) ? " selected" : "";
    const char *enabled = target->enabled ? " selected" : "";
    const char *disabled = target->enabled ? "" : " selected";
    const char *webhook_class = target_is_email(target) ? "" : " show";
    const char *email_class = target_is_email(target) ? " show" : "";
    const char *custom_class = !target_is_email(target) &&
        strcmp(normalize_platform(target->platform), "custom") == 0 ? " show" : "";

    html_escape(name, sizeof(name), target->name);
    html_escape(webhook, sizeof(webhook), target->webhook);
    html_escape(ctype, sizeof(ctype), target->custom_ctype);
    html_escape(custom_body, sizeof(custom_body), target->custom_body);
    html_escape(smtp_host, sizeof(smtp_host), target->smtp_host);
    html_escape(smtp_port, sizeof(smtp_port), target->smtp_port);
    html_escape(smtp_user, sizeof(smtp_user), target->smtp_user);
    html_escape(smtp_password, sizeof(smtp_password), target->smtp_password);
    html_escape(smtp_from, sizeof(smtp_from), target->smtp_from);
    html_escape(smtp_to, sizeof(smtp_to), target->smtp_to);
    buf_append(body, bodysz,
        "<div id=\"targetPanel%d\" class=\"targetpanel%s editorsection\"><div class=\"sectionhead\"><div class=\"sectiontitle\">任务基本信息</div><div class=\"sectionhint\">设置任务名称和是否参与推送。</div></div><div class=\"targetgrid\">"
        "<div><label>启用状态</label><select id=\"target_%d_enabled\" name=\"target_%d_enabled\" onchange=\"updatePreview()\"><option value=\"1\"%s>启用</option><option value=\"0\"%s>停用</option></select></div>"
        "<div><label>任务名称</label><input id=\"target_%d_name\" name=\"target_%d_name\" value=\"%s\" oninput=\"updatePreview()\"></div></div>",
        index, active ? " show" : "", index, index, enabled, disabled,
        index, index, name);
    buf_append(body, bodysz,
        "<div class=\"sectionhead\"><div class=\"sectiontitle\">推送渠道</div><div class=\"sectionhint\">每个任务选择一种渠道，配置完成后才会发送短信。</div></div><div class=\"targetgrid\">"
        "<div class=\"targetwide\"><label>任务类型</label><select id=\"target_%d_type\" name=\"target_%d_type\" onchange=\"toggleTargetType(%d);updatePreview()\"><option value=\"webhook\"%s>Webhook</option><option value=\"email\"%s>邮箱</option></select></div>",
        index, index, index, type_webhook, type_email);
    buf_append(body, bodysz,
        "<div id=\"target_%d_webhook_fields\" class=\"conditionalbox%s targetwide\">"
        "<label>Webhook 平台</label><select id=\"target_%d_platform\" name=\"target_%d_platform\" onchange=\"toggleTargetType(%d);updatePreview()\">"
        "<option value=\"dingtalk\"%s>钉钉</option><option value=\"feishu\"%s>飞书</option><option value=\"wecom\"%s>企业微信</option><option value=\"serverchan\"%s>Server 酱</option><option value=\"discord\"%s>Discord</option><option value=\"telegram\"%s>Telegram Bot</option><option value=\"bark\"%s>Bark</option><option value=\"custom\"%s>自定义</option></select>"
        "<label>Webhook URL</label><textarea id=\"target_%d_webhook\" name=\"target_%d_webhook\" oninput=\"updatePreview()\">%s</textarea>"
        "<div id=\"target_%d_custom_fields\" class=\"conditionalbox%s\">"
        "<label>自定义 Content-Type</label><input id=\"target_%d_custom_ctype\" name=\"target_%d_custom_ctype\" value=\"%s\" oninput=\"updatePreview()\">"
        "<label>自定义消息体模板</label><textarea id=\"target_%d_custom_body\" name=\"target_%d_custom_body\" rows=\"6\" oninput=\"updatePreview()\">%s</textarea>"
        "<div class=\"hint\">支持 {{json_text}}、{{url_text}} 和 {{text}} 占位符。</div></div></div>",
        index, webhook_class, index, index, index,
        selected_attr(target->platform, "dingtalk"), selected_attr(target->platform, "feishu"),
        selected_attr(target->platform, "wecom"), selected_attr(target->platform, "serverchan"),
        selected_attr(target->platform, "discord"), selected_attr(target->platform, "telegram"),
        selected_attr(target->platform, "bark"), selected_attr(target->platform, "custom"),
        index, index, webhook, index, custom_class, index, index, ctype,
        index, index, custom_body);
    buf_append(body, bodysz,
        "<div id=\"target_%d_email_fields\" class=\"conditionalbox%s targetwide\">"
        "<label>SMTP 服务器</label><input id=\"target_%d_smtp_host\" name=\"target_%d_smtp_host\" value=\"%s\" placeholder=\"smtp.example.com\" oninput=\"updatePreview()\">"
        "<label>SMTP 端口</label><input id=\"target_%d_smtp_port\" name=\"target_%d_smtp_port\" value=\"%s\" inputmode=\"numeric\" pattern=\"[0-9]*\" oninput=\"updatePreview()\">"
        "<label>连接安全</label><select id=\"target_%d_smtp_security\" name=\"target_%d_smtp_security\" onchange=\"updatePreview()\"><option value=\"starttls\"%s>STARTTLS（推荐）</option><option value=\"tls\"%s>隐式 TLS</option><option value=\"plain\"%s>明文</option></select>"
        "<label>SMTP 用户名（可选）</label><input id=\"target_%d_smtp_user\" name=\"target_%d_smtp_user\" value=\"%s\" autocomplete=\"username\">"
        "<label>SMTP 密码（可选）</label><input type=\"password\" id=\"target_%d_smtp_password\" name=\"target_%d_smtp_password\" value=\"%s\" autocomplete=\"current-password\">"
        "<label>发件人地址</label><input id=\"target_%d_smtp_from\" name=\"target_%d_smtp_from\" value=\"%s\" placeholder=\"sender@example.com\" oninput=\"updatePreview()\">"
        "<label>收件人地址</label><input id=\"target_%d_smtp_to\" name=\"target_%d_smtp_to\" value=\"%s\" placeholder=\"receiver@example.com\" oninput=\"updatePreview()\">"
        "<div class=\"hint\">邮箱任务独立保存，证书校验关闭。</div></div></div></div>",
        index, email_class, index, index, smtp_host,
        index, index, smtp_port, index, index,
        strcmp(normalize_smtp_security(target->smtp_security), "starttls") == 0 ? " selected" : "",
        strcmp(normalize_smtp_security(target->smtp_security), "tls") == 0 ? " selected" : "",
        strcmp(normalize_smtp_security(target->smtp_security), "plain") == 0 ? " selected" : "",
        index, index, smtp_user, index, index, smtp_password,
        index, index, smtp_from, index, index, smtp_to);
}

static void render_config(int fd, const char *message) {
    web_config_t cfg;
    char *body = calloc(1, WEB_BODY_MAX);
    int i;
    int port;

    if (!body) {
        http_send(fd, 500, "Internal Server Error", "text/plain", "out of memory\n");
        return;
    }
    load_web_config(&cfg);
    port = cfg.port > 0 ? cfg.port : DEFAULT_WEBUI_PORT;
    append_page_start(body, WEB_BODY_MAX, "config", "配置",
                      "管理多个 Webhook 和邮箱推送任务", message);
    buf_append(body, WEB_BODY_MAX,
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">WebUI 设置</div></div><div class=\"pad\">"
        "<form method=\"post\" action=\"/set_port\"><label>WebUI 端口</label><input name=\"port\" value=\"%d\" inputmode=\"numeric\" pattern=\"[0-9]*\" required><div class=\"actions\"><button type=\"submit\">保存并切换端口</button></div></form>"
        "<div class=\"hint\">端口默认保存到 " DEFAULT_CONFIG_PATH "。</div></div></section>"
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"targetbar\"><div><div class=\"title\">推送任务</div><div class=\"hint\">同一条短信会发送到所有已启用且配置完整的任务。</div></div><a class=\"button\" href=\"/target_new\">新建推送任务</a></div></div><div class=\"pad\">"
        "<div class=\"targetbar\"><div class=\"targetstatus\">已启用并配置完整：%d / %d</div></div>"
        "<div style=\"overflow:auto\"><table class=\"startuptable\"><thead><tr><th>任务</th><th>类型</th><th>状态</th><th>配置</th><th>操作</th></tr></thead><tbody>",
        port, enabled_target_count(&cfg), cfg.target_count);
    for (i = 0; i < cfg.target_count; i++) {
        const web_push_target_t *target = &cfg.targets[i];
        const char *name = target->name[0] ? target->name : "未命名任务";
        const char *type = target_is_email(target) ? "邮箱" : "Webhook";
        const char *detail = target_is_email(target) ? "SMTP 邮箱" : platform_label(target->platform);
        const char *status = target->enabled ? "已启用" : "已停用";
        const char *status_class = target->enabled ? "ok" : "off";
        const char *config = target_configured(target) ? "配置完整" : "待配置";
        const char *config_class = target_configured(target) ? "ok" : "warn";
        char esc_name[256], esc_detail[256];
        html_escape(esc_name, sizeof(esc_name), name);
        html_escape(esc_detail, sizeof(esc_detail), detail);
        buf_append(body, WEB_BODY_MAX,
                   "<tr><td><strong>%s</strong><div class=\"hint\">%s</div></td><td>%s</td><td><span class=\"status %s\">%s</span></td><td><span class=\"status %s\">%s</span></td><td><div class=\"rowactions\">"
                   "<a class=\"button alt\" href=\"/target_edit?index=%d\">编辑</a>"
                   "<form method=\"post\" action=\"/target_toggle\"><input type=\"hidden\" name=\"target_index\" value=\"%d\"><button class=\"%s\" type=\"submit\">%s</button></form>"
                   "<form method=\"post\" action=\"/target_delete\" onsubmit=\"return confirm('删除这个推送任务？');\"><input type=\"hidden\" name=\"target_index\" value=\"%d\"><button class=\"warn\" type=\"submit\">删除</button></form>"
                   "</div></td></tr>",
                   esc_name, esc_detail, type, status_class, status,
                   config_class, config, i, i, target->enabled ? "warn" : "alt",
                   target->enabled ? "停用" : "启用", i);
    }
    buf_append(body, WEB_BODY_MAX,
               cfg.target_count > 0 ? "" : "<tr><td class=\"emptyrow\" colspan=\"5\">暂无推送任务，点击“新建推送任务”添加。</td></tr>");
    buf_append(body, WEB_BODY_MAX,
        "</tbody></table></div></div></section>");
    append_page_end(body, WEB_BODY_MAX);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", body);
    free(body);
}

static void render_target_editor(int fd, const char *message, int index,
                                 const web_push_target_t *draft,
                                 const web_config_t *draft_cfg) {
    web_config_t cfg;
    web_push_target_t target;
    char *body = calloc(1, WEB_BODY_MAX);
    char title[256];
    char num[256], head[1024], tail[1024], target_path[512];
    int editing;

    if (!body) {
        http_send(fd, 500, "Internal Server Error", "text/plain", "out of memory\n");
        return;
    }
    load_web_config(&cfg);
    if (draft_cfg) {
        safe_copy(cfg.target_mode, sizeof(cfg.target_mode), draft_cfg->target_mode);
        safe_copy(cfg.target_path, sizeof(cfg.target_path), draft_cfg->target_path);
    }
    if (index < 0 || index > cfg.target_count || index >= ALICE_ENGINE_MAX_TARGETS) {
        free(body);
        render_config(fd, "任务索引无效。\n");
        return;
    }
    editing = index < cfg.target_count;
    if (editing)
        target = cfg.targets[index];
    else {
        init_push_target(&target, index);
        target.enabled = 1;
    }
    if (draft)
        target = *draft;
    html_escape(num, sizeof(num), target.num);
    html_escape(head, sizeof(head), target.headtxt);
    html_escape(tail, sizeof(tail), target.tailtxt);
    html_escape(target_path, sizeof(target_path), cfg.target_path);
    html_escape(title, sizeof(title), editing ? target.name : "新建推送任务");
    append_page_start(body, WEB_BODY_MAX, "config",
                      editing ? "编辑推送任务" : "新建推送任务",
                      "依次配置短信来源、任务信息、推送渠道和消息文本", message);
    buf_append(body, WEB_BODY_MAX,
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"targetbar\"><div><div class=\"title\">%s</div><div class=\"hint\">保存后返回任务列表；同一条短信可同时发送到多个已启用任务。</div></div><a class=\"button alt\" href=\"/config\">返回任务列表</a></div></div><div class=\"pad\">"
        "<form method=\"post\" action=\"/target_save\"><input type=\"hidden\" id=\"targetCount\" name=\"target_count\" value=\"%d\"><input type=\"hidden\" id=\"targetIndex\" name=\"target_index\" value=\"%d\">",
        title, index + 1, index);
    buf_append(body, WEB_BODY_MAX,
        "<div class=\"editorsection\"><div class=\"sectionhead\"><div class=\"sectiontitle\">短信来源</div><div class=\"sectionhint\">短信进程是全局设置；切换后会影响所有推送任务。</div></div>"
        "<label>短信进程</label><select id=\"targetModeSelect\" name=\"target_mode\" onchange=\"toggleTargetProcess()\"><option value=\"mifi\"%s>ZTE MiFi（/sbin/zte_mifi）</option><option value=\"ufi\"%s>ZTE UFI（/sbin/zte_ufi）</option><option value=\"custom\"%s>自定义路径</option></select>"
        "<div id=\"targetCustomFields\" class=\"conditionalbox\"><label>自定义进程路径</label><input name=\"target_path\" value=\"%s\" placeholder=\"/sbin/zte_mifi\"><div class=\"hint\">填写 /proc/&lt;pid&gt;/exe 指向的可执行文件路径。</div></div></div>",
        target_selected_attr(cfg.target_mode, "mifi"), target_selected_attr(cfg.target_mode, "ufi"),
        target_selected_attr(cfg.target_mode, "custom"), target_path);
    append_target_panel(body, WEB_BODY_MAX, &target, index, 1);
    buf_append(body, WEB_BODY_MAX,
        "<div class=\"editorsection\"><div class=\"sectionhead\"><div class=\"sectiontitle\">消息文本</div><div class=\"sectionhint\">这些设置只作用于当前任务，留空则使用原始短信内容。</div></div>"
        "<label>设备手机号（可选）</label><div class=\"fieldrow\"><input id=\"numInput\" name=\"target_%d_num\" value=\"%s\" placeholder=\"留空时自动读取 nv show\" oninput=\"updatePreview()\"><button class=\"alt\" type=\"button\" onclick=\"fetchMsisdn(this)\">获取</button></div><div id=\"numMsg\" class=\"hint\">获取不到时可手动填写，也可以留空。</div>"
        "<label>消息前缀（可选）</label><textarea id=\"headInput\" name=\"target_%d_headtxt\" rows=\"3\" placeholder=\"例如：来自主卡\" oninput=\"updatePreview()\">%s</textarea>"
        "<label>消息后缀（可选）</label><textarea id=\"tailInput\" name=\"target_%d_tailtxt\" rows=\"3\" placeholder=\"例如：请及时处理\" oninput=\"updatePreview()\">%s</textarea></div>",
        index, num, index, head, index, tail);
    buf_append(body, WEB_BODY_MAX,
        "<div class=\"editorsection\"><div class=\"sectionhead\"><div class=\"sectiontitle\">发送预览</div><div class=\"sectionhint\">预览会根据当前任务的渠道和消息文本实时更新。</div></div><div id=\"msgPreview\" class=\"preview\"></div>"
        "<div class=\"actions\"><button class=\"testbutton\" type=\"submit\" formaction=\"/target_test\" formmethod=\"post\">测试任务</button><button type=\"submit\">保存任务</button><a class=\"button alt\" href=\"/config\">取消</a></div></form></div></section>");
    append_page_end(body, WEB_BODY_MAX);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", body);
    free(body);
}

static void render_logs(int fd, const char *message) {
    char *body = calloc(1, WEB_BODY_MAX);
    char *logbuf = calloc(1, LOG_TAIL_MAX + 1);
    char *esc = calloc(1, LOG_TAIL_MAX * 6 + 1);

    if (!body || !logbuf || !esc) {
        free(body); free(logbuf); free(esc);
        http_send(fd, 500, "Internal Server Error", "text/plain", "out of memory\n");
        return;
    }
    read_log_tail(logbuf, LOG_TAIL_MAX + 1);
    html_escape(esc, LOG_TAIL_MAX * 6 + 1, logbuf[0] ? logbuf : "暂无日志");
    append_page_start(body, WEB_BODY_MAX, "logs", "运行日志",
                      "环形保留最近 1KB，可导出当前日志窗口", message);
    buf_append(body, WEB_BODY_MAX,
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">环形日志</div>"
        "<div class=\"hint\">页面显示最近 1KB，导出文件包含当前 1KB 环形日志。</div></div>"
        "<div class=\"pad\"><pre>%s</pre><div class=\"actions\">"
        "<form method=\"get\" action=\"/logs\"><button class=\"alt\" type=\"submit\">刷新</button></form>"
        "<form method=\"get\" action=\"/logs/export\"><button type=\"submit\">导出日志</button></form>"
        "<form method=\"post\" action=\"/logs/clear\" onsubmit=\"return confirm('确定清空运行日志？')\"><button class=\"alt\" type=\"submit\">清空日志</button></form>"
        "</div></div></section>",
        esc);
    append_page_end(body, WEB_BODY_MAX);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", body);
    free(body); free(logbuf); free(esc);
}

static void render_log_export(int fd) {
    char *logbuf = calloc(1, LOG_RING_MAX + 1);

    if (!logbuf) {
        http_send(fd, 500, "Internal Server Error", "text/plain", "out of memory\n");
        return;
    }
    trim_log_file();
    read_log_tail(logbuf, LOG_RING_MAX + 1);
    http_send_download(fd, "text/plain; charset=utf-8", LOG_EXPORT_NAME,
                       logbuf, strlen(logbuf));
    ring_log_append("[WEBUI] log exported");
    free(logbuf);
}

static void handle_clear_logs(int fd) {
    if (clear_log_file() < 0) {
        ring_log_append("[WEBUI] clear log failed errno=%d", errno);
        render_logs(fd, "日志清空失败。");
        return;
    }
    ring_log_append("[WEBUI] log cleared");
    render_logs(fd, "日志已清空。");
}

static void render_about(int fd) {
    char *body = calloc(1, WEB_BODY_MAX);
    if (!body) {
        http_send(fd, 500, "Internal Server Error", "text/plain", "out of memory\n");
        return;
    }
    append_page_start(body, WEB_BODY_MAX, "about", "关于",
                      "项目信息与署名", NULL);
    buf_append(body, WEB_BODY_MAX,
        "<section class=\"panel\"><div class=\"pad about\">"
        "<img class=\"avatar\" src=\"/avatar.jpg\" alt=\"avatar\">"
        "<div><div class=\"aboutname\">alice-pusher-bot-zxic</div>"
        "<div class=\"hint\">ZTE MiFi/UFI 短信捕获与 Webhook 推送工具</div>"
        "<div class=\"labelrow\">项目地址：<a class=\"repo\" href=\"https://github.com/Amamiyashi0n/alice-pusher-bot-zxic\">"
        "github.com/Amamiyashi0n/alice-pusher-bot-zxic</a></div>"
        "<div class=\"signature\">世间自有尘寰在，我亦独吟游且歌。</div>"
        "</div></div></section>"
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"supporthead\">"
        "<div class=\"title\">赞助支持</div>"
        "<div class=\"supportdesc\">软件免费，代码开源。<br>"
        "如果可以的话，也许您可以给予我一些小小的帮助。</div></div></div>"
        "<div class=\"pad supportgrid\">"
        "<div class=\"supportcard\"><div class=\"supporttitle\">微信 / 支付宝扫码</div>"
        "<div class=\"qrbox\"><img class=\"qr\" src=\"/sponsor.jpg\" alt=\"sponsor qrcode\"></div>"
        "</div><div class=\"supportcard\"><div class=\"supporttitle\">爱发电</div>"
        "<a class=\"plainlink\" href=\"https://ifdian.net/a/amamiyashion\">"
        "ifdian.net/a/amamiyashion</a>"
        "</div></div></section>");
    append_page_end(body, WEB_BODY_MAX);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", body);
    free(body);
}

static void render_avatar(int fd) {
    http_send_data(fd, 200, "OK", avatar_image_mime,
                   avatar_image_data, avatar_image_size,
                   "public, max-age=86400");
}

static void render_sponsor_image(int fd) {
    http_send_data(fd, 200, "OK", sponsor_image_mime,
                   sponsor_image_data, sponsor_image_size,
                   "public, max-age=86400");
}

static void render_experimental(int fd, const char *message, int is_error) {
    web_config_t cfg;
    char *body = calloc(1, WEB_BODY_MAX);
    char escaped_message[1024];

    if (!body) {
        http_send(fd, 500, "Internal Server Error", "text/plain",
                  "out of memory\n");
        return;
    }
    load_web_config(&cfg);
    append_page_start(body, WEB_BODY_MAX, "experimental", "实验功能",
                      "用于验证短信分段拼合和长文本推送链路", NULL);
    if (message && message[0]) {
        html_escape(escaped_message, sizeof(escaped_message), message);
        buf_append(body, WEB_BODY_MAX, "<div class=\"msg%s\">%s</div>",
                   is_error ? " error" : "", escaped_message);
    }
    buf_append(body, WEB_BODY_MAX,
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">长短信自动拼合</div></div><div class=\"pad\">"
        "<form method=\"post\" action=\"/experimental/save\"><label class=\"switchline\"><input style=\"width:auto;height:auto\" type=\"checkbox\" name=\"long_sms_reassembly\" value=\"1\"%s>启用长短信分段拼合</label>"
        "<div class=\"hint\">启用后，带有 UDH 分段信息的短信会按顺序收齐后只推送一次；关闭后恢复每个 PDU 独立推送。</div>"
        "<div class=\"actions\"><button type=\"submit\">保存并应用</button></div></form></div></section>"
        "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">当前边界</div></div><div class=\"pad\"><div class=\"grid\">"
        "<div class=\"kv\"><div class=\"k\">当前状态</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">支持编码</div><div class=\"v\">UCS2、GSM 7-bit</div></div>"
        "<div class=\"kv\"><div class=\"k\">最大段数</div><div class=\"v\">%d 段</div></div>"
        "<div class=\"kv\"><div class=\"k\">最大拼合文本</div><div class=\"v\">%d 字节</div></div>"
        "<div class=\"kv\"><div class=\"k\">未收齐超时</div><div class=\"v\">%d 秒</div></div>"
        "<div class=\"kv\"><div class=\"k\">超限处理</div><div class=\"v\">记录日志并丢弃未完成内容</div></div>"
        "</div><div class=\"hint\">保存后如果服务正在运行，WebUI 会自动重启短信监控服务使配置立即生效。</div></div></section>",
        cfg.long_sms_reassembly ? " checked" : "",
        cfg.long_sms_reassembly ? "已启用" : "已关闭",
        ALICE_ENGINE_CONCAT_MAX_PARTS, ALICE_ENGINE_SMS_MAX_BYTES,
        ALICE_ENGINE_CONCAT_TIMEOUT_SECONDS);
    append_page_end(body, WEB_BODY_MAX);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", body);
    free(body);
}

static void render_status_json(int fd) {
    web_config_t cfg;
    autostart_status_t ast;
    char num[256];
    char platform[96];
    char target_mode[64];
    char target_path[512];
    char target_path_raw[256];
    char auto_mode[96];
    char auto_payload[512];
    char auto_script[512];
    char auto_error[512];
    const char *delivery;
    int webhook_configured;
    int email_configured_flag;
    pid_t spid = service_pid();
    pid_t strpid = alice_engine_get_strace_pid();
    int target_pid;
    char body[3072];

    load_web_config(&cfg);
    get_autostart_status(&ast);
    if (!process_alive(strpid)) strpid = 0;
    resolve_target_path(&cfg, target_path_raw, sizeof(target_path_raw));
    target_pid = alice_engine_find_process_by_exe_path(target_path_raw);
    json_escape(num, sizeof(num), cfg.num);
    json_escape(platform, sizeof(platform), configured_platform_label(&cfg));
    json_escape(target_mode, sizeof(target_mode), target_mode_label(cfg.target_mode));
    json_escape(target_path, sizeof(target_path), target_path_raw);
    json_escape(auto_mode, sizeof(auto_mode), ast.mode_label);
    json_escape(auto_payload, sizeof(auto_payload), ast.payload_path);
    json_escape(auto_script, sizeof(auto_script), ast.script_path);
    json_escape(auto_error, sizeof(auto_error), ast.error);
    delivery = configured_delivery_mode(&cfg);
    webhook_configured = strcmp(delivery, "webhook") == 0 ||
                         strcmp(delivery, "multiple") == 0;
    email_configured_flag = strcmp(delivery, "email") == 0 ||
                            strcmp(delivery, "multiple") == 0;
    snprintf(body, sizeof(body),
        "{\"service_running\":%s,\"service_pid\":%ld,"
        "\"strace_pid\":%ld,\"target_pid\":%d,\"zte_mifi_pid\":%d,"
        "\"target_mode\":\"%s\",\"target_path\":\"%s\","
        "\"delivery\":\"%s\",\"target_count\":%d,\"enabled_target_count\":%d,"
        "\"webhook_configured\":%s,\"email_configured\":%s,\"platform\":\"%s\","
        "\"num\":\"%s\",\"port\":%d,\"long_sms_reassembly\":%s,"
        "\"concat_max_segments\":%d,\"concat_max_bytes\":%d,\"concat_timeout_seconds\":%d,"
        "\"wonder_detected\":%s,\"persistence_mode\":\"%s\","
        "\"payload_ready\":%s,\"payload_path\":\"%s\","
        "\"startup_script_ready\":%s,\"startup_entry_ready\":%s,"
        "\"startup_installed\":%s,\"startup_running\":%s,"
        "\"startup_script_path\":\"%s\",\"userdata_free_bytes\":%lu,"
        "\"payload_required_bytes\":%lu,\"install_error\":\"%s\"}\n",
        spid > 0 ? "true" : "false", (long)spid, (long)strpid,
        target_pid > 0 ? target_pid : 0,
        target_pid > 0 ? target_pid : 0, target_mode, target_path,
        delivery,
        cfg.target_count, enabled_target_count(&cfg),
        webhook_configured ? "true" : "false",
        email_configured_flag ? "true" : "false",
        platform, num, g_webui_port, cfg.long_sms_reassembly ? "true" : "false",
        ALICE_ENGINE_CONCAT_MAX_PARTS, ALICE_ENGINE_SMS_MAX_BYTES,
        ALICE_ENGINE_CONCAT_TIMEOUT_SECONDS,
        ast.wonder_detected ? "true" : "false", auto_mode,
        ast.payload_ready ? "true" : "false", auto_payload,
        ast.script_ready ? "true" : "false", ast.entry_ready ? "true" : "false",
        ast.installed ? "true" : "false", ast.startup_running ? "true" : "false",
        auto_script, ast.free_bytes, ast.required_bytes, auto_error);
    http_send(fd, 200, "OK", "application/json; charset=utf-8", body);
}

static void render_msisdn_json(int fd) {
    char num[256];
    char body[640];

    int ok = alice_engine_load_device_msisdn(num, sizeof(num)) == 0;
    char escaped_num[256];
    json_escape(escaped_num, sizeof(escaped_num), num);
    snprintf(body, sizeof(body),
             "{\"ok\":%s,\"num\":\"%s\",\"message\":\"%s\"}\n",
             ok ? "true" : "false", escaped_num,
             ok ? "已读取手机号" :
             "未从 nv show 读取到手机号");
    http_send(fd, 200, "OK", "application/json; charset=utf-8", body);
}

#if 0
static void handle_save_config_legacy(int fd, const char *body) {
    web_config_t cfg;
    char submitted_password[256];
    int submitted_password_present;
    int smtp_port;
    int saved_port;

    load_web_config(&cfg);
    saved_port = cfg.port > 0 ? cfg.port : DEFAULT_WEBUI_PORT;
    if (!form_value(body, "delivery", cfg.delivery, sizeof(cfg.delivery)))
        safe_copy(cfg.delivery, sizeof(cfg.delivery), DELIVERY_WEBHOOK);
    form_value(body, "webhook", cfg.webhook, sizeof(cfg.webhook));
    form_value(body, "platform", cfg.platform, sizeof(cfg.platform));
    form_value(body, "target_mode", cfg.target_mode, sizeof(cfg.target_mode));
    form_value(body, "target_path", cfg.target_path, sizeof(cfg.target_path));
    form_value(body, "custom_ctype", cfg.custom_ctype,
               sizeof(cfg.custom_ctype));
    form_value(body, "custom_body", cfg.custom_body,
               sizeof(cfg.custom_body));
    form_value(body, "num", cfg.num, sizeof(cfg.num));
    form_value(body, "headtxt", cfg.headtxt, sizeof(cfg.headtxt));
    form_value(body, "tailtxt", cfg.tailtxt, sizeof(cfg.tailtxt));
    form_value(body, "smtp_host", cfg.smtp_host, sizeof(cfg.smtp_host));
    form_value(body, "smtp_port", cfg.smtp_port, sizeof(cfg.smtp_port));
    form_value(body, "smtp_user", cfg.smtp_user, sizeof(cfg.smtp_user));
    submitted_password_present = form_value(body, "smtp_password",
                                             submitted_password,
                                             sizeof(submitted_password));
    if (submitted_password_present && submitted_password[0])
        safe_copy(cfg.smtp_password, sizeof(cfg.smtp_password),
                  submitted_password);
    form_value(body, "smtp_from", cfg.smtp_from, sizeof(cfg.smtp_from));
    form_value(body, "smtp_to", cfg.smtp_to, sizeof(cfg.smtp_to));
    form_value(body, "smtp_security", cfg.smtp_security,
               sizeof(cfg.smtp_security));
    cfg.port = saved_port;
    remove_newlines(cfg.webhook);
    safe_copy(cfg.delivery, sizeof(cfg.delivery), normalize_delivery(cfg.delivery));
    safe_copy(cfg.platform, sizeof(cfg.platform),
              normalize_platform(cfg.platform));
    safe_copy(cfg.target_mode, sizeof(cfg.target_mode),
              normalize_target_mode(cfg.target_mode));
    remove_newlines(cfg.target_path);
    if (strcmp(cfg.target_mode, "custom") != 0) {
        safe_copy(cfg.target_path, sizeof(cfg.target_path),
                  target_default_path(cfg.target_mode));
    } else if (!cfg.target_path[0] || cfg.target_path[0] != '/') {
        ring_log_append("[WEBUI] config save rejected: invalid target path");
        render_config(fd, "自定义进程路径必须填写绝对路径，例如 /sbin/zte_mifi。");
        return;
    }
    remove_newlines(cfg.custom_ctype);
    if (!cfg.custom_ctype[0])
        safe_copy(cfg.custom_ctype, sizeof(cfg.custom_ctype),
                  "application/json;charset=utf-8");
    remove_newlines(cfg.num);
    remove_newlines(cfg.smtp_host);
    remove_newlines(cfg.smtp_port);
    remove_newlines(cfg.smtp_user);
    remove_newlines(cfg.smtp_password);
    remove_newlines(cfg.smtp_from);
    remove_newlines(cfg.smtp_to);
    safe_copy(cfg.smtp_security, sizeof(cfg.smtp_security),
              normalize_smtp_security(cfg.smtp_security));
    if (!cfg.smtp_port[0])
        safe_copy(cfg.smtp_port, sizeof(cfg.smtp_port), "587");
    if (delivery_is_email(&cfg))
        cfg.webhook[0] = 0;
    else
        clear_email_target(&cfg);
    if ((cfg.smtp_host[0] || cfg.smtp_user[0] || cfg.smtp_password[0] ||
         cfg.smtp_from[0] || cfg.smtp_to[0]) &&
        delivery_is_email(&cfg) && !email_configured(&cfg)) {
        ring_log_append("[WEBUI] config save rejected: incomplete smtp target");
        render_config(fd, "邮箱方式需要同时填写 SMTP 服务器、发件人和收件人。");
        return;
    }
    if (delivery_is_email(&cfg) && email_configured(&cfg) &&
        parse_port_text(cfg.smtp_port, &smtp_port) < 0) {
        ring_log_append("[WEBUI] config save rejected: invalid smtp port");
        render_config(fd, "SMTP 端口无效，请输入 1-65535 的数字。");
        return;
    }
    if (!any_target_configured(&cfg)) {
        ring_log_append("[WEBUI] config save rejected: no push target");
        render_config(fd, "请选择 Webhook 或邮箱，并完成对应配置。");
        return;
    }
    if (cfg.webhook[0] && strcmp(normalize_platform(cfg.platform), "custom") == 0 &&
        !cfg.custom_body[0]) {
        ring_log_append("[WEBUI] config save rejected: custom body is empty");
        render_config(fd, "自定义消息体模板不能为空。");
        return;
    }
    if (save_web_config(&cfg) < 0) {
        ring_log_append("[WEBUI] config save failed errno=%d", errno);
        render_config(fd, "配置保存失败，请检查 /mnt/userdata 是否可写。");
        return;
    }
    ring_log_append("[WEBUI] config saved delivery=%s platform=%s target=%s",
                    normalize_delivery(cfg.delivery),
                    configured_platform_label(&cfg),
                    normalize_target_mode(cfg.target_mode));
    render_config(fd, "配置已保存。");
}
#endif

static void handle_save_config(int fd, const char *body) {
    web_config_t cfg;
    char value[64];
    char submitted_password[256];
    char previous_password[256];
    int submitted_password_present;
    int count;
    int i;
    int active_count = 0;
    char *count_end;
    long parsed_count;

    load_web_config(&cfg);
    /* Target records are saved by /target_save; this route only owns source settings. */
    form_value(body, "target_mode", cfg.target_mode, sizeof(cfg.target_mode));
    form_value(body, "target_path", cfg.target_path, sizeof(cfg.target_path));
    form_value(body, "num", cfg.num, sizeof(cfg.num));
    form_value(body, "headtxt", cfg.headtxt, sizeof(cfg.headtxt));
    form_value(body, "tailtxt", cfg.tailtxt, sizeof(cfg.tailtxt));
    safe_copy(cfg.target_mode, sizeof(cfg.target_mode),
              normalize_target_mode(cfg.target_mode));
    remove_newlines(cfg.target_path);
    remove_newlines(cfg.num);
    remove_newlines(cfg.headtxt);
    remove_newlines(cfg.tailtxt);
    if (strcmp(cfg.target_mode, "custom") != 0) {
        safe_copy(cfg.target_path, sizeof(cfg.target_path),
                  target_default_path(cfg.target_mode));
    } else if (!cfg.target_path[0] || cfg.target_path[0] != '/') {
        ring_log_append("[WEBUI] source config rejected: invalid target path");
        render_config(fd, "自定义进程路径必须填写绝对路径，例如 /sbin/zte_mifi。");
        return;
    }
    if (save_web_config(&cfg) < 0) {
        ring_log_append("[WEBUI] source config save failed errno=%d", errno);
        render_config(fd, "配置保存失败，请检查 /mnt/userdata 是否可写。");
        return;
    }
    ring_log_append("[WEBUI] source config saved targets=%d", cfg.target_count);
    render_config(fd, "短信来源配置已保存。");
    return;

    form_value(body, "target_count", value, sizeof(value));
    if (!value[0]) {
        ring_log_append("[WEBUI] config save rejected: target count is empty");
        render_config(fd, "任务数量无效，请至少添加一个任务。");
        return;
    }
    errno = 0;
    parsed_count = strtol(value, &count_end, 10);
    while (*count_end == ' ' || *count_end == '\t' ||
           *count_end == '\r' || *count_end == '\n')
        count_end++;
    if (errno || count_end == value || *count_end ||
        parsed_count < 0 || parsed_count > ALICE_ENGINE_MAX_TARGETS) {
        ring_log_append("[WEBUI] config save rejected: target count=%s", value);
        render_config(fd, "任务数量无效，最多支持 4 个任务。");
        return;
    }
    count = (int)parsed_count;
    cfg.target_count = count;
    form_value(body, "target_mode", cfg.target_mode, sizeof(cfg.target_mode));
    form_value(body, "target_path", cfg.target_path, sizeof(cfg.target_path));
    form_value(body, "num", cfg.num, sizeof(cfg.num));
    form_value(body, "headtxt", cfg.headtxt, sizeof(cfg.headtxt));
    form_value(body, "tailtxt", cfg.tailtxt, sizeof(cfg.tailtxt));
    safe_copy(cfg.target_mode, sizeof(cfg.target_mode),
              normalize_target_mode(cfg.target_mode));
    remove_newlines(cfg.target_path);
    remove_newlines(cfg.num);
    remove_newlines(cfg.headtxt);
    remove_newlines(cfg.tailtxt);
    if (strcmp(cfg.target_mode, "custom") != 0) {
        safe_copy(cfg.target_path, sizeof(cfg.target_path),
                  target_default_path(cfg.target_mode));
    } else if (!cfg.target_path[0] || cfg.target_path[0] != '/') {
        ring_log_append("[WEBUI] config save rejected: invalid target path");
        render_config(fd, "自定义进程路径必须填写绝对路径，例如 /sbin/zte_mifi。");
        return;
    }

    for (i = 0; i < ALICE_ENGINE_MAX_TARGETS; i++) {
        web_push_target_t *target = &cfg.targets[i];
        char key[64];

        snprintf(key, sizeof(key), "target_%d_enabled", i);
        form_value(body, key, value, sizeof(value));
        target->enabled = strcmp(value, "1") == 0;
        snprintf(key, sizeof(key), "target_%d_name", i);
        form_value(body, key, target->name, sizeof(target->name));
        snprintf(key, sizeof(key), "target_%d_type", i);
        form_value(body, key, target->type, sizeof(target->type));
        snprintf(key, sizeof(key), "target_%d_platform", i);
        form_value(body, key, target->platform, sizeof(target->platform));
        snprintf(key, sizeof(key), "target_%d_webhook", i);
        form_value(body, key, target->webhook, sizeof(target->webhook));
        snprintf(key, sizeof(key), "target_%d_custom_ctype", i);
        form_value(body, key, target->custom_ctype, sizeof(target->custom_ctype));
        snprintf(key, sizeof(key), "target_%d_custom_body", i);
        form_value(body, key, target->custom_body, sizeof(target->custom_body));
        snprintf(key, sizeof(key), "target_%d_smtp_host", i);
        form_value(body, key, target->smtp_host, sizeof(target->smtp_host));
        snprintf(key, sizeof(key), "target_%d_smtp_port", i);
        form_value(body, key, target->smtp_port, sizeof(target->smtp_port));
        snprintf(key, sizeof(key), "target_%d_smtp_user", i);
        form_value(body, key, target->smtp_user, sizeof(target->smtp_user));
        safe_copy(previous_password, sizeof(previous_password), target->smtp_password);
        snprintf(key, sizeof(key), "target_%d_smtp_password", i);
        submitted_password_present = form_value(body, key, submitted_password,
                                                 sizeof(submitted_password));
        if (submitted_password_present && submitted_password[0])
            safe_copy(target->smtp_password, sizeof(target->smtp_password),
                      submitted_password);
        else
            safe_copy(target->smtp_password, sizeof(target->smtp_password),
                      previous_password);
        snprintf(key, sizeof(key), "target_%d_smtp_from", i);
        form_value(body, key, target->smtp_from, sizeof(target->smtp_from));
        snprintf(key, sizeof(key), "target_%d_smtp_to", i);
        form_value(body, key, target->smtp_to, sizeof(target->smtp_to));
        snprintf(key, sizeof(key), "target_%d_smtp_security", i);
        form_value(body, key, target->smtp_security, sizeof(target->smtp_security));

        remove_newlines(target->name);
        remove_newlines(target->webhook);
        remove_newlines(target->custom_ctype);
        remove_newlines(target->custom_body);
        remove_newlines(target->smtp_host);
        remove_newlines(target->smtp_port);
        remove_newlines(target->smtp_user);
        remove_newlines(target->smtp_password);
        remove_newlines(target->smtp_from);
        remove_newlines(target->smtp_to);
        normalize_push_target(target, i);
        clear_target_inactive_fields(target);
        if (i >= count)
            target->enabled = 0;
        if (!target->enabled)
            continue;
        if (!target_configured(target)) {
            ring_log_append("[WEBUI] config save rejected: target %d incomplete", i + 1);
            render_config(fd, target_is_email(target) ?
                          "启用的邮箱任务需要填写 SMTP 服务器、发件人和收件人。" :
                          "启用的 Webhook 任务需要填写 URL。");
            return;
        }
        if (target_is_email(target)) {
            int smtp_port;
            if (parse_port_text(target->smtp_port, &smtp_port) < 0) {
                ring_log_append("[WEBUI] config save rejected: target %d invalid smtp port", i + 1);
                render_config(fd, "邮箱任务的 SMTP 端口无效，请输入 1-65535 的数字。");
                return;
            }
        } else if (strcmp(normalize_platform(target->platform), "custom") == 0 &&
                   !target->custom_body[0]) {
            ring_log_append("[WEBUI] config save rejected: target %d custom body empty", i + 1);
            render_config(fd, "自定义 Webhook 任务的消息体模板不能为空。");
            return;
        }
        active_count++;
    }
    if (!active_count) {
        ring_log_append("[WEBUI] config save rejected: no enabled target");
        render_config(fd, "请至少启用并完成一个推送任务。");
        return;
    }
    if (save_web_config(&cfg) < 0) {
        ring_log_append("[WEBUI] config save failed errno=%d", errno);
        render_config(fd, "配置保存失败，请检查 /mnt/userdata 是否可写。");
        return;
    }
    ring_log_append("[WEBUI] config saved targets=%d enabled=%d", cfg.target_count,
                    active_count);
    render_config(fd, "多推送任务配置已保存。");
}

static int parse_target_index_value(const char *text, int *index) {
    char *end;
    long value;

    if (!text || !text[0]) return -1;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno || end == text || (*end && *end != '&') ||
        value < 0 || value >= ALICE_ENGINE_MAX_TARGETS)
        return -1;
    if (index) *index = (int)value;
    return 0;
}

static int target_index_from_path(const char *path, int *index) {
    const char *query;

    if (!path) return -1;
    query = strchr(path, '?');
    if (!query || strncmp(query + 1, "index=", 6) != 0)
        return -1;
    return parse_target_index_value(query + 7, index);
}

static void load_target_form(const char *body, web_push_target_t *target,
                             int index) {
    char key[64];
    char submitted_password[256];
    char previous_password[256];

    snprintf(key, sizeof(key), "target_%d_enabled", index);
    target->enabled = form_value(body, key, submitted_password,
                                 sizeof(submitted_password)) &&
                      strcmp(submitted_password, "1") == 0;
    snprintf(key, sizeof(key), "target_%d_name", index);
    form_value(body, key, target->name, sizeof(target->name));
    snprintf(key, sizeof(key), "target_%d_num", index);
    form_value(body, key, target->num, sizeof(target->num));
    snprintf(key, sizeof(key), "target_%d_headtxt", index);
    form_value(body, key, target->headtxt, sizeof(target->headtxt));
    snprintf(key, sizeof(key), "target_%d_tailtxt", index);
    form_value(body, key, target->tailtxt, sizeof(target->tailtxt));
    snprintf(key, sizeof(key), "target_%d_type", index);
    form_value(body, key, target->type, sizeof(target->type));
    snprintf(key, sizeof(key), "target_%d_platform", index);
    form_value(body, key, target->platform, sizeof(target->platform));
    snprintf(key, sizeof(key), "target_%d_webhook", index);
    form_value(body, key, target->webhook, sizeof(target->webhook));
    snprintf(key, sizeof(key), "target_%d_custom_ctype", index);
    form_value(body, key, target->custom_ctype, sizeof(target->custom_ctype));
    snprintf(key, sizeof(key), "target_%d_custom_body", index);
    form_value(body, key, target->custom_body, sizeof(target->custom_body));
    snprintf(key, sizeof(key), "target_%d_smtp_host", index);
    form_value(body, key, target->smtp_host, sizeof(target->smtp_host));
    snprintf(key, sizeof(key), "target_%d_smtp_port", index);
    form_value(body, key, target->smtp_port, sizeof(target->smtp_port));
    snprintf(key, sizeof(key), "target_%d_smtp_user", index);
    form_value(body, key, target->smtp_user, sizeof(target->smtp_user));
    safe_copy(previous_password, sizeof(previous_password), target->smtp_password);
    snprintf(key, sizeof(key), "target_%d_smtp_password", index);
    if (!form_value(body, key, submitted_password, sizeof(submitted_password)) ||
        !submitted_password[0])
        safe_copy(target->smtp_password, sizeof(target->smtp_password),
                  previous_password);
    else
        safe_copy(target->smtp_password, sizeof(target->smtp_password),
                  submitted_password);
    snprintf(key, sizeof(key), "target_%d_smtp_from", index);
    form_value(body, key, target->smtp_from, sizeof(target->smtp_from));
    snprintf(key, sizeof(key), "target_%d_smtp_to", index);
    form_value(body, key, target->smtp_to, sizeof(target->smtp_to));
    snprintf(key, sizeof(key), "target_%d_smtp_security", index);
    form_value(body, key, target->smtp_security, sizeof(target->smtp_security));

    remove_newlines(target->name);
    remove_newlines(target->num);
    remove_newlines(target->headtxt);
    remove_newlines(target->tailtxt);
    remove_newlines(target->webhook);
    remove_newlines(target->custom_ctype);
    remove_newlines(target->custom_body);
    remove_newlines(target->smtp_host);
    remove_newlines(target->smtp_port);
    remove_newlines(target->smtp_user);
    remove_newlines(target->smtp_password);
    remove_newlines(target->smtp_from);
    remove_newlines(target->smtp_to);
    normalize_push_target(target, index);
    clear_target_inactive_fields(target);
}

static const char *validate_target(const web_push_target_t *target) {
    if (!target || !target->enabled)
        return NULL;
    if (!target_configured(target))
        return target_is_email(target) ?
               "启用的邮箱任务需要填写 SMTP 服务器、发件人和收件人。" :
               "启用的 Webhook 任务需要填写 URL。";
    if (target_is_email(target)) {
        int smtp_port;
        if (parse_port_text(target->smtp_port, &smtp_port) < 0)
            return "邮箱任务的 SMTP 端口无效，请输入 1-65535 的数字。";
    } else if (strcmp(normalize_platform(target->platform), "custom") == 0 &&
               !target->custom_body[0]) {
        return "自定义 Webhook 任务的消息体模板不能为空。";
    }
    return NULL;
}

static void handle_target_save(int fd, const char *body) {
    web_config_t *cfg = calloc(1, sizeof(*cfg));
    web_push_target_t *target = calloc(1, sizeof(*target));
    char value[64];
    const char *error;
    int index;

    if (!cfg || !target) {
        free(cfg);
        free(target);
        http_send(fd, 500, "Internal Server Error", "text/plain",
                  "out of memory\n");
        return;
    }
    load_web_config(cfg);
    if (!form_value(body, "target_index", value, sizeof(value)) ||
        parse_target_index_value(value, &index) < 0 ||
        index > cfg->target_count) {
        free(cfg);
        free(target);
        render_config(fd, "任务索引无效。");
        return;
    }
    if (index == cfg->target_count) {
        init_push_target(target, index);
        target->enabled = 1;
    } else {
        *target = cfg->targets[index];
    }
    load_target_form(body, target, index);
    form_value(body, "target_mode", cfg->target_mode, sizeof(cfg->target_mode));
    form_value(body, "target_path", cfg->target_path, sizeof(cfg->target_path));
    safe_copy(cfg->target_mode, sizeof(cfg->target_mode),
              normalize_target_mode(cfg->target_mode));
    remove_newlines(cfg->target_path);
    if (strcmp(cfg->target_mode, "custom") != 0) {
        safe_copy(cfg->target_path, sizeof(cfg->target_path),
                  target_default_path(cfg->target_mode));
    } else if (!cfg->target_path[0] || cfg->target_path[0] != '/') {
        ring_log_append("[WEBUI] target save rejected: invalid target path");
        render_target_editor(fd,
                             "自定义进程路径必须填写绝对路径，例如 /sbin/zte_mifi。",
                             index, target, cfg);
        free(cfg);
        free(target);
        return;
    }
    error = validate_target(target);
    if (error) {
        ring_log_append("[WEBUI] target save rejected: index=%d", index);
        render_target_editor(fd, error, index, target, cfg);
        free(cfg);
        free(target);
        return;
    }
    cfg->targets[index] = *target;
    if (index == cfg->target_count)
        cfg->target_count++;
    if (save_web_config(cfg) < 0) {
        ring_log_append("[WEBUI] target save failed index=%d errno=%d", index, errno);
        render_target_editor(fd, "任务保存失败，请检查 /mnt/userdata 是否可写。",
                             index, target, cfg);
        free(cfg);
        free(target);
        return;
    }
    ring_log_append("[WEBUI] target saved index=%d enabled=%d", index,
                    target->enabled);
    free(cfg);
    free(target);
    render_config(fd, "推送任务已保存。");
}

static void handle_target_toggle(int fd, const char *body) {
    web_config_t *cfg = calloc(1, sizeof(*cfg));
    char value[64];
    const char *error;
    int index;

    if (!cfg) {
        http_send(fd, 500, "Internal Server Error", "text/plain",
                  "out of memory\n");
        return;
    }
    load_web_config(cfg);
    if (!form_value(body, "target_index", value, sizeof(value)) ||
        parse_target_index_value(value, &index) < 0 ||
        index >= cfg->target_count) {
        free(cfg);
        render_config(fd, "任务索引无效。");
        return;
    }
    cfg->targets[index].enabled = !cfg->targets[index].enabled;
    normalize_push_target(&cfg->targets[index], index);
    error = validate_target(&cfg->targets[index]);
    if (error) {
        cfg->targets[index].enabled = 0;
        ring_log_append("[WEBUI] target enable rejected: index=%d", index);
        render_target_editor(fd, error, index, &cfg->targets[index], cfg);
        free(cfg);
        return;
    }
    if (save_web_config(cfg) < 0) {
        ring_log_append("[WEBUI] target toggle failed index=%d errno=%d", index, errno);
        free(cfg);
        render_config(fd, "任务状态保存失败，请检查 /mnt/userdata 是否可写。");
        return;
    }
    ring_log_append("[WEBUI] target toggled index=%d enabled=%d", index,
                    cfg->targets[index].enabled);
    {
        const char *message = cfg->targets[index].enabled ?
                              "推送任务已启用。" : "推送任务已停用。";
        free(cfg);
        render_config(fd, message);
    }
}

static void handle_target_delete(int fd, const char *body) {
    web_config_t *cfg = calloc(1, sizeof(*cfg));
    char value[64];
    int index;

    if (!cfg) {
        http_send(fd, 500, "Internal Server Error", "text/plain",
                  "out of memory\n");
        return;
    }
    load_web_config(cfg);
    if (!form_value(body, "target_index", value, sizeof(value)) ||
        parse_target_index_value(value, &index) < 0 ||
        index >= cfg->target_count) {
        free(cfg);
        render_config(fd, "任务索引无效。");
        return;
    }
    if (index + 1 < cfg->target_count)
        memmove(&cfg->targets[index], &cfg->targets[index + 1],
                (size_t)(cfg->target_count - index - 1) * sizeof(cfg->targets[0]));
    cfg->target_count--;
    init_push_target(&cfg->targets[cfg->target_count], cfg->target_count);
    if (save_web_config(cfg) < 0) {
        ring_log_append("[WEBUI] target delete failed index=%d errno=%d", index, errno);
        free(cfg);
        render_config(fd, "任务删除失败，请检查 /mnt/userdata 是否可写。");
        return;
    }
    ring_log_append("[WEBUI] target deleted index=%d", index);
    free(cfg);
    render_config(fd, "推送任务已删除。");
}

static void handle_save_experimental(int fd, const char *self_path,
                                     const char *body) {
    web_config_t cfg;
    char value[16];
    int was_running;

    load_web_config(&cfg);
    form_value(body, "long_sms_reassembly", value, sizeof(value));
    cfg.long_sms_reassembly = strcmp(value, "1") == 0;
    if (save_web_config(&cfg) < 0) {
        ring_log_append("[WEBUI] experimental config save failed errno=%d",
                        errno);
        render_experimental(fd, "保存失败，请检查 userdata 是否可写。", 1);
        return;
    }
    was_running = service_pid() > 0;
    if (was_running) {
        stop_service();
        if (start_service(self_path, &cfg) < 0) {
            ring_log_append("[WEBUI] experimental service restart failed errno=%d",
                            errno);
            render_experimental(fd,
                                "配置已保存，但服务重启失败，短信监控当前未运行。",
                                1);
            return;
        }
    }
    ring_log_append("[WEBUI] long sms reassembly=%d applied restart=%d",
                    cfg.long_sms_reassembly, was_running);
    render_experimental(fd, was_running ?
                        "配置已保存，短信监控服务已重启。" :
                        "配置已保存，下次启动短信监控服务时生效。", 0);
}

static void handle_set_port(int fd, const char *body) {
    web_config_t cfg;
    char value[32];
    char response[1024];
    int port;

    load_web_config(&cfg);
    form_value(body, "port", value, sizeof(value));
    if (parse_port_text(value, &port) < 0) {
        ring_log_append("[WEBUI] port save rejected: invalid value");
        render_config(fd, "端口无效，请输入 1-65535。");
        return;
    }
    cfg.port = port;
    if (save_web_config(&cfg) < 0) {
        ring_log_append("[WEBUI] port save failed port=%d errno=%d", port, errno);
        render_config(fd, "端口保存失败，请检查 /mnt/userdata 是否可写。");
        return;
    }
    if (port == g_webui_port) {
        ring_log_append("[WEBUI] webui port saved unchanged port=%d", port);
        render_config(fd, "WebUI 端口已保存。");
        return;
    }

    snprintf(response, sizeof(response),
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>WebUI 端口已切换</title>"
        "<style>body{margin:0;font-family:Arial,'Microsoft YaHei',sans-serif;background:#f4f8f2;color:#18251d}"
        ".box{max-width:560px;margin:12vh auto;padding:22px;background:#fff;border:1px solid #d9e5dc;border-radius:8px;box-shadow:0 8px 24px rgba(24,37,29,.06)}"
        ".h{font-size:22px;font-weight:800}.p{color:#55685c;line-height:1.7}.a{display:inline-block;margin-top:10px;color:#1f6d42;font-weight:800}</style>"
        "</head><body><div class=\"box\"><div class=\"h\">WebUI 端口已保存</div>"
        "<div class=\"p\">服务正在切换到 %d 端口。请打开新地址继续访问。</div>"
        "<a class=\"a\" href=\"http://127.0.0.1:%d/\">http://127.0.0.1:%d/</a>"
        "</div></body></html>",
        port, port, port);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", response);
    ring_log_append("[WEBUI] webui port changing from %d to %d",
                    g_webui_port, port);
    request_webui_restart(port);
}

static void handle_autostart_on(int fd) {
    web_config_t cfg;

    load_web_config(&cfg);
    if (install_persistent_autostart(&cfg) < 0) {
        ring_log_append("[WEBUI] autostart install failed errno=%d detail=%s",
                        errno, g_autostart_error);
        if (g_autostart_error[0]) {
            char msg[320];
            snprintf(msg, sizeof(msg), "安装失败：%s", g_autostart_error);
            render_home(fd, msg);
        } else {
            render_home(fd, "安装失败，请查看运行日志。");
        }
        return;
    }
    ring_log_append("[WEBUI] persistent autostart installed mode=%s",
                    wonder_deployed() ? "wonder" : "standalone");
    render_home(fd, wonder_deployed() ?
                "已复用 Alice Wonder 启动链路，Pushbot 自启动项已安装。" :
                "Pushbot 独立 path_sh 自启动已安装。");
}

static void handle_autostart_off(int fd) {
    if (disable_autostart() < 0) {
        ring_log_append("[WEBUI] persistent autostart uninstall failed errno=%d",
                        errno);
        render_home(fd, "卸载失败，请检查 userdata 持久分区和运行日志。");
        return;
    }
    ring_log_append("[WEBUI] persistent autostart uninstalled");
    render_home(fd, "Pushbot 持久化自启动已卸载。");
}

static void handle_start(int fd, const char *self_path) {
    web_config_t cfg;
    load_web_config(&cfg);
    if (start_service(self_path, &cfg) < 0) {
        ring_log_append("[WEBUI] start action failed errno=%d", errno);
        render_home(fd, "启动失败：请先保存有效的推送任务，或查看日志。");
        return;
    }
    ring_log_append("[WEBUI] start action completed");
    render_home(fd, "服务已启动。");
}

static void handle_stop(int fd) {
    stop_service();
    ring_log_append("[WEBUI] stop action completed");
    render_home(fd, "服务已停止。");
}

static void handle_restart(int fd, const char *self_path) {
    web_config_t cfg;
    load_web_config(&cfg);
    stop_service();
    if (start_service(self_path, &cfg) < 0) {
        ring_log_append("[WEBUI] restart action failed errno=%d", errno);
        render_home(fd, "重启失败：请先保存有效的推送任务，或查看日志。");
        return;
    }
    ring_log_append("[WEBUI] restart action completed");
    render_home(fd, "服务已重启。");
}

static int run_test_message(const web_config_t *cfg, const char *txt) {
    alice_engine_push_target_t engine_targets[ALICE_ENGINE_MAX_TARGETS];
    size_t target_count;
    int rc;

    if (!cfg || !txt)
        return -1;
    ring_log_append("[WEBUI] test message sending platform=%s",
                    configured_platform_label(cfg));
    alice_engine_set_log_callback(engine_ring_log_callback, NULL);
    target_count = build_engine_target_list(
        cfg, engine_targets, ALICE_ENGINE_MAX_TARGETS);
    rc = alice_engine_send_target_list(engine_targets, target_count, txt);
    ring_log_append("[WEBUI] test message finished rc=%d", rc);
    trim_log_file();
    return rc;
}

static void handle_test(int fd, const char *self_path, const char *body) {
    web_config_t cfg;
    char txt[1024];

    (void)self_path;
    load_web_config(&cfg);
    if (!any_target_configured(&cfg)) {
        ring_log_append("[WEBUI] test message rejected: no push target");
        render_home(fd, "请先保存有效的推送任务。");
        return;
    }
    if (!form_value(body, "txt", txt, sizeof(txt)) || !txt[0])
        safe_copy(txt, sizeof(txt), "Alice Pusher Bot 测试消息");
    remove_newlines(txt);
    if (run_test_message(&cfg, txt) == 0) {
        render_home(fd, "测试消息已发送，请检查当前推送方式的返回和运行日志。");
    } else {
        render_home(fd,
                    "测试消息发送失败：目标设备当前无法连接 Webhook 网络，可能未联网、缺少默认路由或 DNS；请检查设备网络和运行日志。");
    }
}

static void handle_target_test(int fd, const char *body) {
    web_config_t *cfg = calloc(1, sizeof(*cfg));
    web_config_t *test_cfg = calloc(1, sizeof(*test_cfg));
    web_push_target_t *target = calloc(1, sizeof(*target));
    char value[64];
    const char *error;
    int index;

    if (!cfg || !test_cfg || !target) {
        free(cfg);
        free(test_cfg);
        free(target);
        http_send(fd, 500, "Internal Server Error", "text/plain",
                  "out of memory\n");
        return;
    }
    load_web_config(cfg);
    if (!form_value(body, "target_index", value, sizeof(value)) ||
        parse_target_index_value(value, &index) < 0 ||
        index > cfg->target_count) {
        free(cfg);
        free(test_cfg);
        free(target);
        render_config(fd, "任务索引无效。");
        return;
    }
    if (index == cfg->target_count) {
        init_push_target(target, index);
        target->enabled = 1;
    } else {
        *target = cfg->targets[index];
    }
    load_target_form(body, target, index);
    target->enabled = 1;
    form_value(body, "target_mode", cfg->target_mode, sizeof(cfg->target_mode));
    form_value(body, "target_path", cfg->target_path, sizeof(cfg->target_path));
    safe_copy(cfg->target_mode, sizeof(cfg->target_mode),
              normalize_target_mode(cfg->target_mode));
    remove_newlines(cfg->target_path);
    if (strcmp(cfg->target_mode, "custom") != 0) {
        safe_copy(cfg->target_path, sizeof(cfg->target_path),
                  target_default_path(cfg->target_mode));
    } else if (!cfg->target_path[0] || cfg->target_path[0] != '/') {
        render_target_editor(fd,
                             "自定义进程路径必须填写绝对路径，例如 /sbin/zte_mifi。",
                             index, target, cfg);
        free(cfg);
        free(test_cfg);
        free(target);
        return;
    }
    error = validate_target(target);
    if (error) {
        ring_log_append("[WEBUI] target test rejected: index=%d", index);
        render_target_editor(fd, error, index, target, cfg);
        free(cfg);
        free(test_cfg);
        free(target);
        return;
    }

    *test_cfg = *cfg;
    memset(test_cfg->targets, 0, sizeof(test_cfg->targets));
    test_cfg->targets[0] = *target;
    test_cfg->target_count = 1;
    if (run_test_message(test_cfg, "Alice Pusher Bot 测试消息") == 0) {
        ring_log_append("[WEBUI] target test succeeded: index=%d", index);
        render_target_editor(fd, "测试任务已发送，当前配置尚未保存。",
                             index, target, cfg);
    } else {
        ring_log_append("[WEBUI] target test failed: index=%d", index);
        render_target_editor(fd,
                             "测试任务发送失败：目标设备当前无法连接 Webhook 网络，可能未联网、缺少默认路由或 DNS；请检查设备网络和运行日志。当前配置尚未保存。",
                             index, target, cfg);
    }
    free(cfg);
    free(test_cfg);
    free(target);
}

static int read_http_request(int fd, char *req, size_t reqsz, char **body_out) {
    size_t used = 0;
    int content_len = 0;
    char *hdr_end = NULL;

    if (body_out) *body_out = NULL;
    while (used + 1 < reqsz) {
        ssize_t n = recv(fd, req + used, reqsz - used - 1, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) break;
        used += (size_t)n;
        req[used] = 0;
        hdr_end = strstr(req, "\r\n\r\n");
        if (hdr_end) {
            char *cl = strstr(req, "Content-Length:");
            if (!cl) cl = strstr(req, "content-length:");
            if (cl) content_len = atoi(cl + 15);
            if ((size_t)(hdr_end + 4 - req) + (size_t)content_len <= used)
                break;
        }
    }
    if (!hdr_end)
        hdr_end = strstr(req, "\r\n\r\n");
    if (!hdr_end)
        return -1;
    if (body_out)
        *body_out = hdr_end + 4;
    return 0;
}

static void handle_http_client(int fd, const char *self_path) {
    char req[WEB_REQ_MAX];
    char method[8];
    char path[256];
    char *body;

    memset(req, 0, sizeof(req));
    if (read_http_request(fd, req, sizeof(req), &body) < 0) {
        http_send(fd, 400, "Bad Request", "text/plain", "bad request\n");
        return;
    }
    if (sscanf(req, "%7s %255s", method, path) != 2) {
        http_send(fd, 400, "Bad Request", "text/plain", "bad request\n");
        return;
    }
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/") == 0) render_home(fd, NULL);
        else if (strcmp(path, "/config") == 0) render_config(fd, NULL);
        else if (strcmp(path, "/target_new") == 0) {
            web_config_t cfg;
            load_web_config(&cfg);
            render_target_editor(fd, NULL, cfg.target_count, NULL, NULL);
        }
        else if (strncmp(path, "/target_edit?", 13) == 0) {
            int index;
            if (target_index_from_path(path, &index) < 0)
                render_config(fd, "任务索引无效。");
            else
                render_target_editor(fd, NULL, index, NULL, NULL);
        }
        else if (strcmp(path, "/logs/export") == 0) render_log_export(fd);
        else if (strcmp(path, "/logs") == 0) render_logs(fd, NULL);
        else if (strcmp(path, "/experimental") == 0)
            render_experimental(fd, NULL, 0);
        else if (strcmp(path, "/about") == 0) render_about(fd);
        else if (strcmp(path, "/avatar.jpg") == 0) render_avatar(fd);
        else if (strcmp(path, "/sponsor.jpg") == 0) render_sponsor_image(fd);
        else if (strcmp(path, "/status") == 0) render_status_json(fd);
        else if (strcmp(path, "/msisdn") == 0) render_msisdn_json(fd);
        else http_send(fd, 404, "Not Found", "text/plain", "not found\n");
        return;
    }
    if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/save_config") == 0) handle_save_config(fd, body);
        else if (strcmp(path, "/target_test") == 0)
            handle_target_test(fd, body);
        else if (strcmp(path, "/target_save") == 0)
            handle_target_save(fd, body);
        else if (strcmp(path, "/target_toggle") == 0)
            handle_target_toggle(fd, body);
        else if (strcmp(path, "/target_delete") == 0)
            handle_target_delete(fd, body);
        else if (strcmp(path, "/experimental/save") == 0)
            handle_save_experimental(fd, self_path, body);
        else if (strcmp(path, "/set_port") == 0) handle_set_port(fd, body);
        else if (strcmp(path, "/autostart_on") == 0) handle_autostart_on(fd);
        else if (strcmp(path, "/autostart_off") == 0) handle_autostart_off(fd);
        else if (strcmp(path, "/start") == 0) handle_start(fd, self_path);
        else if (strcmp(path, "/stop") == 0) handle_stop(fd);
        else if (strcmp(path, "/restart") == 0) handle_restart(fd, self_path);
        else if (strcmp(path, "/test") == 0) handle_test(fd, self_path, body);
        else if (strcmp(path, "/logs/clear") == 0) handle_clear_logs(fd);
        else http_send(fd, 404, "Not Found", "text/plain", "not found\n");
        return;
    }
    http_send(fd, 405, "Method Not Allowed", "text/plain", "method not allowed\n");
}

static int run_webui(const char *self_path, int port) {
    int sfd;
    int yes = 1;
    struct sockaddr_in addr;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    if (port <= 0 || port > 65535)
        port = DEFAULT_WEBUI_PORT;
    g_webui_port = port;

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) {
        ring_log_append("[WEBUI] socket failed errno=%d", errno);
        perror("socket");
        return 1;
    }
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ring_log_append("[WEBUI] bind failed port=%d errno=%d", port, errno);
        perror("bind");
        close(sfd);
        return 1;
    }
    if (listen(sfd, 8) < 0) {
        ring_log_append("[WEBUI] listen failed port=%d errno=%d", port, errno);
        perror("listen");
        close(sfd);
        return 1;
    }
    ring_log_append("[WEBUI] listening on 0.0.0.0:%d", port);
    printf("Alice Pusher WebUI listening on 0.0.0.0:%d\n", port);
    fflush(stdout);
    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            continue;
        }
        handle_http_client(cfd, self_path);
        close(cfd);
        if (g_webui_restart_requested)
            break;
    }
    close(sfd);
    if (g_webui_restart_requested) {
        restart_webui_process(self_path, g_webui_restart_port);
        _exit(0);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int only_service_mode = 0;
    int only_send_once_mode = 0;
    int webui_mode = 0;
    int webui_port = DEFAULT_WEBUI_PORT;
    web_config_t saved_cfg;
    char *manual_msisdn = NULL;
    char *cli_platform = NULL;
    char *cli_custom_ctype = NULL;
    char *cli_custom_body = NULL;
    char *cli_url = NULL;
    char *cli_msgtype = NULL;
    char *cli_txt = NULL;
    char *cli_headtxt = NULL;
    char *cli_tailtxt = NULL;
    char *cli_target_path = NULL;
    int i;

    load_web_config(&saved_cfg);
    if (saved_cfg.port > 0 && saved_cfg.port <= 65535)
        webui_port = saved_cfg.port;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--webui") == 0) {
            webui_mode = 1;
        }
        if (strcmp(argv[i], "-L") == 0 && i + 1 < argc) {
            webui_port = atoi(argv[++i]);
        }
        if (strncmp(argv[i], "--port=", 7) == 0) {
            webui_port = atoi(argv[i] + 7);
        }
        if ((strcmp(argv[i], "--mode=service_start") == 0)) {
            only_service_mode = 1;
        }
        if ((strcmp(argv[i], "--mode=send_once") == 0)) { // 新增
            only_send_once_mode = 1;
        }
        if (strncmp(argv[i], "--num=", 6) == 0) {
            manual_msisdn = argv[i] + 6;
        }
        if (strncmp(argv[i], "--platform=", 11) == 0) {
            cli_platform = argv[i] + 11;
        }
        if (strncmp(argv[i], "--custom-ctype=", 15) == 0) {
            cli_custom_ctype = argv[i] + 15;
        }
        if (strncmp(argv[i], "--custom-body=", 14) == 0) {
            cli_custom_body = argv[i] + 14;
        }
        if (strncmp(argv[i], "--url=", 6) == 0) {
            cli_url = argv[i] + 6;
        }
        if (strncmp(argv[i], "--msgtype=", 10) == 0) {
            cli_msgtype = argv[i] + 10;
        }
        if (strncmp(argv[i], "--txt=", 6) == 0) {
            cli_txt = argv[i] + 6;
        }
        if (strncmp(argv[i], "--headtxt=", 10) == 0) {
            cli_headtxt = argv[i] + 10;
        }
        if (strncmp(argv[i], "--tailtxt=", 10) == 0) {
            cli_tailtxt = argv[i] + 10;
        }
        if (strncmp(argv[i], "--target-path=", 14) == 0) {
            cli_target_path = argv[i] + 14;
        }
        if (strncmp(argv[i], "--targetbin=", 12) == 0) {
            cli_target_path = argv[i] + 12;
        }
    }
    if (webui_mode) {
        char self_path[512];
        resolve_self_path(self_path, sizeof(self_path), argv[0]);
        return run_webui(self_path, webui_port);
    }
    if (only_service_mode) {
        alice_engine_service_config_t engine_cfg;
        const char *platform;
        if (!cli_url || strlen(cli_url) == 0) {
            fprintf(stderr, "Error: --mode=service_start 时必须指定 --url=<webhook_url> 参数！\n");
            return 1;
        }
        platform = normalize_platform(cli_platform && cli_platform[0] ?
                                      cli_platform :
                                      detect_platform_from_url(cli_url));
        if (!cli_target_path || !cli_target_path[0])
            cli_target_path = TARGET_MIFI_PATH;
        memset(&engine_cfg, 0, sizeof(engine_cfg));
        engine_cfg.webhook = cli_url;
        engine_cfg.platform = platform;
        engine_cfg.target_path = cli_target_path;
        engine_cfg.custom_ctype = cli_custom_ctype;
        engine_cfg.custom_body = cli_custom_body;
        engine_cfg.num = manual_msisdn;
        engine_cfg.headtxt = cli_headtxt;
        engine_cfg.tailtxt = cli_tailtxt;
        engine_cfg.long_sms_reassembly = 1;
        return alice_engine_start_service(&engine_cfg) == 0 ? 0 : 1;
    }
    if (only_send_once_mode || cli_url || cli_txt) {
        const char *platform;
        char final_txt[ALICE_ENGINE_PUSH_MESSAGE_MAX];
        if (!cli_url || !cli_msgtype || !cli_txt) {
            fprintf(stderr, "Usage: %s --mode=send_once --url=<webhook_url> --platform=<dingtalk|feishu|wecom|serverchan|discord|telegram|bark|custom> [--custom-ctype=<content-type>] [--custom-body=<template>] [--headtxt=<prefix>] [--tailtxt=<suffix>] --msgtype=text --txt=<content>\n", argv[0]);
            return 1;
        }
        if (strcmp(cli_msgtype, "text") != 0) {
            fprintf(stderr, "Only msgtype=text is supported.\n");
            return 1;
        }
        platform = normalize_platform(cli_platform && cli_platform[0] ?
                                      cli_platform :
                                      detect_platform_from_url(cli_url));
        alice_engine_build_push_message(final_txt, sizeof(final_txt),
                                        cli_headtxt, cli_txt, cli_tailtxt);
        return alice_engine_send_once(cli_url, platform, final_txt,
                                      cli_custom_ctype, cli_custom_body) == 0 ? 0 : 1;
    }


    fprintf(stderr, "Usage: %s -w | --mode=send_once --url=<webhook_url> --platform=<dingtalk|feishu|wecom|serverchan|discord|telegram|bark|custom> [--custom-ctype=<content-type>] [--custom-body=<template>] [--headtxt=<prefix>] [--tailtxt=<suffix>] --msgtype=text --txt=<content>\n", argv[0]);
    return 1;
}
