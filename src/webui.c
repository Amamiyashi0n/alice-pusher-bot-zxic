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

typedef struct {
    char webhook[1024];
    char platform[32];
    char target_mode[32];
    char target_path[256];
    char custom_ctype[128];
    char custom_body[2048];
    char num[128];
    char headtxt[256];
    char tailtxt[256];
    int port;
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

static const char *normalize_platform(const char *platform) {
    return alice_engine_normalize_platform(platform);
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
    if (!cfg || !cfg->webhook[0])
        return "未配置";
    return platform_label(cfg->platform);
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
        "path_sh=/sbin\n",
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
    int saw_platform = 0;

    memset(cfg, 0, sizeof(*cfg));
    cfg->port = DEFAULT_WEBUI_PORT;
    safe_copy(cfg->platform, sizeof(cfg->platform), "dingtalk");
    safe_copy(cfg->target_mode, sizeof(cfg->target_mode), "mifi");
    safe_copy(cfg->target_path, sizeof(cfg->target_path), TARGET_MIFI_PATH);
    safe_copy(cfg->custom_ctype, sizeof(cfg->custom_ctype),
              "application/json;charset=utf-8");
    safe_copy(cfg->custom_body, sizeof(cfg->custom_body),
              "{\"text\":\"{{json_text}}\"}");
    fp = fopen(DEFAULT_CONFIG_PATH, "r");
    if (!fp) return;
    while (fgets(line, sizeof(line), fp)) {
        char *eq;
        strip_line(line);
        eq = strchr(line, '=');
        if (!eq) continue;
        *eq++ = 0;
        if (strcmp(line, "webhook") == 0)
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
        else if (strcmp(line, "port") == 0) {
            long port;
            char *end;
            errno = 0;
            port = strtol(eq, &end, 10);
            if (!errno && end != eq && port > 0 && port <= 65535)
                cfg->port = (int)port;
        }
    }
    fclose(fp);
    if (!saw_platform) {
        safe_copy(cfg->platform, sizeof(cfg->platform),
                  normalize_platform(detect_platform_from_url(cfg->webhook)));
    }
    safe_copy(cfg->target_mode, sizeof(cfg->target_mode),
              normalize_target_mode(cfg->target_mode));
    remove_newlines(cfg->target_path);
    if (!cfg->target_path[0] || strcmp(cfg->target_mode, "custom") != 0)
        safe_copy(cfg->target_path, sizeof(cfg->target_path),
                  target_default_path(cfg->target_mode));
}

static int save_web_config(const web_config_t *cfg) {
    FILE *fp;
    char esc_body[8192];
    char esc_head[1024];
    char esc_tail[1024];

    if (mkdir_parent_file(DEFAULT_CONFIG_PATH) < 0)
        return -1;
    config_escape(esc_body, sizeof(esc_body), cfg->custom_body);
    config_escape(esc_head, sizeof(esc_head), cfg->headtxt);
    config_escape(esc_tail, sizeof(esc_tail), cfg->tailtxt);
    fp = fopen(DEFAULT_CONFIG_PATH, "w");
    if (!fp) return -1;
    fprintf(fp, "webhook=%s\n", cfg->webhook);
    fprintf(fp, "platform=%s\n", normalize_platform(cfg->platform));
    fprintf(fp, "target_mode=%s\n", normalize_target_mode(cfg->target_mode));
    fprintf(fp, "target_path=%s\n", cfg->target_path);
    fprintf(fp, "custom_ctype=%s\n", cfg->custom_ctype);
    fprintf(fp, "custom_body=%s\n", esc_body);
    fprintf(fp, "num=%s\n", cfg->num);
    fprintf(fp, "headtxt=%s\n", esc_head);
    fprintf(fp, "tailtxt=%s\n", esc_tail);
    fprintf(fp, "port=%d\n", cfg->port > 0 ? cfg->port : DEFAULT_WEBUI_PORT);
    if (fclose(fp) != 0)
        return -1;
    chmod(DEFAULT_CONFIG_PATH, 0600);
    return 0;
}

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
    if (!cfg->webhook[0]) {
        errno = EINVAL;
        ring_log_append("[WEBUI] service start failed: webhook is empty");
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
        char target_path[256];
        int rc;

        signal(SIGCHLD, SIG_DFL);
        signal(SIGHUP, SIG_IGN);
        setsid();

        resolve_target_path(cfg, target_path, sizeof(target_path));
        alice_engine_set_log_callback(engine_ring_log_callback, NULL);
        ring_log_append("[WEBUI] service child started target=%s platform=%s",
                        target_path, normalize_platform(cfg->platform));
        memset(&engine_cfg, 0, sizeof(engine_cfg));
        engine_cfg.webhook = cfg->webhook;
        engine_cfg.platform = normalize_platform(cfg->platform);
        engine_cfg.target_path = target_path;
        engine_cfg.custom_ctype = cfg->custom_ctype;
        engine_cfg.custom_body = cfg->custom_body;
        engine_cfg.num = cfg->num;
        engine_cfg.headtxt = cfg->headtxt;
        engine_cfg.tailtxt = cfg->tailtxt;
        rc = alice_engine_start_service(&engine_cfg);
        _exit(rc == 0 ? 0 : 1);
    }
    write_pid_file(DEFAULT_SERVICE_PID, pid);
    ring_log_append("[WEBUI] service started pid=%ld target=%s platform=%s",
                    (long)pid, target_path_for_log,
                    normalize_platform(cfg->platform));
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
    if (message && message[0])
        html_escape(esc_msg, sizeof(esc_msg), message);
    else
        esc_msg[0] = 0;
    buf_append(body, bodysz,
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>%s - Alice Pusher</title><style>"
        "*{box-sizing:border-box}body{margin:0;font-family:Arial,'Microsoft YaHei',sans-serif;background:#f4f8f2;color:#18251d}a{color:inherit;text-decoration:none}"
        "@keyframes rise{from{opacity:.62;transform:translateY(7px)}to{opacity:1;transform:none}}"
        ".shell{min-height:100vh;display:grid;grid-template-columns:218px minmax(0,1fr)}.side{position:sticky;top:0;height:100vh;background:#fbfdf9;border-right:1px solid #dbe8dc;padding:18px 14px;display:flex;flex-direction:column;gap:16px}"
        ".brand{font-size:19px;font-weight:800}.sub,.hint{font-size:12px;color:#67786b;margin-top:3px;line-height:1.45}.nav{display:flex;flex-direction:column;gap:6px}.nav a{border-radius:8px;padding:10px 11px;color:#405246;font-size:14px;font-weight:700}.nav a.active,.nav a:hover{background:#dcefe2;color:#1e5e3a}.sidecard{margin-top:auto;border:1px solid #dbe8dc;border-radius:8px;background:#fff;padding:12px}"
        ".pill{display:inline-block;border-radius:999px;padding:6px 10px;background:#2f7d4f;color:#fff;font-size:13px;font-weight:800;white-space:nowrap}.pill.off{background:#7b8a80}"
        "main.page{max-width:1120px;width:100%%;margin:0 auto;padding:22px}.topline{display:flex;justify-content:space-between;gap:14px;margin-bottom:16px}.h1{font-size:25px;font-weight:800}.msg{background:#eef8f0;border:1px solid #c9dfd0;border-radius:8px;color:#235a39;padding:12px 14px;margin-bottom:14px;animation:rise .18s ease-out}"
        ".grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.panel{background:#fff;border:1px solid #d9e5dc;border-radius:8px;margin-bottom:14px;box-shadow:0 5px 16px rgba(24,37,29,.045);overflow:hidden;animation:rise .22s ease-out}.formtop{border-bottom:1px solid #e7eee8;padding:14px 16px}.title{font-size:16px;font-weight:800}.pad{padding:16px}.kv{border-bottom:1px solid #edf2ee;padding:8px 0}.k{font-size:12px;color:#6d7b71}.v{font-size:14px;font-weight:800;word-break:break-all;margin-top:3px}"
        "label{display:block;font-size:13px;font-weight:800;margin:11px 0 5px}input,textarea,select{width:100%%;border:1px solid #b8c7bb;border-radius:6px;padding:9px 10px;font-size:14px;background:#fff;outline:none}input,select{height:40px}textarea{min-height:84px;resize:vertical}input:focus,textarea:focus,select:focus{border-color:#2f7d4f;box-shadow:0 0 0 3px #dfeee5}.fieldrow{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center}.fieldrow button{margin:0}.hint.ok{color:#236a40}.hint.warn{color:#9a5a10}"
        ".custombox{display:none;margin-top:10px;padding:12px;border:1px solid #e0eadf;border-radius:8px;background:#fbfdf9;animation:rise .18s ease-out}.custombox.show{display:block}"
        ".actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:14px}button{height:40px;border:1px solid #2f7d4f;border-radius:6px;background:#2f7d4f;color:#fff;font-size:14px;font-weight:800;padding:0 17px;cursor:pointer}button.alt{background:#fff;color:#2f7d4f}pre,.preview{white-space:pre-wrap;word-break:break-word;background:#101811;color:#d9f5df;border-radius:8px;padding:12px;max-height:520px;overflow:auto}.preview{margin-top:8px;min-height:116px;color:#e3f8e7}"
        ".templates{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.tpl{border:1px solid #e0eadf;border-radius:8px;background:#fbfdf9;padding:12px}.tplname{font-size:14px;font-weight:800}.tpltext{font-size:12px;color:#56695e;line-height:1.6;margin-top:5px;word-break:break-all}.tplcode{font-family:monospace;background:#eef6ef;border-radius:6px;padding:5px 6px;color:#234732}"
        ".about{display:grid;grid-template-columns:148px minmax(0,1fr);gap:18px;align-items:center}.avatar{width:132px;height:132px;border-radius:8px;object-fit:cover;border:1px solid #d9e5dc;box-shadow:0 8px 22px rgba(24,37,29,.08)}.aboutname{font-size:20px;font-weight:800;margin-bottom:7px}.signature{margin-top:13px;color:#2f5f40;font-size:15px;font-weight:800;line-height:1.7}.repo{display:inline-block;margin-top:13px;color:#1f6d42;font-weight:800;word-break:break-all}.labelrow{margin-top:13px;color:#5f7166;font-size:13px;font-weight:800}.labelrow .repo{margin-top:0}.supporthead{display:block}.supportdesc{color:#405246;font-size:14px;font-weight:700;line-height:1.75;margin-top:7px}.supportgrid{display:grid;grid-template-columns:220px minmax(0,1fr);gap:14px;align-items:stretch}.supportcard{border:1px solid #e0eadf;border-radius:8px;background:#fbfdf9;padding:14px;min-width:0}.supporttitle{font-size:15px;font-weight:800;margin-bottom:7px}.plainlink{display:inline-block;color:#1f6d42;font-weight:800;word-break:break-all}.qrbox{display:flex;justify-content:center;align-items:center}.qr{display:block;width:100%%;max-width:190px;height:auto;border-radius:8px;border:1px solid #e5dff0;background:#fff;box-shadow:0 8px 18px rgba(24,37,29,.06)}"
        "@media(max-width:820px){.shell{display:block}.side{position:static;height:auto;border-right:0;border-bottom:1px solid #dbe8dc}.nav{flex-direction:row;overflow:auto}.sidecard{display:none}main.page{padding:16px}.grid,.about,.supportgrid,.templates{grid-template-columns:1fr}.topline{display:block}.qr{max-width:220px}}"
        "</style></head><body><div class=\"shell\"><aside class=\"side\">"
        "<div><div class=\"brand\">Alice Pusher</div><div class=\"sub\">短信推送控制台</div></div>"
        "<nav class=\"nav\"><a class=\"%s\" href=\"/\">控制台</a><a class=\"%s\" href=\"/config\">配置</a><a class=\"%s\" href=\"/logs\">运行日志</a><a class=\"%s\" href=\"/about\">关于</a></nav>"
        "<div class=\"sidecard\"><div class=\"hint\">WebUI</div><div class=\"pill\">%d</div></div></aside><main class=\"page\">"
        "<div class=\"topline\"><div><div class=\"h1\">%s</div><div class=\"hint\">%s</div></div></div>",
        title,
        strcmp(active, "home") == 0 ? "active" : "",
        strcmp(active, "config") == 0 ? "active" : "",
        strcmp(active, "logs") == 0 ? "active" : "",
        strcmp(active, "about") == 0 ? "active" : "",
        g_webui_port, title, subtitle);
    if (esc_msg[0])
        buf_append(body, bodysz, "<div class=\"msg\">%s</div>", esc_msg);
}

static void append_page_end(char *body, size_t bodysz) {
    buf_append(body, bodysz,
        "</main></div><script>"
        "function toggleCustom(){var s=document.getElementById('platformSelect'),b=document.getElementById('customFields');if(!s||!b)return;b.className=s.value==='custom'?'custombox show':'custombox';}"
        "function toggleTarget(){var s=document.getElementById('targetModeSelect'),b=document.getElementById('targetCustomFields');if(!s||!b)return;b.className=s.value==='custom'?'custombox show':'custombox';}"
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
        "function updatePreview(){var h=document.getElementById('headInput'),t=document.getElementById('tailInput'),p=document.getElementById('msgPreview'),s=document.getElementById('platformSelect'),w=document.getElementById('webhookInput'),ct=document.getElementById('ctypeInput'),cb=document.getElementById('customBodyInput');if(!p)return;var a=[],text,plat=s?s.value:'dingtalk',ctype='application/json;charset=utf-8',payload='',jt,key,tmpl;if(h&&h.value)a.push(h.value);a.push(sampleText());if(t&&t.value)a.push(t.value);text=a.join('\\n');if(plat==='serverchan'){ctype='application/x-www-form-urlencoded';payload='title=Alice%%20Pusher&desp='+enc(text);}else if(plat==='telegram'){ctype='application/x-www-form-urlencoded';payload='text='+enc(text);}else if(plat==='custom'){ctype=(ct&&ct.value)||'application/json;charset=utf-8';tmpl=(cb&&cb.value)||'{\"text\":\"{{json_text}}\"}';payload=tmpl.split('{{json_text}}').join(jesc(text)).split('{{url_text}}').join(enc(text)).split('{{text}}').join(text);}else{jt=jesc(text);if(plat==='feishu')payload='{\"msg_type\":\"text\",\"content\":{\"text\":\"'+jt+'\"}}';else if(plat==='discord')payload='{\"content\":\"'+jt+'\"}';else if(plat==='bark'){key=barkKey(w&&w.value);payload=key?'{\"title\":\"Alice Pusher\",\"body\":\"'+jt+'\",\"device_key\":\"'+jesc(key)+'\"}':'需要填写 Bark URL 以提取 device_key';}else payload='{\"msgtype\":\"text\",\"text\":{\"content\":\"'+jt+'\"}}';}p.textContent='最终文本:\\n'+text+'\\n\\nContent-Type:\\n'+ctype+'\\n\\nPayload:\\n'+payload;}"
        "toggleCustom();toggleTarget();updatePreview();"
        "</script></body></html>");
}

static void render_home(int fd, const char *message) {
    web_config_t cfg;
    autostart_status_t ast;
    char *body = calloc(1, WEB_BODY_MAX);
    pid_t spid, strpid;
    int target_pid;
    char target_path[256];
    char esc_num[256], esc_hook[256], esc_platform[128];
    char esc_target_label[128], esc_target_path[512];
    char esc_auto_mode[128], esc_auto_payload[512], esc_auto_script[512];
    char esc_auto_error[512];
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
    html_escape(esc_hook, sizeof(esc_hook), cfg.webhook[0] ? "已配置" : "未配置");
    html_escape(esc_platform, sizeof(esc_platform), configured_platform_label(&cfg));
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
        "<div class=\"kv\"><div class=\"k\">目标 PID</div><div class=\"v\">%d</div></div>"
        "<div class=\"kv\"><div class=\"k\">推送平台</div><div class=\"v\">%s</div></div>"
        "<div class=\"kv\"><div class=\"k\">Webhook</div><div class=\"v\">%s</div></div>"
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
        esc_platform, esc_hook, esc_num,
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

static void render_config(int fd, const char *message) {
    web_config_t cfg;
    char *body = calloc(1, WEB_BODY_MAX);
    char *custom_body = calloc(1, 12288);
    char webhook[2048], num[256], head[1024], tail[1024];
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
    snprintf(sample_body, sizeof(sample_body),
             "接收短信设备手机号:%s\n[pdu解码后的信息]\n短消息服务中心:+8613800755500\n发件人:10086\n时间戳:26/06/30 12:00:00\n短信内容:Alice Pusher Bot 示例短信",
             cfg.num[0] ? cfg.num : "N/A");
    alice_engine_build_push_message(sample_final, sizeof(sample_final),
                       cfg.headtxt, sample_body, cfg.tailtxt);
    if (alice_engine_build_webhook_payload(cfg.webhook, cfg.platform, sample_final,
                              cfg.custom_ctype, cfg.custom_body,
                              sample_payload, sizeof(sample_payload),
                              sample_ctype, sizeof(sample_ctype)) < 0) {
        safe_copy(sample_ctype, sizeof(sample_ctype), "-");
        safe_copy(sample_payload, sizeof(sample_payload),
                  "无法生成 Payload：请检查平台、Webhook 或自定义模板。");
    }
    snprintf(sample_preview, sizeof(sample_preview),
             "最终文本:\n%s\n\nContent-Type:\n%s\n\nPayload:\n%s",
             sample_final, sample_ctype, sample_payload);
    html_escape(sample_preview_esc, sizeof(sample_preview_esc), sample_preview);
    port = cfg.port > 0 ? cfg.port : DEFAULT_WEBUI_PORT;
    append_page_start(body, WEB_BODY_MAX, "config", "配置",
                      "保存 webhook、手机号、推送文本和平台", message);
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
        "<label>推送平台</label><select id=\"platformSelect\" name=\"platform\" onchange=\"toggleCustom();updatePreview()\">"
        "<option value=\"dingtalk\"%s>钉钉</option>"
        "<option value=\"feishu\"%s>飞书</option>"
        "<option value=\"wecom\"%s>企业微信</option>"
        "<option value=\"serverchan\"%s>Server 酱</option>"
        "<option value=\"discord\"%s>Discord</option>"
        "<option value=\"telegram\"%s>Telegram Bot</option>"
        "<option value=\"bark\"%s>Bark</option>"
        "<option value=\"custom\"%s>自定义</option>"
        "</select>"
        "<label>Webhook URL</label><textarea id=\"webhookInput\" name=\"webhook\" required oninput=\"updatePreview()\">%s</textarea>"
        "<div id=\"customFields\" class=\"custombox\">"
        "<label>自定义 Content-Type</label><input id=\"ctypeInput\" name=\"custom_ctype\" value=\"%s\" oninput=\"updatePreview()\">"
        "<label>自定义消息体模板</label><textarea id=\"customBodyInput\" name=\"custom_body\" rows=\"8\" oninput=\"updatePreview()\">%s</textarea>"
        "<div class=\"hint\">占位符：{{json_text}} 适合 JSON 字符串，{{url_text}} 适合表单或 URL 编码，{{text}} 为原文。</div>"
        "</div>"
        "<label>设备手机号，可留空自动读取 nv show</label><div class=\"fieldrow\"><input id=\"numInput\" name=\"num\" value=\"%s\" oninput=\"updatePreview()\"><button class=\"alt\" type=\"button\" onclick=\"fetchMsisdn(this)\">获取</button></div><div id=\"numMsg\" class=\"hint\">获取不到时可手动填写，也可以留空。</div>"
        "<label>消息前缀</label><textarea id=\"headInput\" name=\"headtxt\" rows=\"3\" oninput=\"updatePreview()\">%s</textarea>"
        "<label>消息后缀</label><textarea id=\"tailInput\" name=\"tailtxt\" rows=\"3\" oninput=\"updatePreview()\">%s</textarea>"
        "<label>发送内容示例（按当前平台编码）</label><div id=\"msgPreview\" class=\"preview\">%s</div>"
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
        selected_attr(cfg.platform, "dingtalk"),
        selected_attr(cfg.platform, "feishu"),
        selected_attr(cfg.platform, "wecom"),
        selected_attr(cfg.platform, "serverchan"),
        selected_attr(cfg.platform, "discord"),
        selected_attr(cfg.platform, "telegram"),
        selected_attr(cfg.platform, "bark"),
        selected_attr(cfg.platform, "custom"),
        webhook, custom_ctype, custom_body, num,
        head, tail, sample_preview_esc);
    append_page_end(body, WEB_BODY_MAX);
    http_send(fd, 200, "OK", "text/html; charset=utf-8", body);
    free(custom_body);
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
    pid_t spid = service_pid();
    pid_t strpid = alice_engine_get_strace_pid();
    int target_pid;
    char body[2048];

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
    snprintf(body, sizeof(body),
        "{\"service_running\":%s,\"service_pid\":%ld,"
        "\"strace_pid\":%ld,\"target_pid\":%d,\"zte_mifi_pid\":%d,"
        "\"target_mode\":\"%s\",\"target_path\":\"%s\","
        "\"webhook_configured\":%s,\"platform\":\"%s\","
        "\"num\":\"%s\",\"port\":%d,"
        "\"wonder_detected\":%s,\"persistence_mode\":\"%s\","
        "\"payload_ready\":%s,\"payload_path\":\"%s\","
        "\"startup_script_ready\":%s,\"startup_entry_ready\":%s,"
        "\"startup_installed\":%s,\"startup_running\":%s,"
        "\"startup_script_path\":\"%s\",\"userdata_free_bytes\":%lu,"
        "\"payload_required_bytes\":%lu,\"install_error\":\"%s\"}\n",
        spid > 0 ? "true" : "false", (long)spid, (long)strpid,
        target_pid > 0 ? target_pid : 0,
        target_pid > 0 ? target_pid : 0, target_mode, target_path,
        cfg.webhook[0] ? "true" : "false", platform, num, g_webui_port,
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

static void handle_save_config(int fd, const char *body) {
    web_config_t cfg;
    int saved_port;

    load_web_config(&cfg);
    saved_port = cfg.port > 0 ? cfg.port : DEFAULT_WEBUI_PORT;
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
    cfg.port = saved_port;
    remove_newlines(cfg.webhook);
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
    if (!cfg.webhook[0]) {
        ring_log_append("[WEBUI] config save rejected: webhook is empty");
        render_config(fd, "Webhook 不能为空。");
        return;
    }
    if (strcmp(normalize_platform(cfg.platform), "custom") == 0 &&
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
    ring_log_append("[WEBUI] config saved platform=%s target=%s",
                    normalize_platform(cfg.platform),
                    normalize_target_mode(cfg.target_mode));
    render_config(fd, "配置已保存。");
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
        render_home(fd, "启动失败：请先保存有效 Webhook，或查看日志。");
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
        render_home(fd, "重启失败：请先保存有效 Webhook，或查看日志。");
        return;
    }
    ring_log_append("[WEBUI] restart action completed");
    render_home(fd, "服务已重启。");
}

static int run_test_message(const web_config_t *cfg, const char *txt) {
    pid_t pid;
    int status = 0;
    char final_txt[2048];

    alice_engine_build_push_message(final_txt, sizeof(final_txt),
                                    cfg->headtxt, txt, cfg->tailtxt);
    ring_log_append("[WEBUI] test message sending platform=%s",
                    normalize_platform(cfg->platform));

    pid = fork();
    if (pid < 0) {
        ring_log_append("[WEBUI] test message fork failed errno=%d", errno);
        return -1;
    }
    if (pid == 0) {
        int rc;

        alice_engine_set_log_callback(engine_ring_log_callback, NULL);
        ring_log_append("[WEBUI] test message child started platform=%s",
                        normalize_platform(cfg->platform));
        rc = alice_engine_send_once(cfg->webhook, normalize_platform(cfg->platform),
                                    final_txt, cfg->custom_ctype,
                                    cfg->custom_body);
        _exit(rc == 0 ? 0 : 1);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            ring_log_append("[WEBUI] test message wait failed errno=%d", errno);
            return -1;
        }
    }
    if (WIFEXITED(status)) {
        ring_log_append("[WEBUI] test message finished rc=%d",
                        WEXITSTATUS(status));
        trim_log_file();
        return WEXITSTATUS(status);
    }
    ring_log_append("[WEBUI] test message ended abnormally");
    return -1;
}

static void handle_test(int fd, const char *self_path, const char *body) {
    web_config_t cfg;
    char txt[1024];

    (void)self_path;
    load_web_config(&cfg);
    if (!cfg.webhook[0]) {
        ring_log_append("[WEBUI] test message rejected: webhook is empty");
        render_home(fd, "请先保存 Webhook。");
        return;
    }
    if (!form_value(body, "txt", txt, sizeof(txt)) || !txt[0])
        safe_copy(txt, sizeof(txt), "Alice Pusher Bot 测试消息");
    remove_newlines(txt);
    if (run_test_message(&cfg, txt) == 0) {
        render_home(fd, "测试消息已发送，请检查 Webhook 返回和运行日志。");
    } else {
        render_home(fd, "测试消息发送失败，请检查 Webhook 和运行日志。");
    }
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
        else if (strcmp(path, "/logs/export") == 0) render_log_export(fd);
        else if (strcmp(path, "/logs") == 0) render_logs(fd, NULL);
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
        return alice_engine_start_service(&engine_cfg) == 0 ? 0 : 1;
    }
    if (only_send_once_mode || cli_url || cli_txt) {
        const char *platform;
        char final_txt[2048];
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
