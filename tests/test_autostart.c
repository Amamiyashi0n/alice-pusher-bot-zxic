#define PUSHER_RC_PATH "/tmp/alice-pusher-bot-test-rc"
#define PROC_MOUNTS_PATH "/tmp/alice-pusher-bot-test-mounts"
#define NV_BINARY_PATH_OVERRIDE "/tmp/alice-pusher-bot-test-nv"
#define TEST_NV_STATE "/tmp/alice-pusher-bot-test-nv-state"
#define main alice_pusher_program_main
#include "../src/webui.c"
#undef main

#include <assert.h>

static void test_write_path(const char *path, const char *text, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    assert(fd >= 0);
    assert(write_all_fd(fd, text, strlen(text)) == 0);
    assert(close(fd) == 0);
    assert(chmod(path, mode) == 0);
}

static void test_write_file(const char *text, mode_t mode) {
    test_write_path(PUSHER_RC_PATH, text, mode);
}

static char *test_read_file(void) {
    char *data = read_file_alloc(PUSHER_RC_PATH, PUSHER_RC_MAX_BYTES, NULL);
    assert(data != NULL);
    return data;
}

static void test_port_conflict_kills_listener(void) {
    int ready[2];
    int sfd;
    int yes = 1;
    int status;
    pid_t child;
    unsigned short port_net;
    struct sockaddr_in addr;

    assert(pipe(ready) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        int child_fd;
        socklen_t addr_len = sizeof(addr);

        close(ready[0]);
        child_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (child_fd < 0)
            _exit(2);
        setsockopt(child_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        if (bind(child_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
            listen(child_fd, 1) < 0 ||
            getsockname(child_fd, (struct sockaddr *)&addr, &addr_len) < 0)
            _exit(3);
        port_net = addr.sin_port;
        if (write(ready[1], &port_net, sizeof(port_net)) !=
            (ssize_t)sizeof(port_net))
            _exit(4);
        close(ready[1]);
        for (;;) pause();
    }

    close(ready[1]);
    assert(read(ready[0], &port_net, sizeof(port_net)) ==
           (ssize_t)sizeof(port_net));
    close(ready[0]);
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sfd >= 0);
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = port_net;
    assert(bind_webui_socket(sfd, &addr, ntohs(port_net)) == 0);
    assert(close(sfd) == 0);
    assert(waitpid(child, &status, 0) == child);
    assert(WIFSIGNALED(status));
}

static int text_count(const char *text, const char *needle) {
    int count = 0;
    size_t len = strlen(needle);

    while ((text = strstr(text, needle)) != NULL) {
        count++;
        text += len;
    }
    return count;
}

int main(void) {
    static const char original[] = "#!/bin/sh\necho before\necho after\n";
    static const char partial[] = "#!/bin/sh\n" PUSHER_RC_BEGIN "\n";
    static const char root_mounts[] =
        "rootfs / rootfs rw 0 0\n"
        "/dev/root / jffs2 ro,relatime 0 0\n";
    static const char writable_tmp_mounts[] =
        "rootfs / rootfs rw 0 0\n"
        "/dev/root / jffs2 ro,relatime 0 0\n"
        "tmpfs /tmp tmpfs rw,relatime 0 0\n";
    static const char nv_script[] =
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "get) cat '" TEST_NV_STATE "' ;;\n"
        "set) printf '%s\\n' \"${2#path_sh=}\" > '" TEST_NV_STATE "' ;;\n"
        "save) exit 0 ;;\n"
        "*) exit 1 ;;\n"
        "esac\n";
    rc_mount_info_t mount_info;
    struct stat st;
    char path_sh[256];
    char *data;

    unlink(PUSHER_RC_PATH);
    unlink(PROC_MOUNTS_PATH);
    unlink(NV_BINARY_PATH_OVERRIDE);
    unlink(TEST_NV_STATE);
    test_write_path(NV_BINARY_PATH_OVERRIDE, nv_script, 0700);
    test_write_path(TEST_NV_STATE, "/sbin\n", 0600);
    assert(read_nv_path_sh(path_sh, sizeof(path_sh)) == 0);
    assert(strcmp(path_sh, "/sbin") == 0);
    assert(set_nv_path_sh(PUSHER_DIR) == 0);
    assert(read_nv_path_sh(path_sh, sizeof(path_sh)) == 0);
    assert(strcmp(path_sh, PUSHER_DIR) == 0);
    assert(set_nv_path_sh("/sbin") == 0);

    assert(webui_auto_install_needed(0, 0, 0) == 1);
    assert(webui_auto_install_needed(0, 0, 1) == 1);
    assert(webui_auto_install_needed(0, 1, 0) == 1);
    assert(webui_auto_install_needed(0, 1, 1) == 0);
    assert(webui_auto_install_needed(1, 0, 0) == 0);
    assert(webui_auto_install_needed(1, 1, 0) == 0);
    assert(userdata_space_sufficient(100, 0, 100) == 1);
    assert(userdata_space_sufficient(99, 1, 100) == 1);
    assert(userdata_space_sufficient(99, 0, 100) == 0);
    test_port_conflict_kills_listener();

    test_write_path(PROC_MOUNTS_PATH, root_mounts, 0600);
    assert(find_rc_mount(&mount_info) == 0);
    assert(strcmp(mount_info.source, "/dev/root") == 0);
    assert(strcmp(mount_info.target, "/") == 0);
    assert(mount_info.was_readonly == 1);
    test_write_path(PROC_MOUNTS_PATH, writable_tmp_mounts, 0600);

    test_write_file(original, 0740);
    assert(rewrite_rc_hook(1, 51402) == 0);
    data = test_read_file();
    assert(strncmp(data, original, strlen(original)) == 0);
    assert(text_count(data, PUSHER_RC_BEGIN) == 1);
    assert(text_count(data, PUSHER_RC_END) == 1);
    assert(strstr(data, "-L 51402") != NULL);
    assert(strstr(data, "--start-service") != NULL);
    free(data);
    assert(stat(PUSHER_RC_PATH, &st) == 0);
    assert((st.st_mode & 07777) == 0740);

    assert(rewrite_rc_hook(1, 51403) == 0);
    data = test_read_file();
    assert(text_count(data, PUSHER_RC_BEGIN) == 1);
    assert(text_count(data, PUSHER_RC_END) == 1);
    assert(strstr(data, "-L 51402") == NULL);
    assert(strstr(data, "-L 51403") != NULL);
    free(data);

    assert(rewrite_rc_hook(0, 0) == 0);
    data = test_read_file();
    assert(strcmp(data, original) == 0);
    free(data);
    assert(rewrite_rc_hook(0, 0) == 0);

    test_write_file(partial, 0740);
    errno = 0;
    assert(rewrite_rc_hook(1, 51402) == -1);
    assert(errno == EINVAL);
    data = test_read_file();
    assert(strcmp(data, partial) == 0);
    free(data);

    assert(unlink(PUSHER_RC_PATH) == 0);
    assert(unlink(PROC_MOUNTS_PATH) == 0);
    assert(unlink(NV_BINARY_PATH_OVERRIDE) == 0);
    assert(unlink(TEST_NV_STATE) == 0);
    puts("autostart rc hook tests: ok");
    return 0;
}
