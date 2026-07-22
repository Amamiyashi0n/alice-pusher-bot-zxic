#ifndef ALICE_PUSHER_BOT_H
#define ALICE_PUSHER_BOT_H

#include <stddef.h>
#include <sys/types.h>

#define ALICE_TARGET_MIFI_PATH "/sbin/zte_mifi"
#define ALICE_TARGET_UFI_PATH "/sbin/zte_ufi"
#define ALICE_ENGINE_MAX_TARGETS 4
#define ALICE_ENGINE_SMS_MAX_BYTES 4096
#define ALICE_ENGINE_PUSH_MESSAGE_MAX 6144
#define ALICE_ENGINE_PAYLOAD_MAX 24576
#define ALICE_ENGINE_CONCAT_MAX_PARTS 16
#define ALICE_ENGINE_CONCAT_MAX_ACTIVE 4
#define ALICE_ENGINE_CONCAT_TIMEOUT_SECONDS 120

typedef struct {
    int enabled;
    const char *name;
    const char *num;
    const char *headtxt;
    const char *tailtxt;
    const char *type;
    const char *platform;
    const char *webhook;
    const char *custom_ctype;
    const char *custom_body;
    const char *smtp_host;
    const char *smtp_port;
    const char *smtp_user;
    const char *smtp_password;
    const char *smtp_from;
    const char *smtp_to;
    const char *smtp_security;
} alice_engine_push_target_t;

typedef struct {
    const char *webhook;
    const char *platform;
    const char *target_path;
    const char *custom_ctype;
    const char *custom_body;
    const char *num;
    const char *headtxt;
    const char *tailtxt;
    const char *smtp_host;
    const char *smtp_port;
    const char *smtp_user;
    const char *smtp_password;
    const char *smtp_from;
    const char *smtp_to;
    const char *smtp_security;
    const alice_engine_push_target_t *targets;
    size_t target_count;
    int long_sms_reassembly;
} alice_engine_service_config_t;

typedef void (*alice_engine_log_fn)(void *ctx, const char *line);

void alice_engine_set_log_callback(alice_engine_log_fn fn, void *ctx);
const char *alice_engine_normalize_platform(const char *platform);
const char *alice_engine_detect_platform_from_url(const char *url);
void alice_engine_build_push_message(char *out, size_t outsz,
                                     const char *headtxt,
                                     const char *body,
                                     const char *tailtxt);
int alice_engine_build_push_message_checked(char *out, size_t outsz,
                                            const char *headtxt,
                                            const char *body,
                                            const char *tailtxt);
int alice_engine_build_webhook_payload(const char *webhook,
                                       const char *platform,
                                       const char *txt,
                                       const char *custom_ctype,
                                       const char *custom_body,
                                       char *payload,
                                       size_t payload_sz,
                                       char *ctype,
                                       size_t ctype_sz);
int alice_engine_send_webhook_msg(const char *webhook,
                                  const char *platform,
                                  const char *txt,
                                  const char *custom_ctype,
                                  const char *custom_body);
int alice_engine_send_once(const char *webhook,
                           const char *platform,
                           const char *txt,
                           const char *custom_ctype,
                           const char *custom_body);
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
                              const char *smtp_security);
int alice_engine_send_target_list(const alice_engine_push_target_t *targets,
                                  size_t target_count,
                                  const char *txt);
int alice_engine_start_service(const alice_engine_service_config_t *cfg);
void alice_engine_stop(void);
void alice_engine_cleanup_strace_child(const char *target_path);
int alice_engine_load_device_msisdn(char *out, size_t outsz);
pid_t alice_engine_get_strace_pid(void);
int alice_engine_process_alive(pid_t pid);
int alice_engine_find_process_by_exe_path(const char *exe_path);

#endif
