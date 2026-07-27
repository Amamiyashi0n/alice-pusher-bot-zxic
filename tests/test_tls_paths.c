#include <stdio.h>
#include <string.h>

#include "../src/alice-pusher-bot.c"

int main(int argc, char **argv) {
    int rc;

    if (argc >= 3 && strcmp(argv[1], "webhook") == 0) {
        rc = post_https_body(argv[2], "application/json",
                             "{\"test\":\"bearssl\"}", "custom");
        return rc == 0 ? 0 : 1;
    }
    if (argc >= 3 && strcmp(argv[1], "bark") == 0) {
        rc = alice_engine_send_webhook_msg(argv[2], "bark",
                                           "bearssl bark\n\"quoted\"",
                                           NULL, NULL);
        return rc == 0 ? 0 : 1;
    }
    if (argc >= 3 && strcmp(argv[1], "bark-error") == 0) {
        rc = alice_engine_send_webhook_msg(argv[2], "bark",
                                           "bearssl bark\n\"quoted\"",
                                           NULL, NULL);
        return rc < 0 ? 0 : 1;
    }
    if (argc >= 5 && strcmp(argv[1], "smtp") == 0) {
        rc = smtp_send_message(argv[2], argv[3], "", "",
                               "from@example.test", "to@example.test",
                               argv[4], "bearssl smtp\n.second");
        return rc == 0 ? 0 : 1;
    }
    fprintf(stderr,
            "usage: %s webhook URL | bark|bark-error URL | "
            "smtp HOST PORT starttls|tls\n",
            argv[0]);
    return 2;
}
