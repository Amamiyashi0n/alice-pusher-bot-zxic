#ifndef ALICE_BEARSSL_TRANSPORT_H
#define ALICE_BEARSSL_TRANSPORT_H

#include <stddef.h>

typedef struct {
    int fd;
    void *tls_state;
} alice_transport_t;

void alice_transport_init(alice_transport_t *transport);
int alice_transport_connect(alice_transport_t *transport, const char *host,
                            const char *port, int timeout_seconds);
int alice_transport_start_tls(alice_transport_t *transport,
                              const char *server_name);
int alice_transport_write_all(alice_transport_t *transport,
                              const void *data, size_t length);
int alice_transport_read(alice_transport_t *transport, void *data,
                         size_t length);
int alice_transport_tls_error(const alice_transport_t *transport);
int alice_transport_is_tls(const alice_transport_t *transport);
void alice_transport_close(alice_transport_t *transport);

#endif
