#include "bearssl_transport.h"

#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "bearssl.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

typedef struct {
    const br_x509_class *vtable;
    br_x509_decoder_context decoder;
    unsigned cert_index;
    unsigned decoder_error;
} insecure_x509_context;

typedef struct {
    br_ssl_client_context ssl;
    insecure_x509_context x509;
    br_sslio_context io;
    unsigned char buffer[BR_SSL_BUFSIZE_MONO];
} bearssl_state_t;

static void x509_start_chain(const br_x509_class **context,
                             const char *server_name) {
    insecure_x509_context *x509 = (insecure_x509_context *)context;
    (void)server_name;
    x509->cert_index = 0;
    x509->decoder_error = BR_ERR_X509_TRUNCATED;
}

static void x509_start_cert(const br_x509_class **context, uint32_t length) {
    insecure_x509_context *x509 = (insecure_x509_context *)context;
    (void)length;
    if (x509->cert_index == 0)
        br_x509_decoder_init(&x509->decoder, NULL, NULL);
}

static void x509_append(const br_x509_class **context,
                        const unsigned char *data, size_t length) {
    insecure_x509_context *x509 = (insecure_x509_context *)context;
    if (x509->cert_index == 0)
        br_x509_decoder_push(&x509->decoder, data, length);
}

static void x509_end_cert(const br_x509_class **context) {
    insecure_x509_context *x509 = (insecure_x509_context *)context;
    if (x509->cert_index == 0)
        x509->decoder_error =
            (unsigned)br_x509_decoder_last_error(&x509->decoder);
    x509->cert_index++;
}

static unsigned x509_end_chain(const br_x509_class **context) {
    insecure_x509_context *x509 = (insecure_x509_context *)context;
    return x509->cert_index ? x509->decoder_error : BR_ERR_X509_EMPTY_CHAIN;
}

static const br_x509_pkey *x509_get_pkey(
    const br_x509_class *const *context, unsigned *usages) {
    insecure_x509_context *x509 = (insecure_x509_context *)(void *)context;
    if (usages)
        *usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
    return br_x509_decoder_get_pkey(&x509->decoder);
}

static const br_x509_class insecure_x509_vtable = {
    sizeof(insecure_x509_context),
    x509_start_chain,
    x509_start_cert,
    x509_append,
    x509_end_cert,
    x509_end_chain,
    x509_get_pkey
};

static int socket_read(void *context, unsigned char *buffer, size_t length) {
    int fd = *(int *)context;
    for (;;) {
        ssize_t count = recv(fd, buffer, length, 0);
        if (count > 0)
            return (int)count;
        if (count < 0 && errno == EINTR)
            continue;
        return -1;
    }
}

static int socket_write(void *context, const unsigned char *buffer,
                        size_t length) {
    int fd = *(int *)context;
    for (;;) {
        ssize_t count = send(fd, buffer, length, MSG_NOSIGNAL);
        if (count > 0)
            return (int)count;
        if (count < 0 && errno == EINTR)
            continue;
        return -1;
    }
}

void alice_transport_init(alice_transport_t *transport) {
    if (!transport)
        return;
    transport->fd = -1;
    transport->tls_state = NULL;
}

int alice_transport_connect(alice_transport_t *transport, const char *host,
                            const char *port, int timeout_seconds) {
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    struct timeval timeout;
    int result;

    if (!transport || !host || !host[0] || !port || !port[0]) {
        errno = EINVAL;
        return -1;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    result = getaddrinfo(host, port, &hints, &addresses);
    if (result != 0) {
        errno = EHOSTUNREACH;
        return -1;
    }

    timeout.tv_sec = timeout_seconds > 0 ? timeout_seconds : 10;
    timeout.tv_usec = 0;
    for (address = addresses; address; address = address->ai_next) {
        transport->fd = socket(address->ai_family, address->ai_socktype,
                               address->ai_protocol);
        if (transport->fd < 0)
            continue;
        (void)setsockopt(transport->fd, SOL_SOCKET, SO_RCVTIMEO,
                         &timeout, sizeof(timeout));
        (void)setsockopt(transport->fd, SOL_SOCKET, SO_SNDTIMEO,
                         &timeout, sizeof(timeout));
        if (connect(transport->fd, address->ai_addr,
                    address->ai_addrlen) == 0)
            break;
        close(transport->fd);
        transport->fd = -1;
    }
    freeaddrinfo(addresses);
    return transport->fd >= 0 ? 0 : -1;
}

int alice_transport_start_tls(alice_transport_t *transport,
                              const char *server_name) {
    static const uint16_t suites[] = {
        BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        BR_TLS_RSA_WITH_AES_128_GCM_SHA256,
        BR_TLS_RSA_WITH_AES_128_CBC_SHA256,
        BR_TLS_RSA_WITH_AES_128_CBC_SHA
    };
    bearssl_state_t *state;

    if (!transport || transport->fd < 0 || transport->tls_state ||
        !server_name || !server_name[0]) {
        errno = EINVAL;
        return -1;
    }
    state = (bearssl_state_t *)calloc(1, sizeof(*state));
    if (!state)
        return -1;

    br_ssl_client_zero(&state->ssl);
    br_ssl_engine_set_versions(&state->ssl.eng, BR_TLS12, BR_TLS12);
    br_ssl_engine_set_suites(&state->ssl.eng, suites,
                             sizeof(suites) / sizeof(suites[0]));
    br_ssl_engine_set_hash(&state->ssl.eng, br_sha1_ID, &br_sha1_vtable);
    br_ssl_engine_set_hash(&state->ssl.eng, br_sha256_ID,
                           &br_sha256_vtable);
    br_ssl_engine_set_prf_sha256(&state->ssl.eng, &br_tls12_sha256_prf);
    br_ssl_client_set_rsapub(&state->ssl, &br_rsa_i31_public);
    br_ssl_engine_set_rsavrfy(&state->ssl.eng,
                              &br_rsa_i31_pkcs1_vrfy);
    br_ssl_engine_set_ec(&state->ssl.eng, &br_ec_prime_i31);
    br_ssl_engine_set_cbc(&state->ssl.eng,
                          &br_sslrec_in_cbc_vtable,
                          &br_sslrec_out_cbc_vtable);
    br_ssl_engine_set_gcm(&state->ssl.eng,
                          &br_sslrec_in_gcm_vtable,
                          &br_sslrec_out_gcm_vtable);
    br_ssl_engine_set_aes_cbc(&state->ssl.eng,
                              &br_aes_small_cbcenc_vtable,
                              &br_aes_small_cbcdec_vtable);
    br_ssl_engine_set_aes_ctr(&state->ssl.eng, &br_aes_small_ctr_vtable);
    br_ssl_engine_set_ghash(&state->ssl.eng, &br_ghash_ctmul);
    state->x509.vtable = &insecure_x509_vtable;
    br_ssl_engine_set_x509(&state->ssl.eng, &state->x509.vtable);
    br_ssl_engine_set_buffer(&state->ssl.eng, state->buffer,
                             sizeof(state->buffer), 0);
    if (!br_ssl_client_reset(&state->ssl, server_name, 0)) {
        free(state);
        errno = EPROTO;
        return -1;
    }
    br_sslio_init(&state->io, &state->ssl.eng,
                  socket_read, &transport->fd,
                  socket_write, &transport->fd);
    transport->tls_state = state;
    return 0;
}

int alice_transport_write_all(alice_transport_t *transport,
                              const void *data, size_t length) {
    const unsigned char *buffer = (const unsigned char *)data;
    bearssl_state_t *state;

    if (!transport || transport->fd < 0 || (!data && length)) {
        errno = EINVAL;
        return -1;
    }
    state = (bearssl_state_t *)transport->tls_state;
    if (state) {
        if (br_sslio_write_all(&state->io, buffer, length) < 0)
            return -1;
        return br_sslio_flush(&state->io);
    }
    while (length) {
        int count = socket_write(&transport->fd, buffer, length);
        if (count <= 0)
            return -1;
        buffer += count;
        length -= (size_t)count;
    }
    return 0;
}

int alice_transport_read(alice_transport_t *transport, void *data,
                         size_t length) {
    bearssl_state_t *state;

    if (!transport || transport->fd < 0 || !data || !length) {
        errno = EINVAL;
        return -1;
    }
    state = (bearssl_state_t *)transport->tls_state;
    if (state)
        return br_sslio_read(&state->io, data, length);
    return socket_read(&transport->fd, (unsigned char *)data, length);
}

int alice_transport_tls_error(const alice_transport_t *transport) {
    const bearssl_state_t *state;
    if (!transport || !transport->tls_state)
        return 0;
    state = (const bearssl_state_t *)transport->tls_state;
    return br_ssl_engine_last_error(&state->ssl.eng);
}

int alice_transport_is_tls(const alice_transport_t *transport) {
    return transport && transport->tls_state != NULL;
}

void alice_transport_close(alice_transport_t *transport) {
    if (!transport)
        return;
    if (transport->fd >= 0)
        close(transport->fd);
    transport->fd = -1;
    free(transport->tls_state);
    transport->tls_state = NULL;
}
