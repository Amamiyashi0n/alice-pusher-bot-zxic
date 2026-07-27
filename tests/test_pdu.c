#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/alice-pusher-bot.c"

static void append_hex_byte(char *out, size_t outsz, size_t *used,
                            unsigned int value) {
    int n = snprintf(out + *used, outsz - *used, "%02X", value & 0xff);
    assert(n == 2);
    *used += (size_t)n;
}

static size_t make_pdu(char *out, size_t outsz, unsigned int first_octet,
                       unsigned int dcs, unsigned int udl,
                       const unsigned char *ud, size_t ud_bytes) {
    static const unsigned char sender[] = {0x68, 0x31, 0x08, 0x00, 0x00, 0xf0};
    static const unsigned char timestamp[] = {
        0x42, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    size_t used = 0;
    size_t i;

    out[0] = 0;
    append_hex_byte(out, outsz, &used, 0x00);
    append_hex_byte(out, outsz, &used, first_octet);
    append_hex_byte(out, outsz, &used, 0x0b);
    append_hex_byte(out, outsz, &used, 0x91);
    for (i = 0; i < sizeof(sender); i++)
        append_hex_byte(out, outsz, &used, sender[i]);
    append_hex_byte(out, outsz, &used, 0x00);
    append_hex_byte(out, outsz, &used, dcs);
    for (i = 0; i < sizeof(timestamp); i++)
        append_hex_byte(out, outsz, &used, timestamp[i]);
    append_hex_byte(out, outsz, &used, udl);
    for (i = 0; i < ud_bytes; i++)
        append_hex_byte(out, outsz, &used, ud[i]);
    assert(used + 1 < outsz);
    out[used] = 0;
    return used;
}

static size_t make_ucs2_pdu(char *out, size_t outsz, unsigned int ref,
                            unsigned int ref_bytes, unsigned int total,
                            unsigned int seq, const char *text) {
    unsigned char ud[256];
    size_t ud_bytes;
    size_t i;
    unsigned int first_octet = 0x40;

    if (ref_bytes == 1) {
        ud[0] = 0x05;
        ud[1] = 0x00;
        ud[2] = 0x03;
        ud[3] = (unsigned char)ref;
        ud[4] = (unsigned char)total;
        ud[5] = (unsigned char)seq;
        ud_bytes = 6;
    } else {
        ud[0] = 0x06;
        ud[1] = 0x08;
        ud[2] = 0x04;
        ud[3] = (unsigned char)(ref >> 8);
        ud[4] = (unsigned char)ref;
        ud[5] = (unsigned char)total;
        ud[6] = (unsigned char)seq;
        ud_bytes = 7;
    }
    for (i = 0; text[i]; i++) {
        ud[ud_bytes++] = 0;
        ud[ud_bytes++] = (unsigned char)text[i];
    }
    return make_pdu(out, outsz, first_octet, 0x08, (unsigned int)ud_bytes,
                    ud, ud_bytes);
}

static size_t make_gsm7_pdu(char *out, size_t outsz, unsigned int ref,
                            unsigned int total, unsigned int seq,
                            const char *text) {
    unsigned char ud[256];
    size_t text_len = strlen(text);
    size_t header_bytes = 6;
    size_t total_septets = 7 + text_len;
    size_t ud_bytes = (total_septets * 7 + 7) / 8;
    size_t i;

    memset(ud, 0, sizeof(ud));
    ud[0] = 0x05;
    ud[1] = 0x00;
    ud[2] = 0x03;
    ud[3] = (unsigned char)ref;
    ud[4] = (unsigned char)total;
    ud[5] = (unsigned char)seq;
    for (i = 0; i < text_len; i++) {
        unsigned int value = (unsigned char)text[i] & 0x7f;
        size_t bitpos = header_bytes * 8 + i * 7;
        size_t bit;
        for (bit = 0; bit < 7; bit++) {
            if (value & (1U << bit))
                ud[(bitpos + bit) / 8] |=
                    (unsigned char)(1U << ((bitpos + bit) % 8));
        }
    }
    return make_pdu(out, outsz, 0x40, 0x00, (unsigned int)total_septets,
                    ud, ud_bytes);
}

static void test_ucs2_concat(unsigned int ref, unsigned int ref_bytes) {
    char pdu_one[2048];
    char pdu_two[2048];
    char assembled[SMS_CONCAT_MAX_TEXT + 1];
    sms_info_t one;
    sms_info_t two;

    make_ucs2_pdu(pdu_one, sizeof(pdu_one), ref, ref_bytes, 2, 1, "Hello ");
    make_ucs2_pdu(pdu_two, sizeof(pdu_two), ref, ref_bytes, 2, 2, "world");
    assert(decode_pdu(pdu_one, &one) == 0);
    assert(decode_pdu(pdu_two, &two) == 0);
    assert(one.is_concat && one.concat_seq == 1);
    assert(two.is_concat && two.concat_seq == 2);
    memset(g_concat_assemblies, 0, sizeof(g_concat_assemblies));
    assert(add_concat_segment(&two, assembled, sizeof(assembled)) == 0);
    assert(add_concat_segment(&two, assembled, sizeof(assembled)) == 0);
    assert(add_concat_segment(&one, assembled, sizeof(assembled)) == 1);
    assert(strcmp(assembled, "Hello world") == 0);
}

static void test_gsm7_concat(void) {
    char pdu[2048];
    sms_info_t info;

    make_gsm7_pdu(pdu, sizeof(pdu), 0x55, 1, 1, "HELLO");
    assert(decode_pdu(pdu, &info) == 0);
    assert(info.is_concat && info.concat_ref == 0x55);
    assert(strcmp(info.text, "HELLO") == 0);
}

static void test_bark_webhook(void) {
    char payload[1024];
    char ctype[128];

    assert(strcmp(alice_engine_normalize_platform("bark"), "bark") == 0);
    assert(strcmp(alice_engine_detect_platform_from_url(
                      "https://api.day.app/device-key"), "bark") == 0);
    assert(alice_engine_build_webhook_payload(
               "https://api.day.app/device-key?group=sms", "bark",
               "line 1\n\"line 2\"", NULL, NULL,
               payload, sizeof(payload), ctype, sizeof(ctype)) == 0);
    assert(strcmp(ctype, "application/json;charset=utf-8") == 0);
    assert(strcmp(payload,
                  "{\"title\":\"Alice Pusher\",\"body\":\"line 1\\n\\\"line 2\\\"\","
                  "\"device_key\":\"device-key\"}") == 0);
    assert(alice_engine_build_webhook_payload(
               "https://api.day.app/push", "bark", "test", NULL, NULL,
               payload, sizeof(payload), ctype, sizeof(ctype)) < 0);
    assert(parse_http_status((const unsigned char *)"HTTP/1.1 204 No Content\r\n",
                             25) == 204);
    assert(parse_http_status((const unsigned char *)"HTTP/1.1 400 Bad Request\r\n",
                             26) == 400);
    assert(parse_http_status((const unsigned char *)"not HTTP", 8) < 0);
}

int main(void) {
    test_ucs2_concat(0xaa, 1);
    test_ucs2_concat(0x1234, 2);
    test_gsm7_concat();
    test_bark_webhook();
    puts("pdu tests: ok");
    return 0;
}
