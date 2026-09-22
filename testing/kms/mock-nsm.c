/* Local E2E only. This is explicitly mocked CBOR, never Nitro attestation. */
#include <nsm.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

struct writer { uint8_t *data; size_t used, capacity; int failed; };

static void append(struct writer *w, const void *value, size_t len) {
    if (w->failed || len > w->capacity - w->used) { w->failed = 1; return; }
    memcpy(w->data + w->used, value, len);
    w->used += len;
}

static void head(struct writer *w, uint8_t major, size_t len) {
    uint8_t bytes[3];
    size_t count = 1;
    if (len < 24) bytes[0] = (major << 5) | (uint8_t)len;
    else if (len <= 255) { bytes[0] = (major << 5) | 24; bytes[1] = (uint8_t)len; count = 2; }
    else if (len <= 65535) {
        bytes[0] = (major << 5) | 25;
        bytes[1] = (uint8_t)(len >> 8); bytes[2] = (uint8_t)len; count = 3;
    } else { w->failed = 1; return; }
    append(w, bytes, count);
}

static void text(struct writer *w, const char *value) {
    head(w, 3, strlen(value)); append(w, value, strlen(value));
}

static void bytes(struct writer *w, const uint8_t *value, size_t len) {
    if (value == NULL) { const uint8_t null = 0xf6; append(w, &null, 1); return; }
    head(w, 2, len); append(w, value, len);
}

static int nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

int32_t nsm_lib_init(void) { return 1; }
void nsm_lib_exit(int32_t fd) { (void)fd; }

ErrorCode nsm_get_random(int32_t fd, uint8_t *data, size_t *data_len) {
    (void)fd;
    if (data == NULL || data_len == NULL || *data_len > 256) return (ErrorCode)1;
    size_t offset = 0;
    while (offset < *data_len) {
        ssize_t count = getrandom(data + offset, *data_len - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return (ErrorCode)1;
        offset += (size_t)count;
    }
    return (ErrorCode)0;
}

ErrorCode nsm_get_attestation_doc(int32_t fd, const uint8_t *user_data,
    uint32_t user_data_len, const uint8_t *nonce_data, uint32_t nonce_len,
    const uint8_t *public_key, uint32_t public_key_len,
    uint8_t *document, uint32_t *document_len) {
    (void)fd;
    const char *hex = getenv("KMS_E2E_PCR0");
    uint8_t pcr[48];
    if (hex == NULL || strlen(hex) != 96 || document == NULL || document_len == NULL ||
        public_key == NULL || public_key_len == 0 || public_key_len > 4096 ||
        nonce_len > 512 || user_data_len > 512) return (ErrorCode)1;
    for (size_t i = 0; i < sizeof(pcr); i++) {
        int high = nibble(hex[i * 2]), low = nibble(hex[i * 2 + 1]);
        if (high < 0 || low < 0) return (ErrorCode)1;
        pcr[i] = (uint8_t)((high << 4) | low);
    }
    struct writer w = {document, 0, *document_len, 0};
    head(&w, 5, 6);
    text(&w, "module_id"); text(&w, "mock");
    text(&w, "digest"); text(&w, "SHA384");
    text(&w, "pcrs"); head(&w, 5, 1); head(&w, 0, 0); bytes(&w, pcr, sizeof(pcr));
    text(&w, "nonce"); bytes(&w, nonce_data, nonce_len);
    text(&w, "public_key"); bytes(&w, public_key, public_key_len);
    text(&w, "user_data"); bytes(&w, user_data, user_data_len);
    if (w.failed) return (ErrorCode)1;
    *document_len = (uint32_t)w.used;
    return (ErrorCode)0;
}
