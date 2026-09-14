/* Deterministic malformed-input stress under ASan/UBSan. Never calls AWS/NSM. */
#define main swap_kms_tool_main
#include "../../../enclave/kms-tool/main.c"
#undef main

static uint32_t random_state = 0x73a65b91;
static uint32_t next_random(void) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}

static void exercise(const char *data, size_t size) {
    struct json_object *parsed = parse_json(data, size);
    if (parsed) {
        const char *names[] = {"access_key_id", "secret_access_key", "session_token",
                              "operation", "region", "key_arn", "seed_id", "bitcoin_network"};
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            (void)string_field(parsed, names[i], 0, MESSAGE_LIMIT);
        }
        erase_input_credentials(parsed);
    }
    json_object_put(parsed);
}

int main(void) {
    static const char *corpus[] = {
        "", "{}", "null", "[]", "{", "{\"session_token\":null}",
        "{\"session_token\":\"\\u0000\"}", "{\"session_token\":\"\\ud800\"}",
        "{\"session_token\":\"a\",\"session_token\":\"b\"}",
        "{\"session_token\":123}", "{\"session_token\":true}",
        "{\"session_token\":{\"a\":[[[[[[[[[[]]]]]]]]]]}}",
        "{\"access_key_id\":\"key\",\"secret_access_key\":\"secret\",\"session_token\":\"token\"}",
        "{\"session_token\":\"\\u0020\\n\\r\\t\"} trailing"
    };
    char *data = malloc(MESSAGE_LIMIT + 1);
    if (!data) return EXIT_FAILURE;
    size_t executions = 0;
    for (size_t i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
        size_t size = strlen(corpus[i]);
        for (size_t prefix = 0; prefix <= size; prefix++) {
            exercise(corpus[i], prefix);
            executions++;
        }
        for (size_t mutation = 0; mutation < 1024; mutation++) {
            memcpy(data, corpus[i], size);
            size_t length = size;
            for (size_t j = 0; j < 1 + mutation % 8; j++) {
                size_t position = next_random() % (length + 1);
                data[position] = (char)(next_random() & 255);
                if (position == length) length++;
            }
            exercise(data, length);
            executions++;
        }
    }
    /* Boundary-sized valid strings exercise credential cleanup allocations. */
    const size_t lengths[] = {1, 128, 256, 16384, 65500};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        const char *prefix = "{\"session_token\":\"";
        size_t start = strlen(prefix);
        memcpy(data, prefix, start);
        memset(data + start, 'x', lengths[i]);
        memcpy(data + start + lengths[i], "\"}", 2);
        exercise(data, start + lengths[i] + 2);
        executions++;
    }
    memset(data, '[', MESSAGE_LIMIT);
    exercise(data, MESSAGE_LIMIT);
    executions++;
    free(data);
    printf("%zu deterministic input cases passed ASan/UBSan\n", executions);
    return EXIT_SUCCESS;
}
