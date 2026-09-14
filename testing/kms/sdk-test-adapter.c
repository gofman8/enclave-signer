/* Test executable linker wrappers. Production helper source and SDK are unchanged. */
#include <aws/nitro_enclaves/rest.h>
#include <aws/io/tls_channel_handler.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdarg.h>
#include <linux/random.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

struct aws_nitro_enclaves_rest_client *__real_aws_nitro_enclaves_rest_client_new(
    struct aws_nitro_enclaves_rest_client_configuration *configuration);

struct aws_nitro_enclaves_rest_client *__wrap_aws_nitro_enclaves_rest_client_new(
    struct aws_nitro_enclaves_rest_client_configuration *configuration) {
    const char *port_text = getenv("SWAP_KMS_E2E_PORT");
    char *end = NULL;
    long port = port_text == NULL ? 0 : strtol(port_text, &end, 10);
    if (port < 1 || port > 65535 || end == NULL || *end != '\0') return NULL;
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
    struct addrinfo *result = NULL;
    if (getaddrinfo("host.docker.internal", NULL, &hints, &result) != 0) return NULL;
    struct aws_socket_endpoint endpoint = {.port = (uint32_t)port};
    const struct sockaddr_in *address = (const struct sockaddr_in *)result->ai_addr;
    const char *resolved = inet_ntop(AF_INET, &address->sin_addr,
        endpoint.address, sizeof(endpoint.address));
    freeaddrinfo(result);
    if (resolved == NULL) return NULL;
    struct aws_nitro_enclaves_rest_client_configuration local = *configuration;
    local.endpoint = &endpoint;
    local.domain = AWS_SOCKET_IPV4;
    /* Keep configuration.region and host_name: SDK still verifies AWS SNI/Host. */
    return __real_aws_nitro_enclaves_rest_client_new(&local);
}

void __real_aws_tls_ctx_options_init_default_client(
    struct aws_tls_ctx_options *options, struct aws_allocator *allocator);

void __wrap_aws_tls_ctx_options_init_default_client(
    struct aws_tls_ctx_options *options, struct aws_allocator *allocator) {
    __real_aws_tls_ctx_options_init_default_client(options, allocator);
    const char *ca = getenv("SWAP_KMS_E2E_CA_PEM");
    if (ca != NULL && *ca != '\0' &&
        aws_tls_ctx_options_override_default_trust_store_from_path(options, NULL, ca) != AWS_OP_SUCCESS) {
        /* A broken local trust fixture must never silently fall back. */
        abort();
    }
}

int __real_ioctl(int fd, unsigned long request, ...);

int __wrap_ioctl(int fd, unsigned long request, ...) {
    va_list args;
    va_start(args, request);
    void *argument = va_arg(args, void *);
    va_end(args);
    /* The real SDK still obtains random bytes through mock NSM and seeds
     * /dev/random. Its privileged entropy-counter update is simulated locally.
     * Tests never request a capability to modify the host entropy estimate. */
    if (request == RNDADDTOENTCNT) return 0;
    return __real_ioctl(fd, request, argument);
}
