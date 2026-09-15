/* Exercise Nitro SDK request completion with the real CRT signer and HTTP
 * transport. The only endpoint is a loopback TCP listener that closes before
 * the request, as a KMS relay can while the helper prepares its Recipient.
 * No wrappers, AWS calls, NSM device, or real credentials are involved. */
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include <aws/nitro_enclaves/rest.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/http/connection.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
static struct aws_http_connection *connection;
static int setup_done, shutdown_done;

static void setup(struct aws_http_connection *conn, int error, void *data) {
    (void)data;
    CHECK(error == 0 && conn);
    CHECK(pthread_mutex_lock(&lock) == 0);
    connection = conn;
    setup_done = 1;
    CHECK(pthread_cond_broadcast(&ready) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
}

static void shutdown_connection(struct aws_http_connection *conn, int error, void *data) {
    (void)conn; (void)error; (void)data;
    CHECK(pthread_mutex_lock(&lock) == 0);
    shutdown_done = 1;
    CHECK(pthread_cond_broadcast(&ready) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(5);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(listen(listener, 1) == 0);
    socklen_t length = sizeof(address);
    CHECK(getsockname(listener, (struct sockaddr *)&address, &length) == 0);

    aws_nitro_enclaves_library_init(NULL);
    struct aws_allocator *allocator = aws_nitro_enclaves_get_allocator();
    struct aws_event_loop_group *group = aws_event_loop_group_new_default(allocator, 1, NULL);
    CHECK(group);
    struct aws_host_resolver_default_options resolver_options = {.el_group = group, .max_entries = 1};
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    CHECK(resolver);
    struct aws_client_bootstrap_options bootstrap_options = {.event_loop_group = group, .host_resolver = resolver};
    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    CHECK(bootstrap);
    struct aws_socket_options socket_options = {.type = AWS_SOCKET_STREAM, .domain = AWS_SOCKET_IPV4, .connect_timeout_ms = 1000};
    struct aws_http_client_connection_options options = {
        .self_size = sizeof(options), .allocator = allocator, .bootstrap = bootstrap,
        .host_name = aws_byte_cursor_from_c_str("127.0.0.1"), .port = ntohs(address.sin_port),
        .socket_options = &socket_options, .initial_window_size = SIZE_MAX,
        .on_setup = setup, .on_shutdown = shutdown_connection,
    };
    CHECK(aws_http_client_connect(&options) == AWS_OP_SUCCESS);
    int peer = accept(listener, NULL, NULL);
    CHECK(peer >= 0);
    CHECK(pthread_mutex_lock(&lock) == 0);
    while (!setup_done) CHECK(pthread_cond_wait(&ready, &lock) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
    CHECK(close(peer) == 0);
    CHECK(close(listener) == 0);
    CHECK(pthread_mutex_lock(&lock) == 0);
    while (!shutdown_done) CHECK(pthread_cond_wait(&ready, &lock) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
    CHECK(!aws_http_connection_is_open(connection));

    struct aws_nitro_enclaves_rest_client client = {
        .allocator = allocator, .connection = connection,
        .region = aws_string_new_from_c_str(allocator, "eu-west-1"),
        .service = aws_string_new_from_c_str(allocator, "kms"),
        .host_name = aws_string_new_from_c_str(allocator, "kms.eu-west-1.amazonaws.com"),
        .credentials = aws_credentials_new(allocator, aws_byte_cursor_from_c_str("AKIDEXAMPLE"),
            aws_byte_cursor_from_c_str("test-only-secret"), aws_byte_cursor_from_c_str("test-only-session"), UINT64_MAX),
    };
    CHECK(client.region && client.service && client.host_name && client.credentials);
    printf("peer closed; requesting %s with real AWS signer and HTTP transport\n", argv[1]);
    struct timespec before, after;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    alarm(3);
    struct aws_nitro_enclaves_rest_response *response = aws_nitro_enclaves_rest_client_request_blocking(
        &client, aws_byte_cursor_from_c_str("POST"), aws_byte_cursor_from_c_str("/"),
        aws_byte_cursor_from_c_str(argv[1]), aws_byte_cursor_from_c_str("{}"));
    alarm(0);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    double seconds = (double)(after.tv_sec - before.tv_sec) + (double)(after.tv_nsec - before.tv_nsec) / 1e9;
    CHECK(response == NULL);
    printf("request returned error=%s in %.6f seconds\n", aws_error_name(aws_last_error()), seconds);
    CHECK(seconds < 1.0);
    aws_http_connection_release(connection);
    aws_string_destroy(client.region);
    aws_string_destroy(client.service);
    aws_string_destroy(client.host_name);
    aws_credentials_release(client.credentials);
    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(group);
    aws_nitro_enclaves_library_clean_up();
    return 0;
}
