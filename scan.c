#include <openssl/ssl.h>
#include <openssl/err.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>
#include <string.h>

#include "scan.h"

#define PORT "443"

static int inited = 0;
static SSL_CTX *ctx = NULL;

in_addr_t get_addr(char *domain)
{
    char *protocol = strstr(domain, "://");
    if (protocol != NULL)
        domain = protocol + 3;

    struct hostent *host = gethostbyname(domain);

    if (host == NULL)
        exit(EXIT_FAILURE);

    return *(in_addr_t *)host->h_addr_list[0];
}

int connect_to(char *domain, const char *port)
{
    struct sockaddr_in addr;

    int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sfd == -1)
        return -1;

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = get_addr(domain);
    addr.sin_port = htons(atoi(port));

    int ret = connect(sfd, (struct sockaddr *)&addr, sizeof(addr));

    return ret == -1 ? -1 : sfd;
}

int get_pubkey_bits(SSL *ssl)
{
    X509 *cert = SSL_get_peer_certificate(ssl);
    int bits = EVP_PKEY_bits(X509_get_pubkey(cert));
    // X509_free(cert); ??
    return bits;
}

int get_domain_pubkey_bits(SSL_CTX *ctx, char *domain)
{
    int fd, bits;
    fd = connect_to(domain, PORT);

    if (fd == -1)
        return -1;

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1)
        return -1;

    bits = get_pubkey_bits(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);

    return bits;
}

void print_available_ciphers(SSL_CTX *ctx, char *domain, FILE *output)
{
    STACK_OF(SSL_CIPHER) *sk_cipher = SSL_CTX_get_ciphers(ctx);
    int cipher_num = sk_SSL_CIPHER_num(sk_cipher);

    const char *name;
    int count = 0;
    const SSL_CIPHER *current_cipher;
    SSL *ssl;
    int fd;

    for (; count < cipher_num; count++)
    {
        current_cipher = sk_SSL_CIPHER_value(sk_cipher, count);
        name = SSL_CIPHER_get_name(current_cipher);
        ssl = SSL_new(ctx);
        fd = connect_to(domain, PORT);
        if (fd == -1)
            return;

        SSL_set_fd(ssl, fd);
        SSL_set_cipher_list(ssl, name);
        if (SSL_connect(ssl) == 1)
        {
            fprintf(output, "%s ", name);
            fflush(output);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
    }
    fprintf(output, "\n");
}

#if 0
int print_available_tls_versions(SSL_CTX *ctx, char *domain)
{
    int ret, fd;
    const SSL_METHOD *(*methods[])(void) = {TLSv1_method, TLSv1_1_method, TLSv1_2_method};

    for (int i = 0; i < 3; i++)
    {
        fd = connect_to(domain, PORT);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);

        SSL_set_ssl_method(ssl, methods[i]());
        ret = SSL_connect(ssl);

        printf("%s: %s\n", SSL_get_version(ssl), ret == 1 ? "available" : "not available");

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
    }

    return 1;
}
#endif

const char *get_max_tls_version(SSL_CTX *ctx, char *domain)
{
    int fd = connect_to(domain, PORT);
    if (fd == -1)
        return NULL;

    const SSL_METHOD *method = TLS_client_method();
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    int ret = SSL_connect(ssl);

    if (ret != 1)
        return NULL;

    const char *version = SSL_get_version(ssl);
    SSL_shutdown(ssl);

    return version;
}

void scan_init()
{
    SSL_load_error_strings();
    SSL_library_init();

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", NULL))
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    inited = 1;
}

void scan_free()
{
    if (ctx != NULL)
        SSL_CTX_free(ctx);
}

int scan_domain(char *domain, FILE *output)
{
    if (inited == 0)
        scan_init();

    const char *max_tls_version = get_max_tls_version(ctx, domain);

    if (max_tls_version == NULL)
        return -1;

    int bits = get_domain_pubkey_bits(ctx, domain);

    fprintf(output, "-------\n");
    fprintf(output, "HOSTNAME: %s\n", domain);
    fprintf(output, "MAX TLS VERSION: %s\n", max_tls_version);
    fprintf(output, "PUBLIС KEY SIZE (in bits): %d\n", bits);
    fprintf(output, "CIPHERS:\n");
    print_available_ciphers(ctx, domain, output);
    fflush(output);

    return 0;
}
