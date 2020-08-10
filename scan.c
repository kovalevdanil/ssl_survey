#include <openssl/ssl.h>
#include <openssl/err.h>

#include <unistd.h>
#include <string.h>

#include "scan.h"
#include "strbuf.h"

#define PORT "443"

#define PROTO_COUNT 6
static int proto_versions[PROTO_COUNT] ={ SSL2_VERSION, SSL3_VERSION, TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION };
static char *proto_names[PROTO_COUNT] ={ "SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" };

BIO *BIO_create(SSL_CTX *ctx, char *hostname)
{
    char name[1024] = "";

    SSL *ssl;
    BIO *bio;

    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    sprintf(name, "%s:%s", hostname, "https");
    BIO_set_conn_hostname(bio, name);

    return bio;
}

BIO *BIO_create_and_connect(SSL_CTX *ctx, char *hostname)
{
    BIO *bio = BIO_create(ctx, hostname);

    if (BIO_do_connect(bio) <= 0)
    {
        BIO_free_all(bio);
        return NULL;
    }

    return bio;
}

SSL_CTX *ctx_create(const SSL_METHOD *method)
{
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    #ifdef TRUST_STORE
    if (!SSL_CTX_load_verify_locations(ctx, TRUST_STORE, NULL))
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    #endif

    return ctx;
}

int domain_check(char *domain)
{
    BIO *bio = NULL;

    SSL_CTX *ctx_max = SSL_CTX_new(TLS_method());
    bio = BIO_create_and_connect(ctx_max, domain);
    if (bio == NULL)
    {
        // error print
        return -1;
    }
    BIO_shutdown_wr(bio);
    BIO_free_all(bio);
    bio = NULL;

    return 0;
}

void create_tls_contexts(SSL_CTX **contexts);
void check_protocol_versions(SSL_CTX **contexts, int *available_proto, char *domain);
int min_proto(int *available_proto);
int max_proto(int *available_proto);
int pubkey_len(SSL_CTX *ctx, char *domain);
int check_all_ciphers(SSL_CTX **contexts, int *available_proto, char *domain, strbuf_t *strbuf);

strbuf_t *scan_domain(char *domain)
{
    if (strstr(domain, "https://") != NULL)
        domain = strstr(domain, "https://") + 8;

    char buf[512] ={ 0 };
    strbuf_t *strbuf = buf_create(2048);
    sprintf(buf, "-----\nHOSTNAME: %s\n", domain);
    buf_add(strbuf, buf);

    if (domain_check(domain) == -1)
    {
        buf_add(strbuf, "TLS is not supported\n");
        return strbuf;
    }

    SSL_CTX *contexts[PROTO_COUNT] ={ NULL };
    int available_proto[PROTO_COUNT] ={ 0 };

    create_tls_contexts(contexts);

    check_protocol_versions(contexts, available_proto, domain);

    int min_ind = min_proto(available_proto);
    int max_ind = max_proto(available_proto);

    if (min_ind == -1)
    {
        buf_add(strbuf, "Error making connections\n");
        goto end;
    }

    int bits = pubkey_len(contexts[max_ind], domain);

    int bytes = sprintf(buf, "MIN TLS VERSION: %s\nMAX TLS VERSION: %s\nPUBKEY SIZE (in bits): %d\n",
        proto_names[min_ind], proto_names[max_ind], bits);
    buf[bytes] = '\0';

    buf_add(strbuf, buf);

    // checking all available ciphers for every tls version
    check_all_ciphers(contexts, available_proto, domain, buf);

    end:
    for (int i = 0; i < PROTO_COUNT; i++)
    {
        SSL_CTX_free(contexts[i]);
    }

    return strbuf;
}

void create_tls_contexts(SSL_CTX **contexts)
{
    for (int i = 0; i < PROTO_COUNT; i++)
    {
        contexts[i] = ctx_create(TLS_method());
        SSL_CTX_set_min_proto_version(contexts[i], proto_versions[i]);
        SSL_CTX_set_max_proto_version(contexts[i], proto_versions[i]);
    }
}

void check_protocol_versions(SSL_CTX **contexts, int *available_proto, char *domain)
{
    BIO *bio = NULL;
    for (int i = 0; i < PROTO_COUNT; i++)
    {
        bio = BIO_create_and_connect(contexts[i], domain);
        if (bio == NULL)
            continue;

        available_proto[i] = 1;

        BIO_shutdown_wr(bio);
        BIO_free_all(bio);
        bio = NULL;
    }
}

int min_max_protocols(int *available_proto, int *min, int *max)
{
    int min_ind = 0, max_ind = PROTO_COUNT - 1;
    while (min_ind < PROTO_COUNT && available_proto[min_ind] == 0)
        min_ind++;

    while (max_ind > 0 && available_proto[max_ind] == 0)
        max_ind--;

    if (min_ind == PROTO_COUNT)
    {
        return -1;
    }

    *min = min_ind;
    *max = max_ind;
}

int min_proto(int *available_proto)
{
    int min_ind = 0;
    while (min_ind < PROTO_COUNT && available_proto[min_ind] == 0)
        min_ind++;
    
    return min_ind == PROTO_COUNT ? -1 : min_ind;
}

int max_proto(int *available_proto)
{
    int max_ind = PROTO_COUNT - 1;
    while (max_ind >= 0 && available_proto[max_ind] == 0)
        max_ind--;
    
    return max_ind;
}

int pubkey_len(SSL_CTX *ctx, char *domain)
{
    X509 *cert;
    SSL *ssl;
    BIO *bio;
    int bits = 0;

    bio = BIO_create_and_connect(ctx, domain);
    BIO_get_ssl(bio, &ssl);
    cert = SSL_get_peer_certificate(ssl);
    bits = EVP_PKEY_bits(X509_get_pubkey(cert));

    X509_free(cert);
    BIO_shutdown_wr(bio);

    return bits;
}

int check_all_ciphers(SSL_CTX **contexts, int *available_proto, char *domain, strbuf_t *strbuf)
{
    BIO *bio;
    SSL *ssl;
    STACK_OF(SSL_CIPHER) * ciphers;
    char buf[312];

    for (int i = 0; i < PROTO_COUNT; i++)
    {
        if (available_proto[i] == 0)
            continue;

        int bytes = sprintf(buf, "CIPHERS FOR %s:\n", proto_names[i]);
        buf[bytes] = '\0';
        buf_add(strbuf, buf);

        ciphers = SSL_CTX_get_ciphers(contexts[i]);
        int ciphers_num = sk_SSL_CIPHER_num(ciphers);
        const SSL_CIPHER *cipher;
        for (int j = 0; j < ciphers_num; j++)
        {
            cipher = sk_SSL_CIPHER_value(ciphers, j);
            bio = BIO_create(contexts[i], domain);
            if (bio == NULL)
                continue;
            BIO_get_ssl(bio, &ssl);
            SSL_set_cipher_list(ssl, SSL_CIPHER_get_name(cipher));
            if (BIO_do_connect(bio) == 1)
            {
                buf_add(strbuf, "|\t");
                buf_add(strbuf, SSL_CIPHER_get_name(cipher));
                buf_add(strbuf, "\n");
            }

            BIO_shutdown_wr(bio);
            BIO_free_all(bio);
            bio = NULL;
            ssl = NULL;
        }
    }
}