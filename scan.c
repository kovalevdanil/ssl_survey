#include <openssl/ssl.h>
#include <openssl/err.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>
#include <string.h>

#include "scan.h"
#include "strbuf.h"

#define PORT "443"

static int inited = 0;
static SSL_CTX *ctx_tls = NULL,
               *ctx_tlsv_1 = NULL,
               *ctx_tlsv_1_1 = NULL,
               *ctx_tlsv_1_2 = NULL;


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

void scan_init()
{
    SSL_load_error_strings();
    SSL_library_init();

    ctx_tls = ctx_create(TLS_client_method());
    ctx_tlsv_1 = ctx_create(TLSv1_client_method());
    ctx_tlsv_1_1 = ctx_create(TLSv1_1_client_method());
    ctx_tlsv_1_2 = ctx_create(TLSv1_2_client_method());

    inited = 1;
}

void scan_free()
{
    if (ctx_tls != NULL)
        SSL_CTX_free(ctx_tls);
    if (ctx_tlsv_1 != NULL)
        SSL_CTX_free(ctx_tlsv_1);
    if (ctx_tlsv_1_1 != NULL)
        SSL_CTX_free(ctx_tlsv_1_1);
    if (ctx_tlsv_1_2 != NULL)
        SSL_CTX_free(ctx_tlsv_1_2);
}

int get_tls_version_num(const char *tls_v)
{
    if (!strcmp(tls_v, "TLSv1"))
        return 0;
    else if (!strcmp(tls_v, "TLSv1.1"))
        return 1;
    else if (!strcmp(tls_v, "TLSv1.2"))
        return 2;
    else if (!strcmp(tls_v, "TLSv1.3"))
        return 3;
    else
        return -1;
}

const char *max_tls_version(char *domain)
{
    BIO *bio = BIO_create_and_connect(ctx_tls, domain);

    if (bio == NULL)
        return NULL;

    SSL *ssl;
    BIO_get_ssl(bio, &ssl);

    const char *version = SSL_get_version(ssl);
    BIO_shutdown_wr(bio);
    BIO_free_all(bio);

    return version;
}

const char *min_tls_version(char *domain)
{
    BIO *bio = NULL;
    SSL *ssl;
    SSL_CTX *ctxs[] = {ctx_tlsv_1, ctx_tlsv_1_1, ctx_tlsv_1_2, ctx_tls};
    for (int i = 0; i < 4 && bio == NULL; i++)
        bio = BIO_create_and_connect(ctxs[i], domain);

    if (bio == NULL)
    {
        return NULL;
    }

    BIO_get_ssl(bio, &ssl);
    const char *min_tls = SSL_get_version(ssl);

    BIO_shutdown_wr(bio);
    BIO_free_all(bio);

    return min_tls;
}

int pubkey_size(char *domain)
{
    BIO *bio;
    SSL *ssl;
    int bits;
    X509 *cert;

    bio = BIO_create_and_connect(ctx_tls, domain);
    BIO_get_ssl(bio, &ssl);
    cert = SSL_get_peer_certificate(ssl);
    bits = EVP_PKEY_bits(X509_get_pubkey(cert));

    X509_free(cert);
    BIO_shutdown_wr(bio);
    BIO_free_all(bio);

    return bits;
}

strbuf_t *ciphers_for_all_tls(char *domain, strbuf_t *buf)
{
    if (buf == NULL)
        buf = buf_create_size(512);
    BIO *bio = NULL;
    SSL *ssl = NULL;
   
    SSL_CTX *ctxs[4] = {ctx_tlsv_1, ctx_tlsv_1_1, ctx_tlsv_1_2, ctx_tls};
    int checked[4] = {0, 0, 0, 0}; // v1 v1_1 v_1_2 v_1_3

    for (int i = 0; i < 4; i++)
    {
        bio = BIO_create_and_connect(ctxs[i], domain);
        if (bio == NULL)
            continue;

        BIO_get_ssl(bio, &ssl);
        const char *version = SSL_get_version(ssl);

        int v = get_tls_version_num(version);
        if (checked[v] == 1)
            continue;
        checked[v] = 1;

        buf_add(buf, "CIPHERS FOR ");
        buf_add(buf, version);
        buf_add(buf, ":\n");

        BIO_shutdown_wr(bio);
        BIO_free_all(bio);
        bio = NULL;
        ssl = NULL;

        STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ctxs[i]);
        int num = sk_SSL_CIPHER_num(ciphers);
        const SSL_CIPHER *cipher;

        for (int j = 0; j < num; j++)
        {
            cipher = sk_SSL_CIPHER_value(ciphers, j);

            bio = BIO_create(ctxs[i], domain);
            BIO_get_ssl(bio, &ssl);
            SSL_set_cipher_list(ssl, SSL_CIPHER_get_name(cipher));

            if (BIO_do_connect(bio) == 1)
            {
                buf_add(buf, "|\t");
                buf_add(buf, SSL_CIPHER_get_name(cipher));
                buf_add(buf, "\n");
            }
        
            BIO_shutdown_wr(bio);
            BIO_free_all(bio);
            bio = NULL;
            ssl = NULL;
        }
    }

    return buf;
}

int scan_domain2(char *domain, FILE *output)
{
    if (inited == 0)
        scan_init();

    BIO *bio = NULL;
    SSL *ssl = NULL;

    if (strstr(domain, "://") != NULL)
        domain = strstr(domain, "://") + 3;

    strbuf_t *buf = buf_create(2048);

    buf_add(buf, "--------\n");
    buf_add(buf, "HOSTNAME: ");
    buf_add(buf, domain);
    buf_add(buf, "\n");

    // max tls version
    const char *max_tls = max_tls_version(domain);
    if (max_tls == NULL)
    {
        buf_add(buf, "TLS is not supported\n");
        return -1;
    }
    
    buf_add(buf, "MAX TLS VERSION: ");
    buf_add(buf, max_tls);
    buf_add(buf, "\n");

    
    // min tls version

    const char *min_tls = min_tls_version(domain);

    if (min_tls == NULL)
    {
        buf_add(buf, "An error occurred\n");
        ERR_print_errors_fp(output);
        return -1;
    }

    buf_add(buf, "MIN TLS VERSION: ");
    buf_add(buf, min_tls);
    buf_add(buf, "\n");

    // pubkey size

    int pkey_size = pubkey_size(domain);
    if (pkey_size == -1)
    {
        fprintf(output, "An error occurred\n");
        ERR_print_errors_fp(output);
        return -1;
    }
    char num[10];
    sprintf(num, "%d", pkey_size);
    buf_add(buf, "PUBKEY SIZE (in bits): ");
    buf_add(buf, num);
    buf_add(buf, "\n");

    // ciphers

    ciphers_for_all_tls(domain, buf);
  
    fprintf(output, "%s", buf -> buf);
    buf_free(buf);

    return 0;
}
