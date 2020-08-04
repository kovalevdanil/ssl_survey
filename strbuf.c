#include "strbuf.h"
#include <malloc.h>
#include <string.h>

#define ADDITIONAL_ALLOC 10

strbuf_t *buf_create()
{
    return (strbuf_t *)calloc(1, sizeof(strbuf_t));
}

strbuf_t *buf_create_size(int size)
{
    strbuf_t *buf = buf_create();
    buf->buf = calloc(size, sizeof(char));
    buf->alloc_len = size;

    return buf;
}

void buf_free(strbuf_t *buf)
{
    if (buf == NULL)
        return;

    if (buf->buf != NULL)
        free(buf->buf);
    free(buf);
}

void buf_add(strbuf_t *buf, const char *str)
{
    if (buf == NULL || str == NULL)
        return;

    int str_len = strlen(str);

    if (buf->len + str_len + 1 >= buf->alloc_len)
    {
        buf->buf = realloc(buf->buf, (buf->len + str_len + ADDITIONAL_ALLOC + 1) * sizeof(char));
        buf->alloc_len = buf->len + str_len + ADDITIONAL_ALLOC + 1;
    }

    strncpy(buf->buf + buf->len, str, str_len);
    buf->len = buf->len + str_len;
    buf->buf[buf->len] = '\0';
}
