#ifndef __STRBUF_H
#define __STRBUF_H

typedef struct strbuf
{
    char *buf;
    int len;
    int alloc_len;
} strbuf_t;

strbuf_t *buf_create();
strbuf_t *buf_create_size(int size);
void buf_free(strbuf_t *buf);
void buf_add(strbuf_t *buf, const char *str);

#endif

