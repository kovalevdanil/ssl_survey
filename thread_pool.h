#ifndef _TPOOL_H__

#define _TPOOL_H__

#include <stdbool.h>
#include <stddef.h>

struct tpool;
typedef struct tpool tpool_t;

typedef void (*thread_func_t) (void *args);

tpool_t *tpool_create(size_t num);
void tpool_destroy(tpool_t *pool);

bool tpool_add_work(tpool_t *tm, thread_func_t func, void *args);
void tpool_wait(tpool_t *tm);


#endif

