#include "thread_pool.h"
#include <pthread.h>
#include <malloc.h>

struct tpool_work
{
    thread_func_t func;
    void *args;
    struct tpool_work *next;
};

typedef struct tpool_work tpool_work_t;

struct tpool
{
    tpool_work_t *work_first;
    tpool_work_t *work_last;

    pthread_mutex_t work_mutex;
    pthread_cond_t work_cond;
    pthread_cond_t working_cond;

    size_t working_count;
    size_t thread_count;
    bool stop;
};

typedef struct tpool tpool_t;


static tpool_work_t* tpool_create_work(thread_func_t func, void *args)
{
    if (func == NULL)
        return NULL;

    tpool_work_t *work = malloc(sizeof(tpool_work_t));
    work -> func = func;
    work -> args = args;
    work -> next = NULL;

    return work;
}

static void tpool_work_destroy(tpool_work_t *work)
{
    if (work == NULL)
        return;
    
    free(work);
}

static tpool_work_t *tpool_get_work(tpool_t *tm)
{
    if (tm == NULL)
        return NULL;
    
    tpool_work_t *work = NULL;

    work = tm -> work_first;
    if (work == NULL)
        return NULL;
    
    if (work -> next == NULL)
    {
        tm -> work_first = NULL;
        tm -> work_last = NULL;
    }
    else 
    {
        tm -> work_first = work -> next;
    }

    return work;
}

static void *tpool_worker(void *arg)
{
    tpool_t *tm = arg;
    tpool_work_t *work;

    while (1)
    {
        pthread_mutex_lock(&(tm -> work_mutex));

        while (tm -> work_first == NULL && !tm -> stop)
            pthread_cond_wait(&(tm -> work_cond), &(tm -> work_mutex));
        
        if (tm -> stop)
            break;

        work = tpool_get_work(tm);
        tm -> working_count++;

        pthread_mutex_unlock(&(tm -> work_mutex));

        if (work != NULL)
        {
            work -> func(work -> args);
            tpool_work_destroy(work);
        }

        pthread_mutex_lock(&(tm -> work_mutex));

        tm -> working_count--;
        if (!tm -> stop && tm -> working_count == 0 && tm -> work_first == NULL)
            pthread_cond_signal(&(tm -> working_cond));

        pthread_mutex_unlock(&(tm -> work_mutex));
    }

    tm -> thread_count--;
    pthread_cond_signal(&(tm -> working_cond));
    pthread_mutex_unlock(&(tm -> work_mutex));

    return NULL;
}


tpool_t *tpool_create(size_t num)
{
    tpool_t *tm;
    pthread_t thread;
    size_t i;

    if (num == 0)
        num = 2;
    
    tm = calloc(1, sizeof(tpool_t));
    tm -> thread_count = num;

    pthread_mutex_init(&(tm -> work_mutex), NULL);
    pthread_cond_init(&(tm -> working_cond), NULL);
    pthread_cond_init(&(tm -> work_cond), NULL);

    for (int i = 0; i < num; i++)
    {
        pthread_create(&thread, NULL, tpool_worker, tm);
        pthread_detach(thread);
    }

    return tm;
}

void tpool_destroy(tpool_t *tm)
{
    tpool_work_t *work;
    tpool_work_t *work_next;

    if (tm == NULL)
        return;
    
    pthread_mutex_lock(&(tm -> work_mutex));
    work = tm -> work_first;
    while (work)
    {
        work_next = work -> next;
        tpool_work_destroy(work);
        work = work_next;
    }
    
    tm -> stop = true;

    pthread_cond_broadcast(&(tm -> work_cond));
    pthread_mutex_unlock(&(tm -> work_mutex));

    tpool_wait(tm);

    pthread_mutex_destroy(&(tm -> work_mutex));
    pthread_cond_destroy(&(tm -> work_cond));
    pthread_cond_destroy(&(tm -> working_cond));

    free(tm);
}

bool tpool_add_work(tpool_t *tm, thread_func_t func, void *args)
{
    if (tm == NULL)
        return false;

    tpool_work_t *work = tpool_create_work(func, args);

    if (work == NULL)
        return false;

    pthread_mutex_lock(&(tm -> work_mutex));
    if (tm -> work_first == NULL)
    {
        tm -> work_first = work;
        tm -> work_last = work;
    }
    else 
    {
        tm -> work_last -> next = work;
        tm -> work_last = work;
    }

    pthread_cond_broadcast(&(tm -> work_cond));
    pthread_mutex_unlock(&(tm -> work_mutex));

    return true;
}

void tpool_wait(tpool_t *tm)
{
    if (tm == NULL)
        return;

    pthread_mutex_lock(&(tm -> work_mutex));
    while (1)
    {
        if ((!tm -> stop && tm -> working_count != 0) || (tm -> stop && tm -> thread_count != 0))
            pthread_cond_wait(&(tm -> work_cond), &(tm -> work_mutex));
        else 
            break;
    }

    pthread_mutex_unlock(&(tm -> work_mutex));
    
}