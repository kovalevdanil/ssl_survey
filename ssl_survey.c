#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>
#include "thread_pool.h"

#include "task.h"
#include "scan.h"
#include "strbuf.h"

#define POOL_SIZE 10
#define PROGRESS_BAR_LENGTH 20

void usage(char *program_name)
{
    printf("Usage: %s (list<hosts> | -f FILENAME) [-o FILENAME]...\n", program_name);
    printf("where\n"
           "\tlist<hosts> ::= hostname [...]\n"
           "\t-o FILENAME\t\tto specify output file\n"
           "\t-f FILENAME\t\tto specify input file\n");
}

void failure(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(EXIT_FAILURE);
}

void print_progress(size_t count, size_t num, size_t total)
{
    char prefix[] = "Progress: [";
    char postfix[] = "]";

    size_t percents = (double)num / total * 100;
    char *bar = malloc(sizeof(char) * (count + 1));
    for (int i = 0; i < count; i++)
    {
        bar[i] = ((double)(i + 1) / count) * 100 <= percents ? '#' : '.';
    }
    bar[count] = 0;

    printf("\r%s%s%s %ld/%ld", prefix, bar, postfix, num, total);
    fflush(stdout);
    free(bar);
}

task_t *parse_args(int argc, char **argv)
{
    if (argc == 1)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    task_t *task = task_create();

    for (int i = 1; i < argc; i++)
    {
        if (argv[i][0] == '-')
        {
            if (strcmp(argv[i], "-o") == 0)
            {
                if (i + 1 >= argc)
                {
                    failure("File name should be specified");
                }

                if (task->output != NULL)
                {
                    failure("Output should be specified once");
                }

                FILE *fp = fopen(argv[i + 1], "w");
                if (fp == NULL)
                {
                    failure("Invalid name of output file\n");
                }

                if (task_set_output(task, fp) == -1)
                {
                    fclose(fp);
                    failure("An error occurred");
                }
                i++;
            }
            else if (strcmp(argv[i], "-f") == 0)
            {
                if (i + 1 >= argc)
                {
                    failure("Name of file should be specified");
                }

                FILE *fp = fopen(argv[i + 1], "r");
                if (fp == NULL)
                {
                    failure("Failed opening input file");
                }

                if (task_read_hostnames(task, fp) == -1)
                    failure("An error occurred");
                i++;
            }
            else
            {
                failure("Unknown flag");
            }
        }
        else
        {
            if (task->count != 0)
                failure("List of hosts can be specified only once");

            while (i < argc && argv[i][0] != '-')
                task_add_hostname(task, argv[i++]);
            i--;
        }
    }

    if (task->output == NULL)
        task->output = stdout;

    return task;
}

typedef struct final_buffer
{
    strbuf_t **buffers;
    int buf_count;
} final_buffer_t;

final_buffer_t *final_buffer_create()
{
    return calloc(1, sizeof(final_buffer_t));
}

void final_buffer_add(final_buffer_t *fbuf, strbuf_t *strbuf)
{
    fbuf->buffers = realloc(fbuf->buffers, (fbuf->buf_count) * sizeof(strbuf_t));
    fbuf->buffers[fbuf->buf_count] = strbuf;
    fbuf->buf_count++;
}

void final_buffer_free(final_buffer_t *buf)
{
    if (buf == NULL)
        return;
    for (int i = 0; i < buf->buf_count; i++)
        buf_free(buf->buffers[i]);
    free(buf);
}

void final_buffer_print(final_buffer_t *buf, FILE *output)
{
    for (int i = 0; i < buf->buf_count; i++)
        fprintf(output, "%s", buf->buffers[i]->buf);
}

typedef struct worker_args
{
    FILE *output;
    char *domain;
    pthread_mutex_t *output_mutex;
    int *progress;
    int total;
    final_buffer_t *final_buf;
} worker_args_t;

worker_args_t *worker_args_pack(char *domain, pthread_mutex_t *outm, int *progress, int total, final_buffer_t *fbuf)
{
    worker_args_t *args = malloc(sizeof(worker_args_t));
    args->domain = domain;
    args->output_mutex = outm;
    args->progress = progress;
    args->total = total;
    args->final_buf = fbuf;

    return args;
}

void worker(void *args)
{
    worker_args_t *wargs = (worker_args_t *)args;

    char *domain = wargs->domain;
    strbuf_t *buf = scan_domain2(domain);

    if (buf == NULL)
        return;

    pthread_mutex_lock(wargs->output_mutex);
    (*(wargs->progress))++;
    final_buffer_add(wargs->final_buf, buf);
    print_progress(PROGRESS_BAR_LENGTH, *(wargs->progress), wargs->total);
    pthread_mutex_unlock(wargs->output_mutex);

    free(args);
}

int main(int argc, char *argv[])
{
    task_t *task = parse_args(argc, argv);
    pthread_mutex_t output_mutex;
    tpool_t *pool;
    worker_args_t *wargs;
    int progress = 0;
    final_buffer_t *fbuf;

    pthread_mutex_init(&output_mutex, NULL);
    pool = tpool_create(POOL_SIZE);
    fbuf = final_buffer_create();

    scan_init();
    print_progress(PROGRESS_BAR_LENGTH, 0, task -> count);

    for (int i = 0; i < task->count; i++)
    {
        wargs = worker_args_pack(task->hostnames[i], &output_mutex, &progress, task->count, fbuf);
        tpool_add_work(pool, worker, wargs);
    }

    tpool_wait(pool);
    tpool_destroy(pool);

    final_buffer_print(fbuf, task -> output);

    final_buffer_free(fbuf);
    pthread_mutex_destroy(&output_mutex);
    task_free(task);
    scan_free();

 

    return 0;
}
