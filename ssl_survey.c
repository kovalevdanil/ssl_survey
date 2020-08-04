#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>
#include <uv.h>

#include "task.h"
#include "scan.h"
#include "strbuf.h"

#define PROGRESS_BAR_LENGTH 20
#define HIDE_CURSOR() printf("\e[?25l")
#define SHOW_CURSOR() printf("\e[?25h")

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

void print_progress(size_t bar_len, size_t num, size_t total)
{
    char prefix[] = "Progress: [";
    char postfix[] = "]";

    size_t percents = (double)num / total * 100;
    char *bar = malloc(sizeof(char) * (bar_len + 1));
    for (int i = 0; i < bar_len; i++)
    {
        bar[i] = ((double)(i + 1) / bar_len) * 100 <= percents ? '#' : '.';
    }
    bar[bar_len] = 0;

    printf("\r%s%s%s %ld/%ld", prefix, bar, postfix, num, total);
    fflush(stdout);
    free(bar);
}

task_t parse_args(int argc, char **argv)
{
    int opt;
    task_t task;
    task_init(&task);

    while ((opt = getopt(argc, argv, "f:o:")) != -1)
    {
        switch (opt)
        {
        case 'f':
        {
            FILE *fp = fopen(optarg, "r");
            if (fp == NULL)
                failure("Unable to open input file");

            if (task_read_hostnames(&task, fp) == -1)
                failure("Error reading hostnames");

            fclose(fp);

            break;
        }
        case 'o':
            if (task.output != NULL)
                failure("Input can be specified once");

            task.output = fopen(optarg, "w");
            if (task.output == NULL)
                failure("Unable to open or create open file");

            break;

        case '?':
            if (optopt == 'f')
                failure("The input filename must be specified");
            else if (optopt == 'o')
                failure("The output filename must be specified");
            else
                failure("Unknown option character\n");

            break;

        default:
            failure("Unknown flag being used");
        }
    }

    if (task.hostnames == NULL)
        for (int i = optind; i < argc; i++)
        {
            task_add_hostname(&task, argv[i]);
        }

    if (task.output == NULL)
        task.output = stdout;

    return task;
}

// --------------- final buffer ---------------

typedef struct final_buffer
{
    strbuf_t **buffers;
    int buf_count;
    int buf_alloc;
    pthread_mutex_t mutex;
} final_buffer_t;

final_buffer_t *final_buffer_create(size_t size)
{
    final_buffer_t *fbuf = calloc(1, sizeof(final_buffer_t));
    fbuf->buffers = calloc(size, sizeof(strbuf_t));
    fbuf->buf_alloc = size;
    pthread_mutex_init(&fbuf->mutex, NULL);
    return fbuf;
}

void final_buffer_add(final_buffer_t *final_buffer, strbuf_t *buffer)
{
    pthread_mutex_lock(&final_buffer->mutex);

    if (final_buffer->buf_count < final_buffer->buf_alloc)
    {
        final_buffer->buffers[final_buffer->buf_count] = buffer;
        final_buffer->buf_count++;
    }

    pthread_mutex_unlock(&final_buffer->mutex);
}

void final_buffer_free(final_buffer_t *buf)
{
    if (buf == NULL)
        return;
    for (int i = 0; i < buf->buf_count; i++)
        buf_free(buf->buffers[i]);
    pthread_mutex_destroy(&buf->mutex);
    free(buf);
}

void final_buffer_print(final_buffer_t *buf, FILE *output)
{
    for (int i = 0; i < buf->buf_count; i++)
        fprintf(output, "%s", buf->buffers[i]->buf);
}

// --------------- scan worker ---------------
typedef struct
{
    char *domain;
    final_buffer_t *final_buffer;
    int *progress;
    pthread_mutex_t *progress_mutex;
} scan_context_t;

scan_context_t *scan_context_create(char *domain, final_buffer_t *fbuf, int *progress, pthread_mutex_t *progress_mutex)
{
    scan_context_t *context = calloc(1, sizeof(scan_context_t));
    context->domain = domain;
    context->final_buffer = fbuf;
    context->progress = progress;
    context->progress_mutex = progress_mutex;

    return context;
}

void scan_worker(uv_work_t *work)
{
    scan_context_t *context = (scan_context_t *)work->data;

    strbuf_t *strbuf = scan_domain(context->domain);

    final_buffer_add(context->final_buffer, strbuf);
}

void scan_worker_end(uv_work_t *work, int status)
{
    scan_context_t *context = ((scan_context_t *)work->data);
    pthread_mutex_t *mutex = context->progress_mutex;
    int *progress = context->progress;

    pthread_mutex_lock(mutex);
    (*progress)++;
    print_progress(PROGRESS_BAR_LENGTH, *progress, context->final_buffer->buf_alloc);
    pthread_mutex_unlock(mutex);
}

int main(int argc, char *argv[])
{
    task_t task = parse_args(argc, argv);

    int progress = 0;
    pthread_mutex_t progress_mutex;
    pthread_mutex_init(&progress_mutex, NULL);

    final_buffer_t *final_buffer = final_buffer_create(task.count);

    uv_loop_t *loop = uv_default_loop();
    uv_work_t *req = calloc(task.count, sizeof(uv_work_t));

    HIDE_CURSOR();
    print_progress(PROGRESS_BAR_LENGTH, 0, task.count);

    for (int i = 0; i < task.count; i++)
    {
        req[i].data = scan_context_create(task.hostnames[i], final_buffer, &progress, &progress_mutex);
        uv_queue_work(loop, &req[i], scan_worker, scan_worker_end);
    }

    uv_run(loop, UV_RUN_DEFAULT);

    SHOW_CURSOR();
    printf("\n");
    final_buffer_print(final_buffer, task.output);

    final_buffer_free(final_buffer);
    for (int i = 0; i < task.count; i++)
        free(req[i].data);
    free(req);
    uv_loop_delete(loop);

    return 0;
}
