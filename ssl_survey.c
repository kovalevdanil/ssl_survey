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
    char *bar = malloc(sizeof(char) * (count));
    for (int i = 0; i < count; i++)
    {
        bar[i] = ((double)i / count) * 100 <= percents ? '#' : '.';
    }

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

FILE *output;
pthread_mutex_t output_mutex;

void worker(void *args)
{
    char *domain = (char *)args;
    strbuf_t *buf = scan_domain2(domain);

    if (buf == NULL)
        return;

    pthread_mutex_lock(&output_mutex);
    fprintf(output, "%s", buf -> buf);
    pthread_mutex_unlock(&output_mutex);

    buf_free(buf);
}

int main(int argc, char *argv[])
{
    task_t *task = parse_args(argc, argv);

    output = task->output;
    pthread_mutex_init(&output_mutex, NULL);
    tpool_t *pool = tpool_create(POOL_SIZE);

    scan_init();

    for (int i = 0; i < task->count; i++)
    {
        tpool_add_work(pool, worker, task->hostnames[i]);
        // ret = scan_domain2(task->hostnames[i], task->output);

        // if (task -> output != stdout)
        //     print_progress(20, i + 1, task -> count);
        // else
        //     printf("[%d/%d]\n", i + 1, task -> count);
    }
    printf("\n");

    if (output != stdout)
        fclose(output);

    tpool_destroy(pool);
    pthread_mutex_destroy(&output_mutex);
    task_free(task);
    scan_free();

    return 0;
}
