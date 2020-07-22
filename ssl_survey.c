#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include "task.h"
#include "scan.h"

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
                    failure("An error occured");
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
                    failure("An error occured");
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

int main(int argc, char *argv[])
{
    task_t *task = parse_args(argc, argv);
    scan_init();

    int ret;
    for (int i = 0; i < task->count; i++)
    {
        ret = scan_domain(task->hostnames[i], task->output);
        if (ret == -1)
        {
            fprintf(stderr, "An error occured on hostname %s\n", task -> hostnames[i]);
            break;
        }

        if (task -> output != stdout)
            print_progress(20, i + 1, task -> count);
        else 
            printf("[%d/%d]", i + 1, task -> count);
    }
    printf("\n");

    task_free(task);
    scan_free();
    return 0;
}
