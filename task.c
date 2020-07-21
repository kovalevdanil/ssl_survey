#define _GNU_SOURCE

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <malloc.h>
#include "task.h"

void task_init(task_t *task)
{
    if (task == NULL)
        return;

    task->output = NULL;
    task->hostnames = NULL;
    task->count = 0;
}

task_t *task_create()
{
    task_t *task = malloc(sizeof(task_t));
    task_init(task);
    return task;
}

int task_add_hostname(task_t *task, char *hostname)
{
    if (hostname == NULL || task == NULL)
        return -1;
    if (task->count % 10 == 0)
        task->hostnames = realloc(task->hostnames, sizeof(char *) * (task->count + 10));
    task->hostnames[task->count] = strdup(hostname);
    task->count++;

    return 0;
}

int task_read_hostnames(task_t *task, FILE *fp)
{
    if (task == NULL || fp == NULL)
        return -1;


    char *line = NULL;
    ssize_t size = 0;

    while (getline(&line, &size, fp) != -1)
    {
        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';
        task_add_hostname(task, line);
        free(line);
        line = NULL;
        size = 0;
    }

    return 0;
}

int task_copy_hostnames(task_t *task, char **hostnames, size_t n)
{
    if (task == NULL || hostnames == NULL )
        return -1;
    
    for (int i = 0; i < n; i++)
        task_add_hostname(task, hostnames[i]);
    
    return 0;
}

int task_set_output(task_t *task, FILE *fp)
{
    if (fp == NULL)
        return -1;
    task->output = fp;
    return 0;
}

void task_free_hostnames(task_t *task)
{
    if (task == NULL)
        return;
    
    for (int i = 0; i < task -> count; i++)
        free(task -> hostnames[i]);
    task -> count = 0;
}

void task_free(task_t *task)
{
    task_free_hostnames(task);
    free(task);
}