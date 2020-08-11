#define _GNU_SOURCE

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <malloc.h>
#include "task.h"

static int count_lines(FILE *fp)
{
    fseek(fp, 0, SEEK_SET);

    char ch;
    int lines = 0;

    while (!feof(fp))
    {
        ch = fgetc(fp);
        if (ch == '\n')
        {
            lines++;
        }
    }

    fseek(fp, 0, SEEK_SET);

    return lines;
}

void task_init(task_t *task)
{
    if (task == NULL)
        return;

    task->output = NULL;
    task->hostnames = NULL;
    task->count = 0;
    task->alloc = 0;
}

task_t *task_create()
{
    task_t *task = malloc(sizeof(task_t));
    task_init(task);
    return task;
}

void task_alloc(task_t *task, size_t size)
{
    task->alloc = task->alloc + size;
    task->hostnames = realloc(task->hostnames, sizeof(char *) * (task->alloc));
}

int task_add_hostname(task_t *task, char *hostname)
{
    if (hostname == NULL || task == NULL)
        return -1;
    if (task->alloc <= task->count)
    {
        task->alloc += 10;
        task->hostnames = realloc(task->hostnames, sizeof(char *) * (task->alloc));
    }
    task->hostnames[task->count] = strdup(hostname);
    task->count++;

    return 0;
}

int task_read_hostnames(task_t *task, FILE *fp)
{
    if (task == NULL || fp == NULL)
        return -1;

    int lines = count_lines(fp);
    task_alloc(task, lines);

    char *line = NULL;
    size_t size = 0;

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
    if (task == NULL || hostnames == NULL)
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
    for (int i = 0; i < task->alloc; i++)
        free(task->hostnames[i]);
    task->count = 0;
    task->alloc = 0;
}

void task_free(task_t *task)
{
    task_free_hostnames(task);
    free(task);
}