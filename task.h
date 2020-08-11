#ifndef __TASK_H
#define __TASK_H

#include <stdio.h>

typedef struct 
{
    FILE *output;
    char **hostnames;
    int count;
    int alloc;
} task_t;


void task_init(task_t *task);
task_t *task_create();
int task_read_hostnames(task_t *task, FILE *fp);
int task_copy_hostnames(task_t *task, char **hostnames, size_t n);
int task_add_hostname(task_t *task, char *hostname);
int task_set_output(task_t *task, FILE *fp); 
void task_alloc(task_t *task, size_t size);
void task_free_hostnames(task_t *task);
void task_free(task_t *task);

#endif