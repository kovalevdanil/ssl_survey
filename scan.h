#include <stdio.h>
#include "strbuf.h"

int scan_domain(char *domain, FILE *output);
strbuf_t *scan_domain2(char *domain);
void scan_init();
void scan_free();
