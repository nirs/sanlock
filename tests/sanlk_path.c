#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sanlock.h"
#include "sanlock_resource.h"

#define DSTMAXSIZE 1024

static int __test_passed = 0;

#define check_perror(expression, fmt, args...) \
if (expression) { \
    __test_passed++; \
} \
else {    \
    fprintf(stderr, "%s:%i " fmt "\n", __FILE__, __LINE__, ##args);  \
    exit(1);    \
}

void test_sanlock_path_export(void)
{
    int rv, dst_len;
    char dst_str[DSTMAXSIZE];
    const char *src_str, *dst_exp;

    /* regular behavior, no escapes */
    src_str = "Hello World";
    dst_exp = src_str;
    dst_len = strlen(dst_exp);

    memset(dst_str, 'X', DSTMAXSIZE);

    /* destination too short */
    rv = sanlock_path_export(dst_str, src_str, dst_len);
    check_perror(rv == 0, "sanlock_path_export wrong return code: %u", rv);
    check_perror(dst_str[dst_len] == 'X',
                 "sanlock_path_export buffer overflow");

    /* destination long enough */
    rv = sanlock_path_export(dst_str, src_str, dst_len + 1);
    check_perror(rv == dst_len,
                 "sanlock_path_export wrong return code: %u", rv);
    check_perror(dst_str[dst_len] == '\0',
                 "sanlock_path_import destination not terminated");
    check_perror(!strncmp(dst_str, dst_exp, dst_len),
                 "sanlock_path_export destination is different");

    /* special behavior, escapes */
    src_str = "Hello World:";
    dst_exp = "Hello World\\:";
    dst_len = strlen(dst_exp);

    memset(dst_str, 'X', DSTMAXSIZE);

    /* destination too short */
    rv = sanlock_path_export(dst_str, src_str, dst_len);
    check_perror(rv == 0, "sanlock_path_export wrong return code: %u", rv);
    check_perror(dst_str[dst_len] == 'X',
                 "sanlock_path_export buffer overflow");

    /* destination long enough */
    rv = sanlock_path_export(dst_str, src_str, dst_len + 1);
    check_perror(rv == dst_len,
                 "sanlock_path_export wrong return code: %u", rv);
    check_perror(dst_str[dst_len] == '\0',
                 "sanlock_path_import destination not terminated");
    check_perror(!strncmp(dst_str, dst_exp, dst_len),
                 "sanlock_path_export destination is different");
}

void test_sanlock_path_import(void)
{
    int rv, dst_len;
    char dst_str[DSTMAXSIZE];
    const char *src_str, *dst_exp;

    /* regular behavior, no escapes */
    src_str = "Hello World";
    dst_exp = src_str;
    dst_len = strlen(dst_exp);

    memset(dst_str, 'X', DSTMAXSIZE);

    /* destination too short */
    rv = sanlock_path_import(dst_str, src_str, dst_len);
    check_perror(rv == 0, "sanlock_path_import wrong return code: %u", rv);
    check_perror(dst_str[dst_len] == 'X',
                 "sanlock_path_import buffer overflow");

    /* destination long enough */
    rv = sanlock_path_import(dst_str, src_str, dst_len + 1);
    check_perror(rv == dst_len,
                 "sanlock_path_import wrong return code: %u", rv);
    check_perror(dst_str[dst_len] == '\0',
                 "sanlock_path_import destination not terminated");
    check_perror(!strncmp(dst_str, dst_exp, dst_len),
                 "sanlock_path_import destination is different");

    /* special behavior, escapes */
    src_str = "Hello World\\:";
    dst_exp = "Hello World:";
    dst_len = strlen(dst_exp);

    memset(dst_str, 'X', DSTMAXSIZE);

    /* destination too short */
    rv = sanlock_path_import(dst_str, src_str, dst_len);
    check_perror(rv == 0, "sanlock_path_import wrong return code: %u", rv);
    check_perror(dst_str[dst_len] == 'X',
                 "sanlock_path_import buffer overflow");

    /* destination long enough */
    rv = sanlock_path_import(dst_str, src_str, dst_len + 1);
    check_perror(rv == dst_len,
                 "sanlock_path_import wrong return code: %u", rv);
    check_perror(dst_str[dst_len] == '\0',
                 "sanlock_path_import destination not terminated");
    check_perror(!strncmp(dst_str, dst_exp, dst_len),
                 "sanlock_path_import destination is different");
}

int main(int argc, char *argv[])
{
    test_sanlock_path_export();
    test_sanlock_path_import();
    printf("OK, %i tests sucessfully passed.\n", __test_passed);
    return 0;
}
