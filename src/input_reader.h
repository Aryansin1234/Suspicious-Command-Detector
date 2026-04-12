#ifndef SCD_INPUT_READER_H
#define SCD_INPUT_READER_H

#include "scd.h"

typedef struct {
    FILE   *fp;
    int     is_stdin;
    char    path[MAX_PATH_LEN];
#ifdef __linux__
    int     inotify_fd;
    int     watch_fd;
#endif
} InputReader;

/* Open a file (or stdin if path is NULL). Returns 0 on success. */
int  input_open(InputReader *reader, const char *path);

/* Read next line. Returns 1 on success, 0 on EOF, -1 on error. */
int  input_readline(InputReader *reader, char *buf, size_t buflen);

/* Close the reader. */
void input_close(InputReader *reader);

/* Set up file watching (inotify on Linux, poll fallback on macOS).
   Returns 0 on success. */
int  input_watch_init(InputReader *reader, const char *path);

/* Block until the watched file is modified. Returns 0 on change, -1 on error. */
int  input_watch_wait(InputReader *reader);

/* Clean up watch resources. */
void input_watch_close(InputReader *reader);

#endif /* SCD_INPUT_READER_H */
