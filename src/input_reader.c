/*
 * input_reader.c — File / stdin / inotify reader
 *
 * On Linux, uses inotify for live-tail watching.
 * On macOS / other, falls back to stat()-based polling.
 */

#include "input_reader.h"
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef __linux__
#include <sys/inotify.h>
#endif

/* ── open / read / close ──────────────────────────────────────────── */

int input_open(InputReader *reader, const char *path)
{
    memset(reader, 0, sizeof(*reader));
#ifdef __linux__
    reader->inotify_fd = -1;
    reader->watch_fd   = -1;
#endif

    if (!path || path[0] == '\0') {
        reader->fp       = stdin;
        reader->is_stdin = 1;
        return 0;
    }

    reader->fp = fopen(path, "r");
    if (!reader->fp) {
        perror("scd: cannot open input file");
        return -1;
    }
    strncpy(reader->path, path, MAX_PATH_LEN - 1);
    return 0;
}

int input_readline(InputReader *reader, char *buf, size_t buflen)
{
    if (!reader->fp)
        return -1;
    if (fgets(buf, (int)buflen, reader->fp))
        return 1;
    return feof(reader->fp) ? 0 : -1;
}

void input_close(InputReader *reader)
{
    if (reader->fp && !reader->is_stdin) {
        fclose(reader->fp);
        reader->fp = NULL;
    }
}

/* ── file watching ────────────────────────────────────────────────── */

#ifdef __linux__

int input_watch_init(InputReader *reader, const char *path)
{
    reader->inotify_fd = inotify_init();
    if (reader->inotify_fd < 0) {
        perror("scd: inotify_init");
        return -1;
    }
    reader->watch_fd = inotify_add_watch(reader->inotify_fd, path, IN_MODIFY);
    if (reader->watch_fd < 0) {
        perror("scd: inotify_add_watch");
        close(reader->inotify_fd);
        reader->inotify_fd = -1;
        return -1;
    }
    strncpy(reader->path, path, MAX_PATH_LEN - 1);
    return 0;
}

int input_watch_wait(InputReader *reader)
{
    char buf[4096]
        __attribute__((aligned(__alignof__(struct inotify_event))));
    ssize_t n = read(reader->inotify_fd, buf, sizeof(buf));
    return (n > 0) ? 0 : -1;
}

void input_watch_close(InputReader *reader)
{
    if (reader->watch_fd >= 0)
        inotify_rm_watch(reader->inotify_fd, reader->watch_fd);
    if (reader->inotify_fd >= 0)
        close(reader->inotify_fd);
    reader->inotify_fd = -1;
    reader->watch_fd   = -1;
}

#else  /* macOS / fallback: stat-based polling */

int input_watch_init(InputReader *reader, const char *path)
{
    strncpy(reader->path, path, MAX_PATH_LEN - 1);
    return 0;
}

int input_watch_wait(InputReader *reader)
{
    struct stat st1, st2;
    if (stat(reader->path, &st1) != 0)
        return -1;
    for (;;) {
        usleep(500000);   /* poll every 500 ms */
        if (stat(reader->path, &st2) != 0)
            return -1;
        if (st2.st_mtime != st1.st_mtime || st2.st_size != st1.st_size)
            return 0;
        st1 = st2;
    }
}

void input_watch_close(InputReader *reader)
{
    (void)reader;   /* nothing to clean up on macOS */
}

#endif
