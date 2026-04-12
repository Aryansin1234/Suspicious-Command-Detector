/*
 * daemon.c — Fork / setsid / PID file / signal handlers
 *
 * Enters a watch-read-parse-match-alert loop that runs until SIGTERM.
 * SIGHUP triggers a rule-config reload.
 */

#include "daemon.h"
#include "input_reader.h"
#include "parser.h"
#include "scorer.h"
#include "alert.h"

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

/* ── signal flags ─────────────────────────────────────────────────── */

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload  = 0;

static void handle_sigterm(int sig) { (void)sig; g_running = 0; }
static void handle_sighup(int sig)  { (void)sig; g_reload  = 1; }

/* ── PID file ─────────────────────────────────────────────────────── */

#define PID_PATH "/tmp/scd.pid"

static int write_pidfile(void)
{
    FILE *fp = fopen(PID_PATH, "w");
    if (!fp) return -1;
    fprintf(fp, "%d\n", getpid());
    fclose(fp);
    return 0;
}

static void remove_pidfile(void) { unlink(PID_PATH); }

/* ── daemonize ────────────────────────────────────────────────────── */

static int daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0)  return -1;
    if (pid > 0)  _exit(0);   /* parent exits */

    if (setsid() < 0) return -1;

    /* second fork to avoid acquiring controlling terminal */
    pid = fork();
    if (pid < 0)  return -1;
    if (pid > 0)  _exit(0);

    /* redirect stdio to /dev/null */
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) close(fd);
    }

    umask(0);
    return 0;
}

/* ── main daemon loop ─────────────────────────────────────────────── */

int daemon_start(const Config *config, Rule rules[], int rule_count,
                 const char wl[][MAX_PATTERN_LEN], int wl_count)
{
    if (daemonize() < 0) {
        perror("scd: daemonize failed");
        return -1;
    }

    write_pidfile();

    struct sigaction sa;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = handle_sigterm;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    sa.sa_handler = handle_sighup;
    sigaction(SIGHUP, &sa, NULL);

    /* open log file (alerts go here instead of stdout) */
    FILE *log_fp = NULL;
    if (config->log_path[0]) {
        log_fp = fopen(config->log_path, "a");
        if (!log_fp) {
            remove_pidfile();
            return -1;
        }
    }

    InputReader reader;
    if (input_watch_init(&reader, config->input_path) < 0) {
        if (log_fp) fclose(log_fp);
        remove_pidfile();
        return -1;
    }

    /* initial full scan */
    if (input_open(&reader, config->input_path) == 0) {
        char line[MAX_CMD_LEN];
        while (input_readline(&reader, line, sizeof(line)) > 0)
            ;   /* skip to end — we only alert on NEW lines */
        /* don't close — keep fp at end for tail */
    }

    /* watch loop */
    while (g_running) {
        if (g_reload) {
            g_reload = 0;
            int new_count = 0;
            rules_load(config->rules_path, rules, &new_count);
            if (new_count > 0)
                rule_count = new_count;
            /* re-open log on SIGHUP (log rotation) */
            if (log_fp) {
                fclose(log_fp);
                log_fp = fopen(config->log_path, "a");
            }
        }

        if (input_watch_wait(&reader) < 0) {
            usleep(1000000);
            continue;
        }

        /* read any new lines appended since last read */
        char line[MAX_CMD_LEN];
        while (input_readline(&reader, line, sizeof(line)) > 0 && g_running) {
            ParsedCommand cmd;
            if (parse_command(line, &cmd) <= 0)
                continue;

            if (wl_count > 0 && whitelist_check(wl, wl_count, cmd.raw))
                continue;

            MatchedRule matches[MAX_MATCHES];
            int mc = 0;
            rules_match(rules, rule_count, &cmd, matches, &mc);
            if (mc == 0)
                continue;

            int score = score_calculate(matches, mc);
            if (score < config->threshold)
                continue;

            Alert alert;
            alert_init(&alert, cmd.raw, matches, mc, score);

            if (log_fp) {
                if (config->format == FORMAT_JSON)
                    alert_print_json(log_fp, &alert);
                else
                    alert_print_text(log_fp, &alert);
            }
            alert_syslog(&alert);
        }
    }

    input_watch_close(&reader);
    input_close(&reader);
    if (log_fp) fclose(log_fp);
    remove_pidfile();
    return 0;
}
