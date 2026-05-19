/*
 * main.c — SCD Entry Point (Simple Interactive Shell)
 *
 * Usage: ./scd [rules_file]
 *
 * Launches the SCD Guard Shell which intercepts commands,
 * analyzes them, and warns before executing suspicious ones.
 */

#include "scd.h"
#include "parser.h"
#include "rule_engine.h"
#include "scorer.h"

#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

/* ── Utility functions ────────────────────────────────────────────── */

const char *risk_level_to_str(RiskLevel level)
{
    switch (level) {
    case RISK_LOW:      return "LOW";
    case RISK_MEDIUM:   return "MEDIUM";
    case RISK_HIGH:     return "HIGH";
    case RISK_CRITICAL: return "CRITICAL";
    default:            return "UNKNOWN";
    }
}

RiskLevel str_to_risk_level(const char *str)
{
    if (strcasecmp(str, "CRITICAL") == 0) return RISK_CRITICAL;
    if (strcasecmp(str, "HIGH")     == 0) return RISK_HIGH;
    if (strcasecmp(str, "MEDIUM")   == 0) return RISK_MEDIUM;
    if (strcasecmp(str, "LOW")      == 0) return RISK_LOW;
    return RISK_UNKNOWN;
}

int risk_level_score(RiskLevel level)
{
    switch (level) {
    case RISK_CRITICAL: return SCORE_CRITICAL;
    case RISK_HIGH:     return SCORE_HIGH;
    case RISK_MEDIUM:   return SCORE_MEDIUM;
    case RISK_LOW:      return SCORE_LOW;
    default:            return 0;
    }
}

/* ── ANSI Colors ──────────────────────────────────────────────────── */

#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"
#define C_RED     "\033[1;31m"
#define C_ORANGE  "\033[38;5;208m"
#define C_YELLOW  "\033[1;33m"
#define C_GREEN   "\033[1;32m"
#define C_CYAN    "\033[1;36m"
#define C_BLUE    "\033[1;34m"

/* ── Session stats ────────────────────────────────────────────────── */

typedef struct {
    int total;
    int clean;
    int blocked;
    int allowed_risky;
} Stats;

static Stats g_stats;

/* ── Banner ───────────────────────────────────────────────────────── */

static void print_banner(int rule_count)
{
    fprintf(stderr,
        "\n"
        C_CYAN "╔══════════════════════════════════════════════════════════╗\n"
        "║                                                          ║\n"
        "║   " C_RED "⚡" C_CYAN " " C_BOLD "Suspicious Command Detector (SCD)" C_RESET C_CYAN "                    ║\n"
        "║   " C_DIM "Interactive Guard Shell — System Programming Project" C_RESET C_CYAN "   ║\n"
        "║                                                          ║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        "║                                                          ║\n"
        "║" C_RESET "  Type any shell command and SCD will:" C_CYAN "                    ║\n"
        "║  " C_GREEN "✓" C_CYAN " Parse and tokenize the command (pipes, redirects...)  ║\n"
        "║  " C_GREEN "✓" C_CYAN " Match against %3d detection rules (regex + substring) ║\n"
        "║  " C_GREEN "✓" C_CYAN " Calculate a risk score (0-100)                        ║\n"
        "║  " C_GREEN "✓" C_CYAN " Warn with reasons if suspicious/dangerous             ║\n"
        "║  " C_GREEN "✓" C_CYAN " Execute via fork()/exec() if approved                 ║\n"
        "║                                                          ║\n"
        "║" C_RESET "  Commands: " C_GREEN "help" C_RESET " | " C_GREEN "stats" C_RESET " | " C_GREEN "exit" C_CYAN "                             ║\n"
        "║                                                          ║\n"
        "╚══════════════════════════════════════════════════════════╝" C_RESET "\n\n",
        rule_count);
}

/* ── Warning display ──────────────────────────────────────────────── */

static void print_warning(const MatchedRule matches[], int mc,
                          int score, const char *cmd)
{
    const char *color = (score > THRESH_DANGER) ? C_RED : C_YELLOW;
    const char *label = (score > THRESH_DANGER) ? "DANGEROUS" : "SUSPICIOUS";

    int bar_len = 20;
    int filled  = (score * bar_len) / 100;

    fprintf(stderr, "\n%s", color);
    for (int i = 0; i < 60; i++) fputc('-', stderr);
    fprintf(stderr, C_RESET "\n");

    fprintf(stderr, "  %s⚠  %s%s" C_RESET "  (Score: %s%d/100" C_RESET ")\n",
            color, C_BOLD, label, color, score);

    /* Risk bar */
    fprintf(stderr, "  Risk: [%s", color);
    for (int i = 0; i < bar_len; i++)
        fputc(i < filled ? '#' : '-', stderr);
    fprintf(stderr, C_RESET "] %s%d%%" C_RESET "\n", color, score);

    fprintf(stderr, "%s", color);
    for (int i = 0; i < 60; i++) fputc('-', stderr);
    fprintf(stderr, C_RESET "\n");

    fprintf(stderr, "  " C_BOLD "Command:" C_RESET " %s\n", cmd);
    fprintf(stderr, "  " C_BOLD "Reasons:" C_RESET "\n");

    for (int i = 0; i < mc; i++) {
        const Rule *r = &matches[i].rule;
        const char *rc;
        switch (r->risk_level) {
        case RISK_CRITICAL: rc = C_RED;    break;
        case RISK_HIGH:     rc = C_ORANGE; break;
        case RISK_MEDIUM:   rc = C_YELLOW; break;
        default:            rc = C_DIM;    break;
        }
        fprintf(stderr, "    %s[%s] %-8s" C_RESET " → %s\n",
                rc, r->id, risk_level_to_str(r->risk_level), r->description);
    }

    fprintf(stderr, "%s", color);
    for (int i = 0; i < 60; i++) fputc('-', stderr);
    fprintf(stderr, C_RESET "\n\n");
}

/* ── Command execution via fork/exec/wait (IPC with pipe) ─────────── */

static int execute_command(const char *cmd_str)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) { perror("scd: pipe"); return -1; }

    pid_t pid = fork();
    if (pid < 0) {
        perror("scd: fork");
        close(pipefd[0]); close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* CHILD: close read end, notify parent, exec */
        close(pipefd[0]);
        char msg[512];
        int len = snprintf(msg, sizeof(msg), "[scd] PID %d executing: %s\n",
                           (int)getpid(), cmd_str);
        if (len > 0) write(pipefd[1], msg, (size_t)len);
        close(pipefd[1]);

        /* exec replaces process image; SIGINT resets to default */
        char *const argv[] = { "/bin/sh", "-c", (char *)cmd_str, NULL };
        execvp("/bin/sh", argv);
        perror("scd: exec");
        _exit(EXIT_FAILURE);
    }

    /* PARENT: read IPC message, wait for child */
    close(pipefd[1]);
    char ipc_buf[512];
    read(pipefd[0], ipc_buf, sizeof(ipc_buf) - 1);
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status))   return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

/* ── Built-in commands ────────────────────────────────────────────── */

static void print_help(void)
{
    fprintf(stderr,
        "\n" C_CYAN C_BOLD "  Built-in Commands:" C_RESET "\n"
        "  ─────────────────────────────────────────\n"
        "  " C_GREEN "help" C_RESET "       Show this help message\n"
        "  " C_GREEN "stats" C_RESET "      Show session statistics\n"
        "  " C_GREEN "exit" C_RESET "       Exit SCD Guard Shell\n"
        "  ─────────────────────────────────────────\n"
        "  Any other input is treated as a shell command.\n"
        "  Risky commands will be flagged with reasons.\n\n");
}

static void print_stats(void)
{
    fprintf(stderr,
        "\n" C_CYAN C_BOLD "  Session Statistics:" C_RESET "\n"
        "  ─────────────────────────────────────────\n"
        "  Commands analyzed : " C_BOLD "%d" C_RESET "\n"
        "  " C_GREEN "Clean" C_RESET "             : %d\n"
        "  " C_YELLOW "Risky (allowed)" C_RESET "   : %d\n"
        "  " C_RED "Blocked" C_RESET "           : %d\n"
        "  ─────────────────────────────────────────\n\n",
        g_stats.total, g_stats.clean, g_stats.allowed_risky, g_stats.blocked);
}

/* ── Prompt ───────────────────────────────────────────────────────── */

static void print_prompt(void)
{
    char cwd[256];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
        strcpy(cwd, "?");
    else {
        const char *home = getenv("HOME");
        if (home && home[0] && strncmp(cwd, home, strlen(home)) == 0) {
            char tmp[256];
            snprintf(tmp, sizeof(tmp), "~%s", cwd + strlen(home));
            strncpy(cwd, tmp, sizeof(cwd) - 1);
            cwd[255] = '\0';
        }
    }
    const char *user = getenv("USER");
    if (!user) user = "user";

    fprintf(stderr, C_GREEN "%s" C_RESET "@" C_CYAN "scd" C_RESET
            ":" C_BLUE "%s" C_RESET " " C_RED "$" C_RESET " ", user, cwd);
    fflush(stderr);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    /* Determine rules path */
    const char *rules_path = "./config/rules.conf";
    if (argc > 1) rules_path = argv[1];

    /* Load rules */
    Rule rules[MAX_RULES];
    int  rule_count = 0;
    if (rules_load(rules_path, rules, &rule_count) < 0) {
        fprintf(stderr, "scd: failed to load rules from %s\n", rules_path);
        return 1;
    }
    if (rule_count == 0) {
        fprintf(stderr, "scd: no rules loaded from %s\n", rules_path);
        return 1;
    }

    /* Load whitelist (optional) */
    char wl[MAX_WHITELIST][MAX_PATTERN_LEN];
    int  wl_count = 0;
    whitelist_load("./config/whitelist.conf", wl, &wl_count);

    /* Ignore SIGINT in the monitor (child resets via exec) */
    signal(SIGINT, SIG_IGN);

    /* Print banner */
    print_banner(rule_count);

    /* Main loop */
    char line[MAX_CMD_LEN];
    memset(&g_stats, 0, sizeof(g_stats));

    for (;;) {
        print_prompt();

        if (!fgets(line, sizeof(line), stdin))
            break;  /* EOF / Ctrl-D */

        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') continue;

        /* Built-ins */
        if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) break;
        if (strcmp(line, "help")  == 0) { print_help();  continue; }
        if (strcmp(line, "stats") == 0) { print_stats(); continue; }
        if (strcmp(line, "clear") == 0) { execute_command("clear"); continue; }

        /* cd must be handled in parent process */
        if (strncmp(line, "cd", 2) == 0 &&
            (line[2] == '\0' || line[2] == ' ')) {
            const char *dir = (line[2] == ' ' && line[3] != '\0')
                              ? line + 3 : getenv("HOME");
            if (!dir) dir = "/";
            if (chdir(dir) != 0)
                fprintf(stderr, "scd: cd: %s: %s\n", dir, strerror(errno));
            continue;
        }

        g_stats.total++;

        /* Whitelist check */
        if (wl_count > 0 &&
            whitelist_check((const char (*)[MAX_PATTERN_LEN])wl, wl_count, line)) {
            g_stats.clean++;
            fprintf(stderr, "  " C_GREEN "✓ Clean" C_RESET " (whitelisted)\n");
            execute_command(line);
            continue;
        }

        /* Parse command */
        ParsedCommand pcmd;
        if (parse_command(line, &pcmd) <= 0) {
            g_stats.clean++;
            execute_command(line);
            continue;
        }

        /* Match against rules */
        MatchedRule matches[MAX_MATCHES];
        int mc = 0;
        rules_match(rules, rule_count, &pcmd, matches, &mc);
        int score = (mc > 0) ? score_calculate(matches, mc) : 0;

        /* Clean command — just run it */
        if (score < THRESH_CLEAN || mc == 0) {
            g_stats.clean++;
            fprintf(stderr, "  " C_GREEN "✓ Clean" C_RESET " (score: %d)\n", score);
            execute_command(line);
            continue;
        }

        /* Suspicious/Dangerous — warn and ask */
        print_warning(matches, mc, score, line);

        const char *yn_prompt = (score > THRESH_DANGER)
            ? C_RED "  Run this DANGEROUS command? [y/N]: " C_RESET
            : C_YELLOW "  Run this suspicious command? [y/N]: " C_RESET;
        fprintf(stderr, "%s", yn_prompt);
        fflush(stderr);

        char confirm[32] = {0};
        if (!fgets(confirm, sizeof(confirm), stdin)) {
            fprintf(stderr, "\n" C_RED "  ✗ Aborted." C_RESET "\n\n");
            g_stats.blocked++;
            continue;
        }
        confirm[strcspn(confirm, "\r\n")] = '\0';

        if (confirm[0] == 'y' || confirm[0] == 'Y') {
            g_stats.allowed_risky++;
            fprintf(stderr, "  " C_GREEN "Running..." C_RESET "\n");
            execute_command(line);
        } else {
            g_stats.blocked++;
            fprintf(stderr, "  " C_RED "✗ Command blocked by SCD." C_RESET "\n\n");
        }
    }

    /* Exit summary */
    fprintf(stderr,
        "\n" C_CYAN "════════════════════════════════════════" C_RESET "\n"
        "  " C_BOLD "SCD Session Summary" C_RESET "\n"
        "  Commands: %d | " C_GREEN "Clean: %d" C_RESET
        " | " C_YELLOW "Risky: %d" C_RESET
        " | " C_RED "Blocked: %d" C_RESET "\n"
        C_CYAN "════════════════════════════════════════" C_RESET "\n\n",
        g_stats.total, g_stats.clean, g_stats.allowed_risky, g_stats.blocked);

    return 0;
}
