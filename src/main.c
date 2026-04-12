/*
 * main.c — Entry point, argument parsing, mode dispatch
 *
 * Suspicious Command Detector (SCD) v1.0.0
 * Usage: scd [OPTIONS] [FILE]
 */

#include "scd.h"
#include "parser.h"
#include "rule_engine.h"
#include "scorer.h"
#include "alert.h"
#include "input_reader.h"
#include "daemon.h"

#include <unistd.h>
#include <string.h>
#include <strings.h>

/* ── utility function implementations ─────────────────────────────── */

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

/* ── usage / version ──────────────────────────────────────────────── */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Suspicious Command Detector (SCD) v%s\n\n"
        "Usage: %s [OPTIONS] [FILE]\n\n"
        "Arguments:\n"
        "  FILE                  Path to history/log file (omit for stdin)\n\n"
        "Options:\n"
        "  -f <format>           Output format: text (default) | json\n"
        "  -r <rules>            Path to rules config (default: ./config/rules.conf)\n"
        "  -w <whitelist>        Path to whitelist file\n"
        "  -l <logfile>          Write alerts to logfile instead of stdout\n"
        "  -d                    Run as daemon (watch FILE via inotify)\n"
        "  -v                    Verbose: show all scanned commands\n"
        "  -t <threshold>        Minimum risk score to report (default: %d)\n"
        "  -h                    Show this help\n"
        "  --version             Show version\n",
        SCD_VERSION, prog, THRESH_CLEAN);
}

/* ── CLI argument parsing ─────────────────────────────────────────── */

static int parse_args(int argc, char *argv[], Config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->threshold = THRESH_CLEAN;
    strncpy(cfg->rules_path, "./config/rules.conf", MAX_PATH_LEN - 1);

    /* check for --version / --help before getopt */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) { cfg->show_version = 1; return 0; }
        if (strcmp(argv[i], "--help")    == 0) { cfg->show_help = 1;    return 0; }
    }

    int opt;
    while ((opt = getopt(argc, argv, "f:r:w:l:dvt:h")) != -1) {
        switch (opt) {
        case 'f':
            if (strcmp(optarg, "json") == 0)      cfg->format = FORMAT_JSON;
            else if (strcmp(optarg, "text") == 0)  cfg->format = FORMAT_TEXT;
            else { fprintf(stderr, "scd: unknown format '%s'\n", optarg); return -1; }
            break;
        case 'r': strncpy(cfg->rules_path,     optarg, MAX_PATH_LEN - 1); break;
        case 'w': strncpy(cfg->whitelist_path,  optarg, MAX_PATH_LEN - 1); break;
        case 'l': strncpy(cfg->log_path,        optarg, MAX_PATH_LEN - 1); break;
        case 'd': cfg->daemon_mode = 1; break;
        case 'v': cfg->verbose     = 1; break;
        case 't': cfg->threshold   = atoi(optarg); break;
        case 'h': cfg->show_help   = 1; return 0;
        default:  return -1;
        }
    }

    if (optind < argc)
        strncpy(cfg->input_path, argv[optind], MAX_PATH_LEN - 1);

    return 0;
}

/* ── main ─────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    Config cfg;
    if (parse_args(argc, argv, &cfg) < 0) {
        print_usage(argv[0]);
        return EXIT_ERROR;
    }
    if (cfg.show_version) {
        printf("scd version %s\n", SCD_VERSION);
        return EXIT_CLEAN;
    }
    if (cfg.show_help) {
        print_usage(argv[0]);
        return EXIT_CLEAN;
    }

    /* ── load rules ──────────────────────────────────────────────── */
    Rule rules[MAX_RULES];
    int  rule_count = 0;
    if (rules_load(cfg.rules_path, rules, &rule_count) < 0)
        return EXIT_ERROR;
    if (rule_count == 0) {
        fprintf(stderr, "scd: no rules loaded from %s\n", cfg.rules_path);
        return EXIT_ERROR;
    }

    /* ── load whitelist (optional) ───────────────────────────────── */
    char wl[MAX_WHITELIST][MAX_PATTERN_LEN];
    int  wl_count = 0;
    if (cfg.whitelist_path[0])
        whitelist_load(cfg.whitelist_path, wl, &wl_count);

    /* ── daemon mode ─────────────────────────────────────────────── */
    if (cfg.daemon_mode) {
        if (!cfg.input_path[0]) {
            fprintf(stderr, "scd: daemon mode requires a FILE argument\n");
            return EXIT_ERROR;
        }
        return daemon_start(&cfg, rules, rule_count,
                            (const char (*)[MAX_PATTERN_LEN])wl, wl_count);
    }

    /* ── scanner mode ────────────────────────────────────────────── */
    InputReader reader;
    if (input_open(&reader, cfg.input_path[0] ? cfg.input_path : NULL) < 0)
        return EXIT_ERROR;

    FILE *out = stdout;
    if (cfg.log_path[0]) {
        out = fopen(cfg.log_path, "a");
        if (!out) {
            perror("scd: cannot open log file");
            input_close(&reader);
            return EXIT_ERROR;
        }
    }

    int max_score  = 0;
    int line_count = 0;
    int alert_count = 0;
    char line[MAX_CMD_LEN];

    while (input_readline(&reader, line, sizeof(line)) > 0) {
        ParsedCommand cmd;
        int tc = parse_command(line, &cmd);
        if (tc <= 0)
            continue;

        line_count++;

        /* whitelist check */
        if (wl_count > 0 && whitelist_check((const char (*)[MAX_PATTERN_LEN])wl,
                                             wl_count, cmd.raw))
        {
            if (cfg.verbose)
                fprintf(out, "[SKIP-WL] %s\n", cmd.raw);
            continue;
        }

        /* match rules */
        MatchedRule matches[MAX_MATCHES];
        int mc = 0;
        rules_match(rules, rule_count, &cmd, matches, &mc);

        if (mc == 0) {
            if (cfg.verbose)
                fprintf(out, "[CLEAN  ] %s\n", cmd.raw);
            continue;
        }

        int score = score_calculate(matches, mc);
        if (score > max_score)
            max_score = score;

        if (score < cfg.threshold) {
            if (cfg.verbose)
                fprintf(out, "[BELOW-%d] %s (score=%d)\n",
                        cfg.threshold, cmd.raw, score);
            continue;
        }

        alert_count++;
        Alert alert;
        alert_init(&alert, cmd.raw, matches, mc, score);

        if (cfg.format == FORMAT_JSON)
            alert_print_json(out, &alert);
        else
            alert_print_text(out, &alert);
    }

    /* summary (text mode only) */
    if (cfg.format == FORMAT_TEXT) {
        fprintf(out, "\n── SCD Scan Summary ────────────────────────\n");
        fprintf(out, " Rules loaded : %d\n", rule_count);
        fprintf(out, " Lines scanned: %d\n", line_count);
        fprintf(out, " Alerts raised: %d\n", alert_count);
        fprintf(out, " Max score    : %d (%s)\n", max_score, score_label(max_score));
        fprintf(out, "────────────────────────────────────────────\n");
    }

    if (out != stdout)
        fclose(out);
    input_close(&reader);

    /* exit code per contract */
    if (max_score > THRESH_DANGER)
        return EXIT_DANGEROUS;
    if (max_score > THRESH_CLEAN)
        return EXIT_SUSPICIOUS;
    return EXIT_CLEAN;
}
