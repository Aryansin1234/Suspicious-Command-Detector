/*
 * alert.c — Output Formatter (text / JSON / syslog)
 */

#include "alert.h"
#include <time.h>
#include <syslog.h>
#include <string.h>

/* ── helpers ──────────────────────────────────────────────────────── */

static void now_timestamp(char *buf, size_t len)
{
    time_t     t  = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%S%z", tm);
}

/* Escape a string for JSON output (handles \, ", newline, tab) */
static void json_escape(FILE *out, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n",  out); break;
        case '\r': fputs("\\r",  out); break;
        case '\t': fputs("\\t",  out); break;
        default:   fputc(*s, out);     break;
        }
    }
}

/* ── public API ───────────────────────────────────────────────────── */

void alert_init(Alert *alert, const char *command,
                const MatchedRule matches[], int match_count, int risk_score)
{
    memset(alert, 0, sizeof(*alert));
    now_timestamp(alert->timestamp, sizeof(alert->timestamp));
    strncpy(alert->command, command, MAX_CMD_LEN - 1);
    alert->risk_score = risk_score;

    const char *label = (risk_score <= THRESH_CLEAN)  ? "clean" :
                        (risk_score <= THRESH_DANGER)  ? "suspicious" :
                                                         "dangerous";
    strncpy(alert->risk_label, label, sizeof(alert->risk_label) - 1);

    alert->match_count = (match_count > MAX_MATCHES) ? MAX_MATCHES : match_count;
    for (int i = 0; i < alert->match_count; i++)
        alert->matches[i] = matches[i];
}

void alert_print_text(FILE *out, const Alert *alert)
{
    fprintf(out,
        "──────────────────────────────────────────────\n"
        " ⚠  SCD ALERT  [%s]\n"
        "──────────────────────────────────────────────\n"
        " Time    : %s\n"
        " Command : %s\n"
        " Score   : %d / %d  (%s)\n"
        " Matches :\n",
        alert->risk_label,
        alert->timestamp,
        alert->command,
        alert->risk_score, SCORE_CAP,
        alert->risk_label);

    for (int i = 0; i < alert->match_count; i++) {
        const MatchedRule *m = &alert->matches[i];
        fprintf(out, "   [%s] %-8s  %s  — %s\n",
                m->rule.id,
                risk_level_to_str(m->rule.risk_level),
                m->rule.pattern,
                m->rule.description);
    }
    fprintf(out, "──────────────────────────────────────────────\n\n");
    fflush(out);
}

void alert_print_json(FILE *out, const Alert *alert)
{
    fprintf(out, "{\n");
    fprintf(out, "  \"timestamp\": \"");  json_escape(out, alert->timestamp); fprintf(out, "\",\n");
    fprintf(out, "  \"command\": \"");    json_escape(out, alert->command);   fprintf(out, "\",\n");
    fprintf(out, "  \"risk_score\": %d,\n", alert->risk_score);
    fprintf(out, "  \"risk_level\": \"%s\",\n", alert->risk_label);
    fprintf(out, "  \"matched_rules\": [\n");

    for (int i = 0; i < alert->match_count; i++) {
        const MatchedRule *m = &alert->matches[i];
        fprintf(out, "    {\n");
        fprintf(out, "      \"rule_id\": \"%s\",\n",     m->rule.id);
        fprintf(out, "      \"risk\": \"%s\",\n",        risk_level_to_str(m->rule.risk_level));
        fprintf(out, "      \"pattern\": \"");            json_escape(out, m->rule.pattern);
        fprintf(out, "\",\n");
        fprintf(out, "      \"description\": \"");        json_escape(out, m->rule.description);
        fprintf(out, "\",\n");
        fprintf(out, "      \"position\": %d\n",          m->position);
        fprintf(out, "    }%s\n", (i < alert->match_count - 1) ? "," : "");
    }

    fprintf(out, "  ]\n}\n");
    fflush(out);
}

void alert_syslog(const Alert *alert)
{
    openlog(SCD_NAME, LOG_PID | LOG_CONS, LOG_USER);

    int priority = (alert->risk_score > THRESH_DANGER) ? LOG_CRIT :
                   (alert->risk_score > THRESH_CLEAN)  ? LOG_WARNING :
                                                          LOG_INFO;
    syslog(priority, "[%s] score=%d cmd=\"%.200s\"",
           alert->risk_label, alert->risk_score, alert->command);

    for (int i = 0; i < alert->match_count; i++)
        syslog(priority, "  matched %s (%s): %s",
               alert->matches[i].rule.id,
               risk_level_to_str(alert->matches[i].rule.risk_level),
               alert->matches[i].rule.description);

    closelog();
}
