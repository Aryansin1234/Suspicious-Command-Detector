/*
 * rule_engine.c — Rule Loader & Pattern Matcher
 *
 * Loads detection rules from an external config file (rules.conf)
 * and performs case-insensitive substring matching of each rule
 * pattern against raw command strings.
 */

#include "rule_engine.h"
#include <ctype.h>
#include <string.h>

/* ── portable case-insensitive substring search ───────────────────── */

static const char *scd_strcasestr(const char *haystack, const char *needle)
{
    if (!needle[0])
        return haystack;
    for (const char *h = haystack; *h; h++) {
        const char *a = h;
        const char *b = needle;
        while (*a && *b &&
               tolower((unsigned char)*a) == tolower((unsigned char)*b)) {
            a++;
            b++;
        }
        if (!*b)
            return h;
    }
    return NULL;
}

/* ── trim leading/trailing whitespace in place ────────────────────── */

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

/* ── public: load rules from config ───────────────────────────────── */

int rules_load(const char *path, Rule rules[], int *count)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("scd: cannot open rules file");
        return -1;
    }

    char line[MAX_LINE_LEN];
    *count = 0;

    while (fgets(line, sizeof(line), fp) && *count < MAX_RULES) {
        /* strip newline */
        line[strcspn(line, "\r\n")] = '\0';
        char *p = trim(line);
        if (*p == '\0' || *p == '#')
            continue;

        /*
         * Parse: ID|RISK|PATTERN|DESCRIPTION
         * Strategy: find 1st, 2nd, and LAST '|' to handle
         * patterns that contain pipe characters.
         */
        char *sep1 = strchr(p, '|');
        if (!sep1) continue;
        char *sep2 = strchr(sep1 + 1, '|');
        if (!sep2) continue;
        char *sep_last = strrchr(p, '|');
        if (sep_last == sep2) {
            /* only 3 fields — no pipe in pattern */
            sep_last = NULL;
        }

        Rule *r = &rules[*count];

        /* ID */
        size_t id_len = (size_t)(sep1 - p);
        if (id_len >= MAX_ID_LEN) id_len = MAX_ID_LEN - 1;
        memcpy(r->id, p, id_len);
        r->id[id_len] = '\0';

        /* RISK */
        char risk_buf[32];
        size_t risk_len = (size_t)(sep2 - sep1 - 1);
        if (risk_len >= sizeof(risk_buf)) risk_len = sizeof(risk_buf) - 1;
        memcpy(risk_buf, sep1 + 1, risk_len);
        risk_buf[risk_len] = '\0';
        r->risk_level = str_to_risk_level(trim(risk_buf));

        /* PATTERN and DESCRIPTION */
        if (sep_last && sep_last != sep2) {
            /* pattern may contain '|' */
            size_t pat_len = (size_t)(sep_last - sep2 - 1);
            if (pat_len >= MAX_PATTERN_LEN) pat_len = MAX_PATTERN_LEN - 1;
            memcpy(r->pattern, sep2 + 1, pat_len);
            r->pattern[pat_len] = '\0';

            strncpy(r->description, trim(sep_last + 1), MAX_DESC_LEN - 1);
            r->description[MAX_DESC_LEN - 1] = '\0';
        } else {
            /* no pipe in pattern — description is after 3rd '|' ... wait,
               there are only 3 separators. */
            /* Actually with 3 separators we have 4 fields: ID|RISK|PATTERN|DESC.
               sep1=1st|, sep2=2nd|, sep_last=3rd|=last. If sep_last==sep2, we
               have only 2 pipes which means 3 fields (malformed). Skip. */
            /* Re-check: sep_last was set NULL above when sep_last==sep2.
               So reaching here means we only had 2 pipes — malformed. */
            continue;
        }

        (*count)++;
    }

    fclose(fp);
    return 0;
}

/* ── public: match command against rules ──────────────────────────── */

int rules_match(const Rule rules[], int rule_count,
                const ParsedCommand *cmd,
                MatchedRule matches[], int *match_count)
{
    *match_count = 0;
    if (!cmd->raw[0])
        return 0;

    for (int i = 0; i < rule_count && *match_count < MAX_MATCHES; i++) {
        const char *pos = scd_strcasestr(cmd->raw, rules[i].pattern);
        if (pos) {
            MatchedRule *m = &matches[*match_count];
            m->rule     = rules[i];   /* struct copy */
            m->position = (int)(pos - cmd->raw);
            (*match_count)++;
        }
    }
    return *match_count;
}

/* ── whitelist support ────────────────────────────────────────────── */

int whitelist_load(const char *path, char patterns[][MAX_PATTERN_LEN], int *count)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;     /* silently fail — whitelist is optional */

    char line[MAX_LINE_LEN];
    *count = 0;

    while (fgets(line, sizeof(line), fp) && *count < MAX_WHITELIST) {
        line[strcspn(line, "\r\n")] = '\0';
        char *p = trim(line);
        if (*p == '\0' || *p == '#')
            continue;
        strncpy(patterns[*count], p, MAX_PATTERN_LEN - 1);
        patterns[*count][MAX_PATTERN_LEN - 1] = '\0';
        (*count)++;
    }

    fclose(fp);
    return 0;
}

int whitelist_check(const char patterns[][MAX_PATTERN_LEN], int count,
                    const char *command)
{
    for (int i = 0; i < count; i++) {
        if (scd_strcasestr(command, patterns[i]))
            return 1;
    }
    return 0;
}
