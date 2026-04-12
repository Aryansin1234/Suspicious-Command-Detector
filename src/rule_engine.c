/*
 * rule_engine.c — Rule Loader & Pattern Matcher
 *
 * Loads detection rules from an external config file (rules.conf)
 * and performs case-insensitive substring matching (or POSIX regex
 * matching for rules prefixed with "regex:") against raw commands.
 */

#include "rule_engine.h"
#include <ctype.h>
#include <string.h>
#include <regex.h>

/* Compiled regex cache (indexed by rule position) */
static regex_t compiled_re[MAX_RULES];
static int     re_compiled[MAX_RULES];

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
        memset(r, 0, sizeof(*r));

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
            size_t pat_len = (size_t)(sep_last - sep2 - 1);
            if (pat_len >= MAX_PATTERN_LEN) pat_len = MAX_PATTERN_LEN - 1;
            memcpy(r->pattern, sep2 + 1, pat_len);
            r->pattern[pat_len] = '\0';

            strncpy(r->description, trim(sep_last + 1), MAX_DESC_LEN - 1);
            r->description[MAX_DESC_LEN - 1] = '\0';
        } else {
            continue;
        }

        /* Check for regex: prefix */
        if (strncmp(r->pattern, "regex:", 6) == 0) {
            r->is_regex = 1;
            memmove(r->pattern, r->pattern + 6, strlen(r->pattern + 6) + 1);
            if (regcomp(&compiled_re[*count], r->pattern,
                        REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) {
                fprintf(stderr, "scd: invalid regex in rule %s: %s\n",
                        r->id, r->pattern);
                r->is_regex = 0;
            } else {
                re_compiled[*count] = 1;
            }
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
        int matched = 0;
        int mpos = 0;

        if (rules[i].is_regex && re_compiled[i]) {
            /* POSIX regex match */
            regmatch_t rm;
            if (regexec(&compiled_re[i], cmd->raw, 1, &rm, 0) == 0) {
                matched = 1;
                mpos = (int)rm.rm_so;
            }
        } else {
            /* Substring match */
            const char *pos = scd_strcasestr(cmd->raw, rules[i].pattern);
            if (pos) {
                matched = 1;
                mpos = (int)(pos - cmd->raw);
            }
        }

        if (matched) {
            MatchedRule *m = &matches[*match_count];
            m->rule     = rules[i];
            m->position = mpos;
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
