/*
 * rule_engine.c — Rule Loader & Pattern Matcher
 *
 * Loads detection rules from config file and performs
 * case-insensitive substring matching or POSIX regex matching.
 */

#include "rule_engine.h"
#include <ctype.h>
#include <string.h>
#include <regex.h>

static regex_t compiled_re[MAX_RULES];
static int     re_compiled[MAX_RULES];

static const char *scd_strcasestr(const char *haystack, const char *needle)
{
    if (!needle[0]) return haystack;
    for (const char *h = haystack; *h; h++) {
        const char *a = h, *b = needle;
        while (*a && *b && tolower((unsigned char)*a) == tolower((unsigned char)*b)) { a++; b++; }
        if (!*b) return h;
    }
    return NULL;
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

int rules_load(const char *path, Rule rules[], int *count)
{
    FILE *fp = fopen(path, "r");
    if (!fp) { perror("scd: cannot open rules file"); return -1; }

    char line[MAX_LINE_LEN];
    *count = 0;

    while (fgets(line, sizeof(line), fp) && *count < MAX_RULES) {
        line[strcspn(line, "\r\n")] = '\0';
        char *p = trim(line);
        if (*p == '\0' || *p == '#') continue;

        /* Parse: ID|RISK|PATTERN|DESCRIPTION */
        char *sep1 = strchr(p, '|');
        if (!sep1) continue;
        char *sep2 = strchr(sep1 + 1, '|');
        if (!sep2) continue;
        char *sep_last = strrchr(p, '|');
        if (sep_last == sep2) continue;

        Rule *r = &rules[*count];
        memset(r, 0, sizeof(*r));

        size_t id_len = (size_t)(sep1 - p);
        if (id_len >= MAX_ID_LEN) id_len = MAX_ID_LEN - 1;
        memcpy(r->id, p, id_len);

        char risk_buf[32];
        size_t risk_len = (size_t)(sep2 - sep1 - 1);
        if (risk_len >= sizeof(risk_buf)) risk_len = sizeof(risk_buf) - 1;
        memcpy(risk_buf, sep1 + 1, risk_len);
        risk_buf[risk_len] = '\0';
        r->risk_level = str_to_risk_level(trim(risk_buf));

        size_t pat_len = (size_t)(sep_last - sep2 - 1);
        if (pat_len >= MAX_PATTERN_LEN) pat_len = MAX_PATTERN_LEN - 1;
        memcpy(r->pattern, sep2 + 1, pat_len);
        r->pattern[pat_len] = '\0';

        strncpy(r->description, trim(sep_last + 1), MAX_DESC_LEN - 1);

        /* Check for regex: prefix */
        if (strncmp(r->pattern, "regex:", 6) == 0) {
            r->is_regex = 1;
            memmove(r->pattern, r->pattern + 6, strlen(r->pattern + 6) + 1);
            if (regcomp(&compiled_re[*count], r->pattern,
                        REG_EXTENDED | REG_ICASE) != 0) {
                fprintf(stderr, "scd: invalid regex in rule %s\n", r->id);
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

int rules_match(const Rule rules[], int rule_count,
                const ParsedCommand *cmd,
                MatchedRule matches[], int *match_count)
{
    *match_count = 0;
    if (!cmd->raw[0]) return 0;

    for (int i = 0; i < rule_count && *match_count < MAX_MATCHES; i++) {
        int matched = 0, mpos = 0;

        if (rules[i].is_regex && re_compiled[i]) {
            regmatch_t rmatch;
            if (regexec(&compiled_re[i], cmd->raw, 1, &rmatch, 0) == 0) {
                matched = 1; mpos = (int)rmatch.rm_so;
            }
        } else {
            const char *pos = scd_strcasestr(cmd->raw, rules[i].pattern);
            if (pos) { matched = 1; mpos = (int)(pos - cmd->raw); }
        }

        if (matched) {
            matches[*match_count].rule = rules[i];
            matches[*match_count].position = mpos;
            (*match_count)++;
        }
    }
    return *match_count;
}

int whitelist_load(const char *path, char patterns[][MAX_PATTERN_LEN], int *count)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[MAX_LINE_LEN];
    *count = 0;
    while (fgets(line, sizeof(line), fp) && *count < MAX_WHITELIST) {
        line[strcspn(line, "\r\n")] = '\0';
        char *p = trim(line);
        if (*p == '\0' || *p == '#') continue;
        strncpy(patterns[*count], p, MAX_PATTERN_LEN - 1);
        (*count)++;
    }
    fclose(fp);
    return 0;
}

int whitelist_check(const char patterns[][MAX_PATTERN_LEN], int count,
                    const char *command)
{
    for (int i = 0; i < count; i++)
        if (scd_strcasestr(command, patterns[i])) return 1;
    return 0;
}
