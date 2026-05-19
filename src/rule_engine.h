#ifndef SCD_RULE_ENGINE_H
#define SCD_RULE_ENGINE_H

#include "scd.h"
#include "parser.h"

/*
 * Load detection rules from config file.
 * Format: ID|RISK|PATTERN|DESCRIPTION
 * Returns 0 on success, -1 on error.
 */
int rules_load(const char *path, Rule rules[], int *count);

/*
 * Match a parsed command against all loaded rules.
 * Populates matches[] array and sets match_count.
 * Returns number of matches.
 */
int rules_match(const Rule rules[], int rule_count,
                const ParsedCommand *cmd,
                MatchedRule matches[], int *match_count);

/* Load whitelist patterns from file */
int whitelist_load(const char *path, char patterns[][MAX_PATTERN_LEN], int *count);

/* Check if command matches any whitelist pattern (returns 1 if whitelisted) */
int whitelist_check(const char patterns[][MAX_PATTERN_LEN], int count,
                    const char *command);

#endif /* SCD_RULE_ENGINE_H */
