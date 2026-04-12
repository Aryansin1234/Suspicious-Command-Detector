#ifndef SCD_RULE_ENGINE_H
#define SCD_RULE_ENGINE_H

#include "scd.h"

/*
 * Load detection rules from a config file.
 * Returns 0 on success, -1 on error. Sets *count to number loaded.
 */
int rules_load(const char *path, Rule rules[], int *count);

/*
 * Match a parsed command against all loaded rules.
 * Populates matches[] and sets *match_count.
 * Returns number of matches.
 */
int rules_match(const Rule rules[], int rule_count,
                const ParsedCommand *cmd,
                MatchedRule matches[], int *match_count);

/*
 * Load whitelist patterns from a file.
 * Returns 0 on success, -1 on error.
 */
int whitelist_load(const char *path, char patterns[][MAX_PATTERN_LEN], int *count);

/*
 * Check if a command matches any whitelist pattern.
 * Returns 1 if whitelisted, 0 otherwise.
 */
int whitelist_check(const char patterns[][MAX_PATTERN_LEN], int count,
                    const char *command);

#endif /* SCD_RULE_ENGINE_H */
