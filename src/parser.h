#ifndef SCD_PARSER_H
#define SCD_PARSER_H

#include "scd.h"

/*
 * Parse a shell command line into a ParsedCommand struct.
 * Handles pipes, redirects, subshells, quotes, escapes.
 * Returns token count (>0) on success, 0 for empty/comment, -1 on error.
 */
int parse_command(const char *line, ParsedCommand *cmd);

#endif /* SCD_PARSER_H */
