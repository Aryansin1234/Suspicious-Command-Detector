#ifndef SCD_PARSER_H
#define SCD_PARSER_H

#include "scd.h"

/*
 * Tokenize a raw command line into a ParsedCommand struct.
 * Handles pipes, redirects, subshells, quotes, and escapes.
 * Returns token count on success, -1 on error, 0 for empty/comment lines.
 */
int parse_command(const char *line, ParsedCommand *cmd);

#endif /* SCD_PARSER_H */
