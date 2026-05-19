/*
 * parser.c — Command Tokenizer
 *
 * Tokenizes shell command lines into structured ParsedCommand
 * structs, handling pipes, redirects, subshells, quoted strings,
 * and escape sequences.
 */

#include "parser.h"
#include <ctype.h>
#include <string.h>

typedef enum {
    PS_NORMAL,
    PS_SINGLE_QUOTE,
    PS_DOUBLE_QUOTE
} ParserState;

static void finish_token(ParsedCommand *cmd, char *buf, int *pos, TokenType type)
{
    if (*pos <= 0) return;
    buf[*pos] = '\0';
    if (cmd->token_count < MAX_TOKENS) {
        strncpy(cmd->tokens[cmd->token_count].value, buf, MAX_TOKEN_LEN - 1);
        cmd->tokens[cmd->token_count].value[MAX_TOKEN_LEN - 1] = '\0';
        cmd->tokens[cmd->token_count].type = type;
        cmd->token_count++;
    }
    *pos = 0;
}

static void add_special(ParsedCommand *cmd, const char *val, TokenType type)
{
    if (cmd->token_count < MAX_TOKENS) {
        strncpy(cmd->tokens[cmd->token_count].value, val, MAX_TOKEN_LEN - 1);
        cmd->tokens[cmd->token_count].value[MAX_TOKEN_LEN - 1] = '\0';
        cmd->tokens[cmd->token_count].type = type;
        cmd->token_count++;
    }
}

int parse_command(const char *line, ParsedCommand *cmd)
{
    if (!line || !cmd) return -1;
    memset(cmd, 0, sizeof(*cmd));

    strncpy(cmd->raw, line, MAX_CMD_LEN - 1);
    cmd->raw[MAX_CMD_LEN - 1] = '\0';
    size_t len = strlen(cmd->raw);
    while (len > 0 && (cmd->raw[len-1] == '\n' || cmd->raw[len-1] == '\r'))
        cmd->raw[--len] = '\0';

    if (len == 0 || cmd->raw[0] == '#') return 0;

    char buf[MAX_TOKEN_LEN];
    int bp = 0;
    ParserState state = PS_NORMAL;

    for (size_t i = 0; i < len; i++) {
        char c = cmd->raw[i];
        char next = (i + 1 < len) ? cmd->raw[i+1] : '\0';

        switch (state) {
        case PS_SINGLE_QUOTE:
            if (c == '\'') state = PS_NORMAL;
            else if (bp < MAX_TOKEN_LEN - 1) buf[bp++] = c;
            break;
        case PS_DOUBLE_QUOTE:
            if (c == '"') state = PS_NORMAL;
            else if (c == '\\' && next) { if (bp < MAX_TOKEN_LEN-1) buf[bp++] = next; i++; }
            else if (bp < MAX_TOKEN_LEN - 1) buf[bp++] = c;
            break;
        case PS_NORMAL:
            if (c == '\'') state = PS_SINGLE_QUOTE;
            else if (c == '"') state = PS_DOUBLE_QUOTE;
            else if (c == '\\' && next) { if (bp < MAX_TOKEN_LEN-1) buf[bp++] = next; i++; }
            else if (c == '|') {
                finish_token(cmd, buf, &bp, TOKEN_WORD);
                if (next == '|') { add_special(cmd, "||", TOKEN_OR); i++; }
                else { add_special(cmd, "|", TOKEN_PIPE); cmd->has_pipe = 1; }
            } else if (c == '>') {
                finish_token(cmd, buf, &bp, TOKEN_WORD);
                if (next == '>') { add_special(cmd, ">>", TOKEN_REDIRECT_APPEND); i++; }
                else add_special(cmd, ">", TOKEN_REDIRECT_OUT);
                cmd->has_redirect = 1;
            } else if (c == '<') {
                finish_token(cmd, buf, &bp, TOKEN_WORD);
                add_special(cmd, "<", TOKEN_REDIRECT_IN);
                cmd->has_redirect = 1;
            } else if (c == ';') {
                finish_token(cmd, buf, &bp, TOKEN_WORD);
                add_special(cmd, ";", TOKEN_SEMICOLON);
            } else if (c == '&') {
                finish_token(cmd, buf, &bp, TOKEN_WORD);
                if (next == '&') { add_special(cmd, "&&", TOKEN_AND); i++; }
                else add_special(cmd, "&", TOKEN_BACKGROUND);
            } else if (c == '$' && next == '(') {
                finish_token(cmd, buf, &bp, TOKEN_WORD);
                add_special(cmd, "$(", TOKEN_SUBSHELL_START);
                cmd->has_subshell = 1; i++;
            } else if (c == ')') {
                finish_token(cmd, buf, &bp, TOKEN_WORD);
                add_special(cmd, ")", TOKEN_SUBSHELL_END);
            } else if (c == '`') {
                cmd->has_subshell = 1;
                if (bp < MAX_TOKEN_LEN - 1) buf[bp++] = c;
            } else if (isspace((unsigned char)c)) {
                finish_token(cmd, buf, &bp, TOKEN_WORD);
            } else {
                if (bp < MAX_TOKEN_LEN - 1) buf[bp++] = c;
            }
            break;
        }
    }
    finish_token(cmd, buf, &bp, TOKEN_WORD);
    return cmd->token_count;
}
