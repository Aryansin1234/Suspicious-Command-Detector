/*
 * Suspicious Command Detector (SCD) — Shared Definitions
 * POSIX C11 | Simple Interactive Edition
 *
 * System Programming Concepts:
 *   - Process creation: fork()
 *   - Program execution: execvp() via /bin/sh
 *   - Process synchronization: waitpid(), WIFEXITED, WEXITSTATUS
 *   - Inter-process communication: pipe()
 *   - Signal handling: signal(), SIGINT
 *   - File I/O: fopen, fgets (rule loading)
 *   - POSIX regex: regcomp, regexec
 */

#ifndef SCD_H
#define SCD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SCD_VERSION     "2.0.0"
#define SCD_NAME        "scd"

/* Buffer limits */
#define MAX_CMD_LEN     4096
#define MAX_TOKEN_LEN   512
#define MAX_TOKENS      64
#define MAX_RULES       128
#define MAX_MATCHES     32
#define MAX_WHITELIST   64
#define MAX_LINE_LEN    4096
#define MAX_PATTERN_LEN 512
#define MAX_DESC_LEN    256
#define MAX_ID_LEN      16
#define MAX_PATH_LEN    1024

/* Risk levels */
typedef enum {
    RISK_LOW = 0,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL,
    RISK_UNKNOWN
} RiskLevel;

#define SCORE_LOW       15
#define SCORE_MEDIUM    40
#define SCORE_HIGH      70
#define SCORE_CRITICAL  100
#define SCORE_CAP       100

#define THRESH_CLEAN    20
#define THRESH_DANGER   50

/* Token types (from shell parsing) */
typedef enum {
    TOKEN_WORD = 0,
    TOKEN_PIPE,
    TOKEN_REDIRECT_OUT,
    TOKEN_REDIRECT_IN,
    TOKEN_REDIRECT_APPEND,
    TOKEN_REDIRECT_ERR,
    TOKEN_SUBSHELL_START,
    TOKEN_SUBSHELL_END,
    TOKEN_SEMICOLON,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_BACKGROUND
} TokenType;

/* Data structures */
typedef struct {
    char        value[MAX_TOKEN_LEN];
    TokenType   type;
} Token;

typedef struct {
    char    raw[MAX_CMD_LEN];
    Token   tokens[MAX_TOKENS];
    int     token_count;
    int     has_pipe;
    int     has_redirect;
    int     has_subshell;
} ParsedCommand;

typedef struct {
    char        id[MAX_ID_LEN];
    RiskLevel   risk_level;
    char        pattern[MAX_PATTERN_LEN];
    char        description[MAX_DESC_LEN];
    int         is_regex;
} Rule;

typedef struct {
    Rule    rule;
    int     position;
} MatchedRule;

typedef struct {
    char        timestamp[64];
    char        command[MAX_CMD_LEN];
    MatchedRule matches[MAX_MATCHES];
    int         match_count;
    int         risk_score;
    char        risk_label[16];
} Alert;

typedef struct {
    char        rules_path[MAX_PATH_LEN];
    char        whitelist_path[MAX_PATH_LEN];
    int         threshold;
} Config;

/* Utility functions (main.c) */
const char  *risk_level_to_str(RiskLevel level);
RiskLevel    str_to_risk_level(const char *str);
int          risk_level_score(RiskLevel level);

#endif /* SCD_H */
