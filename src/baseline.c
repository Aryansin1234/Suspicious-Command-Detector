/*
 * baseline.c — User Behavior Baseline & Anomaly Detection
 *
 * Learns normal command patterns from shell history and flags
 * deviations. Uses simple frequency analysis of command prefixes.
 *
 * File format (baseline.dat):
 *   HEADER: "SCD_BASELINE v1\n"
 *   ENTRY:  "count prefix\n"  (sorted by count descending)
 *   FOOTER: "TOTAL total_commands\n"
 */

#include "baseline.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

/* ── Extract first word (command name) from a line ────────────────── */

static void extract_prefix(const char *line, char *prefix, size_t max)
{
    /* Skip leading whitespace */
    while (*line && isspace((unsigned char)*line)) line++;

    /* Skip common prefixes like sudo, env, nice, etc. */
    static const char *skip_prefixes[] = {
        "sudo ", "env ", "nice ", "nohup ", "time ", NULL
    };
    for (const char **sp = skip_prefixes; *sp; sp++) {
        size_t len = strlen(*sp);
        if (strncasecmp(line, *sp, len) == 0) {
            line += len;
            while (*line && isspace((unsigned char)*line)) line++;
            break;
        }
    }

    /* Copy first word */
    size_t i = 0;
    while (line[i] && !isspace((unsigned char)line[i]) && i < max - 1) {
        prefix[i] = line[i];
        i++;
    }
    prefix[i] = '\0';
}

/* ── Find or create entry in baseline ─────────────────────────────── */

static BaselineEntry *find_or_create(Baseline *bl, const char *prefix)
{
    for (int i = 0; i < bl->entry_count; i++) {
        if (strcmp(bl->entries[i].prefix, prefix) == 0)
            return &bl->entries[i];
    }
    if (bl->entry_count >= MAX_BASELINE_ENTRIES)
        return NULL;
    BaselineEntry *e = &bl->entries[bl->entry_count++];
    strncpy(e->prefix, prefix, BASELINE_PREFIX_LEN - 1);
    e->prefix[BASELINE_PREFIX_LEN - 1] = '\0';
    e->count = 0;
    return e;
}

/* ── Simple sort by count (descending) ────────────────────────────── */

static int cmp_entries(const void *a, const void *b)
{
    return ((const BaselineEntry *)b)->count - ((const BaselineEntry *)a)->count;
}

/* ── Public: Learn mode ───────────────────────────────────────────── */

int baseline_learn(const char *input_path, const char *output_path)
{
    FILE *in = fopen(input_path, "r");
    if (!in) { perror("scd: cannot open input for baseline learning"); return -1; }

    Baseline bl;
    memset(&bl, 0, sizeof(bl));

    char line[MAX_CMD_LEN];
    while (fgets(line, sizeof(line), in)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0] || line[0] == '#') continue;

        char prefix[BASELINE_PREFIX_LEN];
        extract_prefix(line, prefix, sizeof(prefix));
        if (!prefix[0]) continue;

        BaselineEntry *e = find_or_create(&bl, prefix);
        if (e) {
            e->count++;
            bl.total_commands++;
        }
    }
    fclose(in);

    /* Sort by frequency */
    qsort(bl.entries, (size_t)bl.entry_count, sizeof(BaselineEntry), cmp_entries);

    /* Write to file */
    FILE *out = fopen(output_path, "w");
    if (!out) { perror("scd: cannot write baseline file"); return -1; }

    fprintf(out, "SCD_BASELINE v1\n");
    for (int i = 0; i < bl.entry_count; i++)
        fprintf(out, "%d %s\n", bl.entries[i].count, bl.entries[i].prefix);
    fprintf(out, "TOTAL %d\n", bl.total_commands);
    fclose(out);

    fprintf(stderr, "scd: baseline learned — %d unique commands, %d total from %s\n",
            bl.entry_count, bl.total_commands, input_path);
    return 0;
}

/* ── Public: Load baseline ────────────────────────────────────────── */

int baseline_load(const char *path, Baseline *bl)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    memset(bl, 0, sizeof(*bl));

    char line[256];
    /* Check header */
    if (!fgets(line, sizeof(line), fp) || strncmp(line, "SCD_BASELINE", 12) != 0) {
        fclose(fp);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "TOTAL ", 6) == 0) {
            bl->total_commands = atoi(line + 6);
            continue;
        }
        if (bl->entry_count >= MAX_BASELINE_ENTRIES) break;

        int count = 0;
        char prefix[BASELINE_PREFIX_LEN] = "";
        if (sscanf(line, "%d %63s", &count, prefix) == 2) {
            bl->entries[bl->entry_count].count = count;
            strncpy(bl->entries[bl->entry_count].prefix, prefix, BASELINE_PREFIX_LEN - 1);
            bl->entry_count++;
        }
    }
    fclose(fp);
    return 0;
}

/* ── Public: Anomaly scoring ──────────────────────────────────────── */

float baseline_anomaly_score(const Baseline *bl, const char *command)
{
    if (!bl || bl->total_commands == 0 || !command)
        return 0.5f;   /* unknown baseline → moderate anomaly */

    char prefix[BASELINE_PREFIX_LEN];
    extract_prefix(command, prefix, sizeof(prefix));
    if (!prefix[0]) return 0.0f;

    /* Look up in baseline */
    for (int i = 0; i < bl->entry_count; i++) {
        if (strcmp(bl->entries[i].prefix, prefix) == 0) {
            float freq = (float)bl->entries[i].count / (float)bl->total_commands;
            /* Common command (>5% of history): very normal */
            if (freq > 0.05f) return 0.05f;
            /* Moderate (1-5%): normal */
            if (freq > 0.01f) return 0.15f;
            /* Infrequent (0.1-1%): slightly unusual */
            if (freq > 0.001f) return 0.35f;
            /* Rare (<0.1%): suspicious */
            return 0.55f;
        }
    }

    /* Never seen before: highly anomalous */
    return 0.90f;
}
