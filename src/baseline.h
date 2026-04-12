#ifndef SCD_BASELINE_H
#define SCD_BASELINE_H

#include "scd.h"

#define MAX_BASELINE_ENTRIES 2048
#define BASELINE_PREFIX_LEN  64

/* Single command frequency entry */
typedef struct {
    char prefix[BASELINE_PREFIX_LEN]; /* First word (command name) */
    int  count;                       /* Times seen in training set */
} BaselineEntry;

/* Full baseline profile */
typedef struct {
    BaselineEntry entries[MAX_BASELINE_ENTRIES];
    int           entry_count;
    int           total_commands;
} Baseline;

/*
 * Learn mode: read commands from input file, build frequency profile,
 * and write the baseline to output_path.
 * Returns 0 on success, -1 on error.
 */
int baseline_learn(const char *input_path, const char *output_path);

/*
 * Load a previously saved baseline from disk.
 * Returns 0 on success, -1 on error.
 */
int baseline_load(const char *path, Baseline *bl);

/*
 * Compute an anomaly score for a command against the baseline.
 * Returns a float 0.0 (normal) to 1.0 (highly anomalous).
 *   0.0 – 0.2  = common command, normal
 *   0.2 – 0.5  = infrequent but known
 *   0.5 – 0.8  = rare command, review advised
 *   0.8 – 1.0  = never-before-seen, suspicious
 */
float baseline_anomaly_score(const Baseline *bl, const char *command);

#endif /* SCD_BASELINE_H */
