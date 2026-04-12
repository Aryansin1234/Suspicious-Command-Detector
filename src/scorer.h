#ifndef SCD_SCORER_H
#define SCD_SCORER_H

#include "scd.h"

/*
 * Calculate aggregate risk score from matched rules.
 * Score is the sum of individual rule base scores, capped at SCORE_CAP.
 */
int score_calculate(const MatchedRule matches[], int count);

/*
 * Return human-readable label for a numeric risk score:
 *   0–20  → "clean"
 *   21–50 → "suspicious"
 *   51+   → "dangerous"
 */
const char *score_label(int score);

#endif /* SCD_SCORER_H */
