#ifndef SCD_SCORER_H
#define SCD_SCORER_H

#include "scd.h"

/*
 * Calculate aggregate risk score from matched rules.
 * Applies compound bonuses for multiple matches.
 * Returns score capped at SCORE_CAP (100).
 */
int score_calculate(const MatchedRule matches[], int count);

/* Return human-readable label for a score */
const char *score_label(int score);

#endif /* SCD_SCORER_H */
