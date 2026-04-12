/*
 * scorer.c — Risk Score Aggregator
 *
 * Sums base scores for all matched rules and returns an aggregate
 * risk score capped at SCORE_CAP (100).
 */

#include "scorer.h"

int score_calculate(const MatchedRule matches[], int count)
{
    int total = 0;
    for (int i = 0; i < count; i++)
        total += risk_level_score(matches[i].rule.risk_level);
    return (total > SCORE_CAP) ? SCORE_CAP : total;
}

const char *score_label(int score)
{
    if (score <= THRESH_CLEAN)
        return "clean";
    if (score <= THRESH_DANGER)
        return "suspicious";
    return "dangerous";
}
