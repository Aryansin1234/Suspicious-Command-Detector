/*
 * scorer.c — Risk Score Aggregator
 *
 * Sums base scores for all matched rules with compound bonuses.
 */

#include "scorer.h"

int score_calculate(const MatchedRule matches[], int count)
{
    if (count <= 0) return 0;

    int total = 0;
    int has_critical = 0;
    for (int i = 0; i < count; i++) {
        total += risk_level_score(matches[i].rule.risk_level);
        if (matches[i].rule.risk_level == RISK_CRITICAL)
            has_critical = 1;
    }

    /* Compound bonus: multiple matches = more dangerous */
    if (count >= 2) total += 10;
    if (count >= 3) total += 10;

    /* CRITICAL always trips dangerous threshold */
    if (has_critical && total < THRESH_DANGER + 1)
        total = THRESH_DANGER + 1;

    return (total > SCORE_CAP) ? SCORE_CAP : total;
}

const char *score_label(int score)
{
    if (score <= THRESH_CLEAN)  return "clean";
    if (score <= THRESH_DANGER) return "suspicious";
    return "dangerous";
}
