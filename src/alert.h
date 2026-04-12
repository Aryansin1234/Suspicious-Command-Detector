#ifndef SCD_ALERT_H
#define SCD_ALERT_H

#include "scd.h"

/* Populate an Alert struct from scan results. */
void alert_init(Alert *alert, const char *command,
                const MatchedRule matches[], int match_count, int risk_score);

/* Write alert in plain-text format. */
void alert_print_text(FILE *out, const Alert *alert);

/* Write alert in JSON format. */
void alert_print_json(FILE *out, const Alert *alert);

/* Send alert to syslog. */
void alert_syslog(const Alert *alert);

#endif /* SCD_ALERT_H */
