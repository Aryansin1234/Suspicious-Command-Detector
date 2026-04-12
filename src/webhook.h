#ifndef SCD_WEBHOOK_H
#define SCD_WEBHOOK_H

#include "scd.h"

/*
 * Send an alert to a generic webhook endpoint via HTTP POST.
 * Uses system curl — no library dependency.
 * Returns 0 on success, -1 on error.
 */
int webhook_send(const char *url, const Alert *alert);

/*
 * Send an alert formatted for Slack (Block Kit).
 * Returns 0 on success, -1 on error.
 */
int webhook_send_slack(const char *url, const Alert *alert);

#endif /* SCD_WEBHOOK_H */
