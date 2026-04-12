#ifndef SCD_DAEMON_H
#define SCD_DAEMON_H

#include "scd.h"
#include "rule_engine.h"

/*
 * Start SCD as a background daemon.
 * Forks, creates a new session, writes PID file, installs signal
 * handlers, and enters the watch-parse-alert main loop.
 * Returns only on error (returns -1) or on SIGTERM (returns 0).
 */
int daemon_start(const Config *config, Rule rules[], int rule_count,
                 const char wl[][MAX_PATTERN_LEN], int wl_count);

#endif /* SCD_DAEMON_H */
