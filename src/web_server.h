#ifndef SCD_WEB_SERVER_H
#define SCD_WEB_SERVER_H

#include "scd.h"

#define WEB_DEFAULT_PORT 8080

/*
 * Start the SCD web dashboard server.
 * Serves a visual dashboard at / and alert data at /api/alerts.
 *
 * Parameters:
 *   port        — TCP port to listen on
 *   alerts_path — path to JSON alerts log file (produced by scd -f json -l ...)
 *   html_path   — path to dashboard HTML file (web/dashboard.html)
 *
 * This function blocks (runs the accept loop). Does not return
 * unless SIGTERM/SIGINT is received. Returns 0 on clean shutdown.
 */
int web_server_start(int port, const char *alerts_path, const char *html_path);

#endif /* SCD_WEB_SERVER_H */
