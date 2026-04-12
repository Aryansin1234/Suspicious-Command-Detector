/*
 * webhook.c — Alert Forwarding via HTTP POST
 *
 * Sends alert payloads to generic webhooks or Slack-formatted
 * endpoints using the system `curl` command (zero library deps).
 */

#include "webhook.h"
#include <stdio.h>
#include <string.h>

/* ── JSON escape helper ──────────────────────────────────────────── */

static void json_escape_str(char *dst, size_t dst_len, const char *src)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_len - 2; i++) {
        switch (src[i]) {
        case '"':  dst[j++] = '\\'; dst[j++] = '"';  break;
        case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
        case '\n': dst[j++] = '\\'; dst[j++] = 'n';  break;
        case '\r': dst[j++] = '\\'; dst[j++] = 'r';  break;
        case '\t': dst[j++] = '\\'; dst[j++] = 't';  break;
        default:   dst[j++] = src[i]; break;
        }
    }
    dst[j] = '\0';
}

/* ── Generic webhook ──────────────────────────────────────────────── */

int webhook_send(const char *url, const Alert *alert)
{
    if (!url || !url[0] || !alert) return -1;

    char esc_cmd[MAX_CMD_LEN * 2];
    char esc_label[32];
    json_escape_str(esc_cmd, sizeof(esc_cmd), alert->command);
    json_escape_str(esc_label, sizeof(esc_label), alert->risk_label);

    char payload[8192];
    int n = snprintf(payload, sizeof(payload),
        "{"
        "\"source\":\"scd\","
        "\"version\":\"%s\","
        "\"timestamp\":\"%s\","
        "\"command\":\"%s\","
        "\"risk_score\":%d,"
        "\"risk_level\":\"%s\","
        "\"matched_rules\":[",
        SCD_VERSION, alert->timestamp, esc_cmd,
        alert->risk_score, esc_label);

    for (int i = 0; i < alert->match_count && n < (int)sizeof(payload) - 256; i++) {
        char esc_pat[MAX_PATTERN_LEN * 2];
        char esc_desc[MAX_DESC_LEN * 2];
        json_escape_str(esc_pat, sizeof(esc_pat), alert->matches[i].rule.pattern);
        json_escape_str(esc_desc, sizeof(esc_desc), alert->matches[i].rule.description);
        n += snprintf(payload + n, sizeof(payload) - (size_t)n,
            "%s{\"id\":\"%s\",\"risk\":\"%s\",\"pattern\":\"%s\",\"desc\":\"%s\"}",
            (i > 0) ? "," : "",
            alert->matches[i].rule.id,
            risk_level_to_str(alert->matches[i].rule.risk_level),
            esc_pat, esc_desc);
    }
    snprintf(payload + n, sizeof(payload) - (size_t)n, "]}");

    /* Build curl command — run in background (&) to not block */
    char curl_cmd[sizeof(payload) + 512];
    snprintf(curl_cmd, sizeof(curl_cmd),
        "curl -sS -X POST "
        "-H 'Content-Type: application/json' "
        "-d '%s' "
        "'%s' >/dev/null 2>&1 &",
        payload, url);

    return system(curl_cmd);
}

/* ── Slack-formatted webhook ──────────────────────────────────────── */

int webhook_send_slack(const char *url, const Alert *alert)
{
    if (!url || !url[0] || !alert) return -1;

    const char *emoji;
    const char *color;
    if (alert->risk_score > THRESH_DANGER) {
        emoji = ":rotating_light:"; color = "#FF0000";
    } else if (alert->risk_score > THRESH_CLEAN) {
        emoji = ":warning:"; color = "#FFA500";
    } else {
        emoji = ":white_check_mark:"; color = "#36A64F";
    }

    char esc_cmd[MAX_CMD_LEN * 2];
    json_escape_str(esc_cmd, sizeof(esc_cmd), alert->command);

    /* Build matched rules text */
    char rules_text[2048] = "";
    int rn = 0;
    for (int i = 0; i < alert->match_count && rn < (int)sizeof(rules_text) - 128; i++) {
        rn += snprintf(rules_text + rn, sizeof(rules_text) - (size_t)rn,
            "• `%s` %s — %s\\n",
            alert->matches[i].rule.id,
            risk_level_to_str(alert->matches[i].rule.risk_level),
            alert->matches[i].rule.description);
    }

    char payload[8192];
    snprintf(payload, sizeof(payload),
        "{"
        "\"attachments\":[{"
        "\"color\":\"%s\","
        "\"blocks\":["
        "{\"type\":\"header\",\"text\":{\"type\":\"plain_text\",\"text\":\"%s SCD Alert — %s\"}},"
        "{\"type\":\"section\",\"fields\":["
        "{\"type\":\"mrkdwn\",\"text\":\"*Command:*\\n`%s`\"},"
        "{\"type\":\"mrkdwn\",\"text\":\"*Score:*\\n%d/100 (%s)\"}"
        "]},"
        "{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":\"*Matched Rules:*\\n%s\"}}"
        "]}]}",
        color, emoji, alert->risk_label,
        esc_cmd, alert->risk_score, alert->risk_label,
        rules_text);

    char curl_cmd[sizeof(payload) + 512];
    snprintf(curl_cmd, sizeof(curl_cmd),
        "curl -sS -X POST "
        "-H 'Content-Type: application/json' "
        "-d '%s' "
        "'%s' >/dev/null 2>&1 &",
        payload, url);

    return system(curl_cmd);
}
