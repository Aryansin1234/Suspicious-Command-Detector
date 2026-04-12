/*
 * web_server.c — Minimal HTTP Server for SCD Dashboard
 *
 * Provides a browser-based dashboard by serving:
 *   GET /               → HTML dashboard page
 *   GET /api/alerts     → JSON array of alerts from log file
 *   GET /api/stats      → Aggregate statistics
 *
 * Uses POSIX sockets only — zero external dependencies.
 */

#include "web_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>

static volatile sig_atomic_t g_web_running = 1;

static void web_sig_handler(int sig) { (void)sig; g_web_running = 0; }

/* ── HTTP response helpers ────────────────────────────────────────── */

static void send_response(int fd, const char *status, const char *content_type,
                          const char *body, size_t body_len)
{
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "\r\n", status, content_type, body_len);
    write(fd, header, (size_t)hlen);
    if (body && body_len > 0)
        write(fd, body, body_len);
}

static void send_404(int fd)
{
    const char *body = "{\"error\":\"not found\"}";
    send_response(fd, "404 Not Found", "application/json", body, strlen(body));
}

/* ── Read file into malloc'd buffer ───────────────────────────────── */

static char *read_file(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "r");
    if (!fp) { *out_len = 0; return NULL; }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (sz <= 0) { fclose(fp); *out_len = 0; return NULL; }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); *out_len = 0; return NULL; }

    *out_len = fread(buf, 1, (size_t)sz, fp);
    buf[*out_len] = '\0';
    fclose(fp);
    return buf;
}

/* ── Wrap individual JSON objects into an array ───────────────────── */

static char *wrap_json_array(const char *raw, size_t raw_len, size_t *out_len)
{
    /* The log file has one JSON object per alert, not an array.
       Wrap them: find each top-level { ... } and join with commas. */
    size_t alloc = raw_len + 256;
    char *arr = malloc(alloc);
    if (!arr) { *out_len = 0; return NULL; }

    size_t pos = 0;
    arr[pos++] = '[';

    int depth = 0, first = 1, in_string = 0;
    size_t obj_start = 0;

    for (size_t i = 0; i < raw_len; i++) {
        char c = raw[i];
        if (c == '"' && (i == 0 || raw[i-1] != '\\'))
            in_string = !in_string;
        if (in_string) continue;

        if (c == '{') {
            if (depth == 0) obj_start = i;
            depth++;
        } else if (c == '}') {
            depth--;
            if (depth == 0) {
                size_t obj_len = i - obj_start + 1;
                if (pos + obj_len + 4 > alloc) {
                    alloc = alloc * 2 + obj_len;
                    arr = realloc(arr, alloc);
                    if (!arr) { *out_len = 0; return NULL; }
                }
                if (!first) arr[pos++] = ',';
                memcpy(arr + pos, raw + obj_start, obj_len);
                pos += obj_len;
                first = 0;
            }
        }
    }

    arr[pos++] = ']';
    arr[pos] = '\0';
    *out_len = pos;
    return arr;
}

/* ── Generate stats JSON from alerts ──────────────────────────────── */

static char *generate_stats(const char *alerts_path, size_t *out_len)
{
    size_t raw_len = 0;
    char *raw = read_file(alerts_path, &raw_len);

    int total = 0, critical = 0, high = 0, medium = 0, low = 0;
    if (raw) {
        /* Count occurrences of risk levels */
        const char *p = raw;
        while ((p = strstr(p, "\"risk_level\"")) != NULL) {
            total++;
            if (strstr(p, "dangerous"))  critical++;
            else if (strstr(p, "suspicious")) medium++;
            p += 12;
        }
        /* More detailed counting */
        p = raw;
        while ((p = strstr(p, "\"risk\":\"CRITICAL\"")) != NULL) { high++; p += 15; }
        p = raw;
        while ((p = strstr(p, "\"risk\":\"HIGH\"")) != NULL) { high++; p += 11; }
        free(raw);
    }

    char *buf = malloc(512);
    *out_len = (size_t)snprintf(buf, 512,
        "{\"total_alerts\":%d,\"critical\":%d,\"high\":%d,"
        "\"medium\":%d,\"low\":%d,\"last_updated\":\"%s\"}",
        total, critical, high, medium, low, "now");
    return buf;
}

/* ── Handle a single HTTP request ─────────────────────────────────── */

static void handle_request(int client_fd, const char *alerts_path,
                           const char *html_path)
{
    char buf[4096];
    ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = '\0';

    /* Parse request method and path */
    char method[8] = "", path[256] = "";
    sscanf(buf, "%7s %255s", method, path);

    if (strcmp(method, "GET") != 0) {
        send_404(client_fd);
        return;
    }

    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        /* Serve dashboard HTML */
        size_t len = 0;
        char *html = read_file(html_path, &len);
        if (html) {
            send_response(client_fd, "200 OK", "text/html; charset=utf-8", html, len);
            free(html);
        } else {
            const char *msg = "<h1>SCD Dashboard</h1><p>dashboard.html not found</p>";
            send_response(client_fd, "200 OK", "text/html", msg, strlen(msg));
        }
    } else if (strcmp(path, "/api/alerts") == 0) {
        size_t raw_len = 0;
        char *raw = read_file(alerts_path, &raw_len);
        if (raw) {
            size_t arr_len = 0;
            char *arr = wrap_json_array(raw, raw_len, &arr_len);
            free(raw);
            if (arr) {
                send_response(client_fd, "200 OK", "application/json", arr, arr_len);
                free(arr);
            } else {
                send_response(client_fd, "200 OK", "application/json", "[]", 2);
            }
        } else {
            send_response(client_fd, "200 OK", "application/json", "[]", 2);
        }
    } else if (strcmp(path, "/api/stats") == 0) {
        size_t len = 0;
        char *stats = generate_stats(alerts_path, &len);
        if (stats) {
            send_response(client_fd, "200 OK", "application/json", stats, len);
            free(stats);
        }
    } else {
        send_404(client_fd);
    }
}

/* ── Public: Start the web server ─────────────────────────────────── */

int web_server_start(int port, const char *alerts_path, const char *html_path)
{
    struct sigaction sa;
    sa.sa_handler = web_sig_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("scd: socket"); return -1; }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("scd: bind");
        close(sock);
        return -1;
    }

    if (listen(sock, 16) < 0) {
        perror("scd: listen");
        close(sock);
        return -1;
    }

    fprintf(stderr,
        "\n"
        "  ╔══════════════════════════════════════════╗\n"
        "  ║  🛡️  SCD Web Dashboard                   ║\n"
        "  ║  http://localhost:%-5d                  ║\n"
        "  ║  Press Ctrl+C to stop                   ║\n"
        "  ╚══════════════════════════════════════════╝\n"
        "\n"
        "  Serving alerts from: %s\n\n",
        port, alerts_path);

    while (g_web_running) {
        int client = accept(sock, NULL, NULL);
        if (client < 0) continue;
        handle_request(client, alerts_path, html_path);
        close(client);
    }

    close(sock);
    fprintf(stderr, "\n  SCD web server stopped.\n");
    return 0;
}
