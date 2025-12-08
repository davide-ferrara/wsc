#include "wsc.h"

#define MAX_HTTP_HEADERS 32

typedef struct {
  char *key;
  char *value;
} http_header_item_t;

typedef struct {
  char *method;
  char *target;
  char *http_version;
} http_request_line_t;

typedef struct {
  http_request_line_t request_line;
  http_header_item_t headers[MAX_HTTP_HEADERS];
  int headers_count;
} http_header_t;

typedef struct {
  int code;
  char *reason_phrase;
} http_status;

typedef struct {
  size_t len;
  size_t cap;
  char *buf;
} buffer_t;

typedef struct client {
  int sock;
  buffer_t req;
  sds resp;
  char target[4096];
  char addr[16];
  http_header_t *header;
} client;

void http_handle_client(int client_sock);
