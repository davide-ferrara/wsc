#include "wsc.h"
#include <stddef.h>
#include <sys/types.h>

#define HTTP_V "HTTP/1.1"
#define REQUEST_CAPACITY 4096
#define MAX_REQUEST_HEADERS 32
#define MAX_RESPONSE_HEADERS 32

typedef struct {
  size_t len;
  size_t cap;
  char *buf;
} buffer_t;

typedef struct {
  char *key;
  char *value;
} http_header_t;

typedef struct {
  char *method;
  char *target;
  char *version;
} http_req_line_t;

typedef struct {
  http_req_line_t line;
  ssize_t headers_count;
  http_header_t headers[MAX_REQUEST_HEADERS];
} http_req_t;

// https://developer.mozilla.org/en-US/docs/Glossary/Representation_header
typedef struct {
  int code;
  http_header_t headers[MAX_RESPONSE_HEADERS];
  ssize_t headers_count;
  char *body;
  ssize_t body_len;
  sds buf;
} http_resp_t;

// https://developer.mozilla.org/en-US/docs/Glossary/Request_header
typedef struct client {
  int fd;
  char addr[16];
  buffer_t buf;
  http_req_t req;
  http_resp_t resp;
} client;

void httpHandleClient(int fd);
