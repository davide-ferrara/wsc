#ifndef HTTP_H
#define HTTP_H

#include "sds.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// https://github.com/rxi/log.c/blob/master/src/log.h
#include "log.h"

#define HTTP_V "HTTP/1.1"
#define HTTP_OK 200
#define HTTP_NOT_FOUND 404
#define HTTP_INT_SERV_ERR 500
#define HTTP_NOT_SUPP 505

#define REQUEST_CAPACITY 4096
#define MAX_REQUEST_HEADERS 32
#define MAX_RESPONSE_HEADERS 32

#define ERROR_PAGE_PATH "error_pages/"

/* Server state structure */
struct http_server {
  int port;
  char *addr;
  int listen_fd;
};

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

/* Opaque structures for the server */
typedef struct http_server http_server_t;

/* --- API Public Functions --- */

/* Create a new HTTP server instance. Returns NULL on error. */
http_server_t *httpCreateServer(const char *addr, int port);

/* Start the main loop (blocking). Accepts connections and spawns threads. */
void httpServe(http_server_t *server);

/* Free server resources */
void httpFreeServer(http_server_t *server);

/* Handle a single client connection */
void httpHandleClient(client *c);

#endif
