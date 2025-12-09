#include "http.h"
#include "log.h"
#include "sds.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

/*
 * Read a file and return it's file descriptor
 * @param file path
 */
FILE *fileOpen(char *path) {
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    log_error("Could not read %s", path);
    return NULL;
  }
  return file;
}

/*
 * Read a file and calcutale it's lenght.
 * Used to calcutale the Header Content-Length.
 * @param file descriptor
 */
ssize_t fileLen(FILE *file) {
  long int len;

  if (fseek(file, 0, SEEK_END)) {
    log_error("Impossibile posizionare il pointer alla fine del file: %s",
              strerror(errno));
    return -1;
  }

  len = ftell(file);
  rewind(file);

  return len;
}

/*
 * Read a file and put it's bytes inside a buffer
 * @file descriptor
 * @buff buffer to write byte read
 * @len how many bytes to read
 * */
ssize_t fileRead(FILE *file, char *buf, ulong len) {
  return fread(buf, sizeof(char), len, file);
}

int fileEndsWithHtml(char *filename, size_t len) {
  if (len < 5) {
    return 1;
  }

  char *end = (filename + len) - 1;

  return (*(end) | 0x20) == 'l' && (*(end - 1) | 0x20) == 'm' &&
         (*(end - 2) | 0x20) == 't' && (*(end - 3) | 0x20) == 'h' &&
         (*(end - 4) | 0x20) == '.';
}

/*
 * Check if the buffer contains a CRLF only if the buffer is at least 4 byes
 * long.
 * @param buffer of chars
 * @param len of the buffer
 * */
static int endOfHeader(client *c) {
  if (c->buf.len < 4) {
    return -1;
  }
  // Pointer to the end of the buf
  // TODO change with strpbrk()
  const char *end = c->buf.buf + c->buf.len;
  return (end[-4] == '\r' && end[-3] == '\n' && end[-2] == '\r' &&
          end[-1] == '\n');
}

char *nextToken(char *buf, char delimter) {
  if (buf == NULL) {
    return NULL;
  }

  char *c = strchr(buf, delimter);
  if (c) {
    *c = '\0';
    return c + 1;
  }

  return NULL;
}

int parseRequestLine(char *buf, http_req_line_t *rql) {
  rql->method = buf;
  char *next = nextToken(buf, ' ');
  if (next == NULL) {
    log_error("Error while parsing metohd, missing a space!");
    return -1;
  }

  rql->target = next;
  next = nextToken(next, ' ');
  if (next == NULL) {
    log_error("Error while parsing target, missing a space!");
    return -1;
  }

  rql->version = next;
  char *end = nextToken(next, '\r');
  if (end == NULL) {
    log_error("Error while parsing version, CRLF is missing");
    return -1;
  }

  *(end) = '\0';
  return 0;
}

static int parseRequestHeaders(void) { return 0; }

static int parseRequest(client *c) {
  char *buf = c->buf.buf;

  if (parseRequestLine(buf, &c->req.line) == -1) {
    log_error("Request line parsing has failed!");
    return -1;
  }

  // TODO
  parseRequestHeaders();

  return 0;
}

static void addResponseHeader(client *c, char *key, char *value) {
  if (c->resp.headers_count >= MAX_RESPONSE_HEADERS) {
    return;
  }
  int i = c->resp.headers_count;
  c->resp.headers[i].key = key;
  c->resp.headers[i].value = value;
}

#define HTTP_OK 200
#define HTTP_NOT_FOUND 404
#define HTTP_INT_SERV_ERR 500
static const char *getReasonPhrase(int code) {
  switch (code) {
  case HTTP_OK:
    return "OK";
  case HTTP_NOT_FOUND:
    return "Not Found";
  case HTTP_INT_SERV_ERR:
    return "Internal Server Error";
  default:
    return "Unknown";
  }
}

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages#http_responses
static void addStatusLine(client *c) {
  if (c->resp.buf)
    sdsfree(c->resp.buf);

  c->resp.buf = sdsempty();
  c->resp.buf = sdscatprintf(c->resp.buf, "%s %d %s\r\n", HTTP_V, c->resp.code,
                             getReasonPhrase(c->resp.code));
  return;
}

static void addHeaders(client *c) {
  for (ssize_t i = 0; i < c->resp.headers_count; i++) {
    c->resp.buf =
        sdscatprintf(c->resp.buf, "%s: %s \r\n", c->resp.headers[i].key,
                     c->resp.headers[i].value);
  }
  return;
}

static void addCRLF(client *c) {
  c->resp.buf = sdscatprintf(c->resp.buf, "\r\n");
}

static void addBody(client *c) {
  c->resp.buf = sdscatprintf(c->resp.buf, "%s", c->resp.body);
  return;
}

static int prepareResponse(client *c) {
  addStatusLine(c);
  addHeaders(c);
  addCRLF(c);
  addBody(c);

  log_debug("HTTP Response: %s", c->resp.buf);
  return 0;
}

static void sendError() { return; }
static void sendFile() { return; }

static void handleGet(client *c) {
  char index[] = "index.html";

  // Path Resolution
  const char *target = c->req.line.target;
  if (strcmp(target, "/") == 0) {
    FILE *file = fileOpen(index);
    if (file == NULL) {
      log_error("Could not open file.");
      sendError();
      return;
    }

    c->resp.body_len = fileLen(file);
    if (c->resp.body_len < 0) {
      log_error("Could not read file len.");
      sendError();
      return;
    }

    log_debug("Content-Length: %zu", c->resp.body_len);

    c->resp.body = (char *)malloc(c->resp.body_len + 1);
    if (c->resp.body == NULL) {
      log_error("Could not allocate memory for response body!");
      sendError();
      return;
    }

    ssize_t byte_read = fileRead(file, c->resp.body, c->resp.body_len);
    if (byte_read < c->resp.body_len) {
      log_error("Could not read all bytes from file.");
      sendError();
      return;
    }
    fclose(file);

    c->resp.body[c->resp.body_len] = '\0';
    c->resp.code = HTTP_OK;

    if (fileEndsWithHtml(index, strlen(index))) {
      addResponseHeader(c, "Content-Type", "text/html");
    } else {
      addResponseHeader(c, "Content-Type", "text/plain");
    }

    addResponseHeader(c, "Content-Length", sdsfromlonglong(c->resp.body_len));
  }

  if (prepareResponse(c) == -1) {
    log_error("Could not prepare response.");
    sendError();
    return;
  }
  return;
}

static void handlePost(client *c) { return; }

static void dispatchRequest(client *c) {
  int get = strcmp(c->req.line.method, "GET") == 0;
  int post = strcmp(c->req.line.method, "POST") == 0;

  if (get) {
    log_info("Recived HTTP GET request from client.");
    handleGet(c);
  } else if (post) {
    log_info("Recived HTTP POST request from client.");
    handlePost(c);
  } else {
    sendError();
  }
}

static void sendResponse(client *c) {}

void httpHandleClient(int fd) {
  // TODO init inside a fun
  client *c = (client *)malloc(sizeof(*c));
  if (c == NULL)
    pthread_exit((void *)-1);
  memset(c, 0, sizeof(*c));

  c->fd = fd;
  c->buf.cap = REQUEST_CAPACITY;
  c->buf.len = 0;
  c->buf.buf = (char *)malloc(sizeof(char) * c->buf.cap);

  // TODO separate into Read Client FD
  while (1) {
    ssize_t free_space = (c->buf.cap) - (c->buf.len);
    if (free_space < 1024) {
      log_debug("Reqeust buf is almost full, reallocating...");
      c->buf.cap *= 2;

      char *new_buff = realloc(c->buf.buf, sizeof(char) * c->buf.cap);
      if (new_buff == NULL) {
        log_error("Could not allocate memory for request buffer!");
        pthread_exit((void *)-1);
      }

      c->buf.buf = new_buff;

      if (c->buf.buf == NULL) {
        log_error("Could not allocate memory for request buffer!");
        pthread_exit((void *)-1);
      }

      log_debug("Request buf reallocated is now %d bytes.", c->buf.cap);
    }

    ssize_t byte_read = recv(c->fd, c->buf.buf + c->buf.len, free_space, 0);

    if ((int)byte_read == 0) {
      log_error("Socket data has been read.");
      break;
    }

    if ((int)byte_read == -1) {
      log_error("Socket reading error: %s", strerror(errno));
      break;
    }

    c->buf.len += byte_read;
    log_debug("Request Capacity: %zu\nRequest Len: %zu\n", c->buf.cap,
              c->buf.len);

    // Possible optimization only give last byte received
    if (endOfHeader(c)) {
      log_debug("Complete header received!");

      // Now the buffer is a valid C string
      c->buf.buf[c->buf.len] = '\0';
      break;
    }
  }

  parseRequest(c);

  dispatchRequest(c);

  // Reply
  if (send(c->fd, c->resp.buf, sdslen(c->resp.buf), 0) == -1) {
    log_error("Could not send HTTP response!\n");
    free(c);
    pthread_exit((void *)-1);
  }

  log_info("HTTP Response sent to: %d\n", c->fd);

  // Cleanup
  if (close(c->fd) == -1) {
    log_error("Error while closing the socket: %s\n", strerror(errno));
    free(c);
    pthread_exit((void *)-1);
  }

  free(c);
  pthread_exit((void *)0);
}
