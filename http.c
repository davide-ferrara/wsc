#include "http.h"
#include "sds.h"
#include <string.h>

static void sendFile(client *c, char *path);

/* ==========================================================================
 * Networking Helpers (Private)
 * ========================================================================== */

/* * Create a TCP socket, bind it and start listening.
 * Returns the socket file descriptor or -1 on error.
 * * We use SO_REUSEADDR to avoid "Address already in use" errors during
 * restarts (TIME_WAIT state).
 */
static int createServerSocket(const char *addr, int port) {
  int s, opt = 1;
  int backlog = 511; // Standard Redis backlog size
  struct sockaddr_in sa;

  // 1. Create socket
  if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    log_error("Failed to create server socket: %s", strerror(errno));
    return -1;
  }

  // 2. Set options
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
    log_error("setsockopt failed: %s", strerror(errno));
    close(s);
    return -1;
  }

  // 3. Initialize address struct
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);

  // Handle IP binding
  if (addr == NULL) {
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
  } else {
    if (inet_pton(AF_INET, addr, &sa.sin_addr) <= 0) {
      log_error("Invalid bind address: %s", addr);
      close(s);
      return -1;
    }
  }

  // 4. Bind
  if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
    log_error("Bind failed: %s", strerror(errno));
    close(s);
    return -1;
  };

  // 5. Listen
  if (listen(s, backlog) == -1) {
    log_error("Listen failed on port %d: %s", port, strerror(errno));
    close(s);
    return -1;
  }

  return s;
}

static client *initClient(int fd) {
  client *c = (client *)malloc(sizeof(*c));
  if (c == NULL) {
    log_error("OOM: Could not allocate client struct");
    return NULL;
  }

  memset(c, 0, sizeof(*c));

  c->fd = fd;
  c->buf.cap = REQUEST_CAPACITY;
  c->buf.len = 0;
  c->buf.buf = (char *)malloc(c->buf.cap);

  if (c->buf.buf == NULL) {
    log_error("OOM: Could not allocate client buffer");
    free(c);
    return NULL;
  }

  return c;
}

/* * Thread entry point.
 * Wraps the httpHandleClient logic. Responsible for freeing the argument.
 */
static void *clientThreadHandler(void *args) {
  int fd = *(int *)args;
  free(args); // Free the pointer allocated in the main loop

  // Call the core logic (defined in your previous http.c code)
  client *c = initClient(fd);
  httpHandleClient(c);

  return NULL;
}

/*
 * Read a file and return it's file descriptor
 * @param file path
 */
FILE *fileOpen(char *path) {
  FILE *file = fopen(path, "r");
  if (file == NULL) {
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
  c->resp.headers_count++;
}

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
static int addStatusLine(client *c) {
  if (c->resp.buf)
    sdsfree(c->resp.buf);

  c->resp.buf = sdsempty();
  c->resp.buf = sdscatprintf(c->resp.buf, "%s %d %s\r\n", HTTP_V, c->resp.code,
                             getReasonPhrase(c->resp.code));
  if (c->resp.buf == NULL) {
    return -1;
  }

  return 0;
}

static int addHeaders(client *c) {
  for (ssize_t i = 0; i < c->resp.headers_count; i++) {
    c->resp.buf =
        sdscatprintf(c->resp.buf, "%s: %s \r\n", c->resp.headers[i].key,
                     c->resp.headers[i].value);
  }

  if (c->resp.buf == NULL) {
    return -1;
  }

  return 0;
}

static int addCRLF(client *c) {
  c->resp.buf = sdscatprintf(c->resp.buf, "\r\n");

  if (c->resp.buf == NULL) {
    return -1;
  }
  return 0;
}

static int addBody(client *c) {
  c->resp.buf = sdscatprintf(c->resp.buf, "%s", c->resp.body);

  if (c->resp.buf == NULL) {
    return -1;
  }

  return 0;
}

static int prepareResponse(client *c) {
  if (addStatusLine(c) == -1)
    return -1;
  if (addHeaders(c) == -1) {
    return -1;
  }
  if (addCRLF(c)) {
    return -1;
  }
  if (addBody(c)) {
    return -1;
  }

  return 0;
}

/* Helper per costruire il path: "error_pages/http-404.html" */
static sds getErrorPagePath(int code) {
  sds path = sdsnew(ERROR_PAGE_PATH); // Assumiamo "error_pages/"
  // Costruisce stringa dinamica tipo "http-404.html"
  path = sdscatprintf(path, "http-%d.html", code);
  return path;
}

/*
 * Gestisce l'invio di un errore al client.
 * Tenta di servire una pagina HTML custom (es. error_pages/http-404.html).
 * Se il file non esiste, genera una risposta testuale di fallback.
 */
static void sendError(client *c, int code) {
  // 1. PULIZIA: Reset dello stato "sporco" della risposta
  if (c->resp.body) {
    free(c->resp.body);
    c->resp.body = NULL;
  }
  // Liberiamo eventuali header precedenti (es. Content-Type errati)
  // Nota: Se headers.key/value sono allocati dinamicamente, andrebbero liberati
  // qui.
  c->resp.headers_count = 0;

  // Reset buffer SDS se presente
  if (c->resp.buf) {
    sdsclear(c->resp.buf);
  }

  // 2. SETUP BASE
  c->resp.code = code;
  addResponseHeader(c, "Connection", "close");

  // 3. TENTATIVO PAGINA CUSTOM (La parte "Smart")
  sds page_path = getErrorPagePath(code);

  // access() restituisce 0 se il file esiste ed è leggibile.
  // Questo controllo PREVIENE la ricorsione infinita: se il file non c'è,
  // non chiamiamo sendFile (che richiamerebbe sendError).
  if (access(page_path, R_OK) != -1) {
    log_debug("Serving custom error page: %s", page_path);
    sendFile(c, page_path);
    sdsfree(page_path);
    return; // Successo, usciamo.
  }

  sdsfree(page_path);

  // 4. FALLBACK: Risposta Testuale Semplice
  // Se siamo qui, la pagina HTML custom non esiste.
  log_debug("Custom error page not found for %d, sending text fallback.", code);

  const char *reason = getReasonPhrase(code);

  // Creiamo un body descrittivo: "404 Not Found"
  sds body = sdsempty();
  body = sdscatprintf(body, "%d %s", code, reason);

  c->resp.body =
      strdup(body); // O assegna body direttamente se la struct supporta sds
  c->resp.body_len = sdslen(body);
  sdsfree(body);

  addResponseHeader(c, "Content-Type", "text/plain");
  addResponseHeader(c, "Content-Length", sdsfromlonglong(c->resp.body_len));

  if (prepareResponse(c) == -1) {
    log_error("CRITICAL: Failed to prepare fallback error response");
  }
}

static void sendFile(client *c, char *path) {
  FILE *file = fileOpen(path);
  if (file == NULL) {
    log_info("File %s not found.", path);
    sendError(c, HTTP_NOT_FOUND);
    return;
  }

  c->resp.body_len = fileLen(file);
  if (c->resp.body_len < 0) {
    log_error("Could not read file len.");
    sendError(c, 500);
    return;
  }

  log_debug("Content-Length: %zu", c->resp.body_len);

  c->resp.body = (char *)malloc(c->resp.body_len + 1);
  if (c->resp.body == NULL) {
    log_error("Could not allocate memory for response body!");
    sendError(c, 500);
    return;
  }

  ssize_t byte_read = fileRead(file, c->resp.body, c->resp.body_len);
  if (byte_read < c->resp.body_len) {
    log_error("Could not read all bytes from file.");
    sendError(c, 500);
    return;
  }
  fclose(file);

  c->resp.body[c->resp.body_len] = '\0';
  // c->resp.code = HTTP_OK;

  if (fileEndsWithHtml(path, strlen(path))) {
    addResponseHeader(c, "Content-Type", "text/html");
  } else {
    addResponseHeader(c, "Content-Type", "text/plain");
  }

  sds len = sdsfromlonglong(c->resp.body_len);
  addResponseHeader(c, "Content-Length", len);

  if (prepareResponse(c) == -1) {
    log_error("Could not prepare response.");
    sendError(c, HTTP_INT_SERV_ERR);
    return;
  }
}

static void handleGet(client *c) {
  // Path Resolution
  char *target = c->req.line.target;
  if (strcmp(target, "/") == 0) {
    target = "index.html";
  }

  c->resp.code = HTTP_OK;
  sendFile(c, target);

  return;
}

static void handlePost(client *c) {
  log_error("POST NOT IMPLEMENTED FOR CLIENT: %d!", c->fd);
  return;
}

static void dispatchRequest(client *c) {
  int get = strcmp(c->req.line.method, "GET") == 0;
  int post = strcmp(c->req.line.method, "POST") == 0;

  // TODO implement custom endpoint instead of serving only static files!
  if (get) {
    log_info("Received HTTP GET request from client.");
    // Static files
    handleGet(c);
  } else if (post) {
    log_info("Received HTTP POST request from client.");
    handlePost(c);
  } else {
    log_info("Received not implemented HTTP request from client.");
    sendError(c, HTTP_NOT_SUPP);
  }
}

static int readFromBuf(client *c) {
  while (1) {
    ssize_t free_space = (c->buf.cap) - (c->buf.len);
    if (free_space < 1024) {
      log_debug("Reqeust buf is almost full, reallocating...");
      c->buf.cap *= 2;

      char *new_buff = realloc(c->buf.buf, sizeof(char) * c->buf.cap);
      if (new_buff == NULL) {
        log_error("Could not allocate memory for request buffer!");
        return -1;
      }

      c->buf.buf = new_buff;

      if (c->buf.buf == NULL) {
        log_error("Could not allocate memory for request buffer!");
        return -1;
      }

      log_debug("Request buf reallocated is now %d bytes.", c->buf.cap);
    }

    ssize_t byte_read = recv(c->fd, c->buf.buf + c->buf.len, free_space, 0);

    if ((int)byte_read == 0) {
      log_info("Socket data has been read.");
      break;
    }

    if ((int)byte_read == -1) {
      log_error("Socket reading error: %s", strerror(errno));
      break;
    }

    c->buf.len += byte_read;
    // log_debug("Request Capacity: %zu\nRequest Len: %zu\n", c->buf.cap,
    //           c->buf.len);

    // Possible optimization only give last byte received
    if (endOfHeader(c)) {
      log_debug("Complete header received!");

      // Now the buffer is a valid C string
      c->buf.buf[c->buf.len] = '\0';
      break;
    }
  }
  return 0;
}

static int sendResponse(client *c) {
  if (send(c->fd, c->resp.buf, sdslen(c->resp.buf), 0) == -1) {
    log_error("Could not send HTTP response!\n");
    return -1;
  }
  return 0;
}

static void closeConnection(client *c) {
  if (c->fd != -1)
    close(c->fd);
  if (c->buf.buf)
    free(c->buf.buf);
  if (c->resp.buf)
    sdsfree(c->resp.buf);
  if (c->resp.body)
    free(c->resp.body);

  pthread_exit((void *)0);
}

void httpHandleClient(client *c) {
  if (readFromBuf(c) == 0) {
    if (parseRequest(c) == 0) {
      dispatchRequest(c);
      sendResponse(c);
    }
  }

  closeConnection(c);
}

/* ==========================================================================
 * Public API
 * ========================================================================== */

http_server_t *httpCreateServer(const char *addr, int port) {
  http_server_t *s = malloc(sizeof(*s));
  if (!s)
    return NULL;

  s->port = port;
  s->addr = addr ? strdup(addr) : NULL;
  s->listen_fd = createServerSocket(addr, port);

  if (s->listen_fd == -1) {
    free(s);
    return NULL;
  }

  return s;
}

void httpServe(http_server_t *server) {
  // Setup logging to file (optional, as per your previous code)
  FILE *log_fp = fopen("server.log", "w+");
  if (log_fp)
    log_add_fp(log_fp, 0);

  log_info("HTTP Server listening on %s:%d",
           server->addr ? server->addr : "0.0.0.0", server->port);

  while (1) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    // 1. Accept connection
    int client_fd =
        accept(server->listen_fd, (struct sockaddr *)&client_addr, &client_len);

    if (client_fd == -1) {
      if (errno == EINTR)
        continue; // Interrupted by signal
      log_error("Accept failed: %s", strerror(errno));
      continue;
    }

    // 2. Log connection info
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    log_info("Client connected: %s", client_ip);

    // 3. Threading setup
    pthread_t thread;
    int *arg = malloc(sizeof(int));

    if (arg == NULL) {
      log_error("OOM: Failed to allocate thread argument");
      close(client_fd);
      continue;
    }
    *arg = client_fd;

    // 4. Spawn thread
    if (pthread_create(&thread, NULL, clientThreadHandler, arg) != 0) {
      log_error("Thread creation failed");
      free(arg);
      close(client_fd);
      continue;
    }

    // 5. Detach (fire and forget)
    pthread_detach(thread);
  }
}

void httpFreeServer(http_server_t *server) {
  if (!server)
    return;
  if (server->listen_fd != -1)
    close(server->listen_fd);
  if (server->addr)
    free(server->addr);
  free(server);
}
