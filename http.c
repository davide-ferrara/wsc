#include "http.h"
#include "log.h"
#include "sds.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define HTTP_V "HTTP/1.1"

/*
 * Read a file and return it's file descriptor
 * @param file path
*/
FILE *file_open(char *path) {
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
ssize_t file_len(FILE *file) {
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
ssize_t file_read(FILE *file, char *buf, ulong len) {
  return fread(buf, sizeof(char), len, file);
}

/*
 * TODO docs
 * */
static int consume_token(char **cursor, char delimeter, char **out_token) {
  char *p = *cursor;
  *out_token = p;

  while (*p && *p != delimeter && *p != '\r' && *p != '\n') {
    p++;
  }

  if (*p == delimeter) {
    *p = '\0';
    *cursor = p + 1;
    return 0;
  }

  return -1;
}

/*
 * Check if the buffer contains a CRLF only if the buffer is at least 4 byes
 * long.
 * @param buffer of chars
 * @param len of the buffer
 * */
static int is_end_of_header(const char *buf, size_t len) {
  if (len < 4) {
    return -1;
  }
  // Pointer to the end of the buf
  const char *end = buf + len;
  return (end[-4] == '\r' && end[-3] == '\n' && end[-2] == '\r' &&
          end[-1] == '\n');
}

static int http_parse_header(client *c) {
  char *p = c->header_buff;

  // Parse Request Line
  if (consume_token(&p, ' ', &c->http_header->request_line.method) == -1) {
    log_error("Error while parsing metohd, missing a space!");
    return -1;
  }

  if (consume_token(&p, ' ', &c->http_header->request_line.target) == -1) {
    log_error("Error while parsing target, missing a space!");
    return -1;
  }

  if (consume_token(&p, '\r', &c->http_header->request_line.http_version) ==
      -1) {
    log_error("Error while parsing version, CRLF is missing");
    return -1;
  }

  /* Skips the /n char */
  if (*p == '\n')
    p++;

  c->http_header->headers_count = 0;

  while (*p && c->http_header->headers_count < MAX_HTTP_HEADERS) {

    // Se la riga inizia con \r o \n, è la riga vuota che segna la fine.
    if (*p == '\r' || *p == '\n') {
      break;
    }

    http_header_item_t *curr =
        &c->http_header->headers[c->http_header->headers_count];

    // Imposto la chiave all'indirizzo di p
    curr->key = p;

    // Cerco i doppi punti
    char *colon = strchr(p, ':');
    if (colon == NULL) {
      log_error("Header malformato, mancano i doppi punti.");
      return -1;
    }

    // Al posto dei due punti metto il carattere di terminazione
    *colon = '\0';
    p = colon + 1;

    // Salto gli spazi vuoti
    while (*p == ' ')
      p++;

    // Assegno il valore
    curr->value = p;

    // Cerco CRLF
    char *end_line = strpbrk(p, "\r\n");
    if (end_line == NULL) {
      log_error("Header malformato, manca il CRLF.");
      return -1;
    }

    // Tronco la riga
    *end_line = '\0';
    p = end_line + 1;

    // Aumento di 1 perché dopo \r abbiamo il \n e se inizia con \n smetterebbe
    // il parse
    if (*p == '\n')
      p++;

    // Aumento il counter dell'array
    c->http_header->headers_count++;
  }

  return 0;
}

static sds http_build_reqeust_line(http_status *http_status, ssize_t *len) {

  sds reqeust_line = sdscatprintf(
      sdsempty(), "%s %d %s\r\nContent-Type: text/html\r\nContent-Length: %ld",
      HTTP_V, http_status->code, http_status->reason_phrase, *len);
  log_warn(reqeust_line);

  return reqeust_line;
}

int http_build_header(client *c) {

  FILE *file = file_open(c->target);
  ssize_t len = file_len(file);

  char *body = (char *)malloc(sizeof(char) * len + 1);
  if (body == NULL) {
    log_error("Could not allocate memory on the heap!");
    return -1;
  }

  if (file_read(file, body, len) != len) {
    log_error("Could not read target!");
    return -1;
  }

  fclose(file);

  http_status http_status = {0};
  http_status.code = 200;
  http_status.reason_phrase = "OK";

  sds request_line = http_build_reqeust_line(&http_status, &len);
  sds header = sdscatprintf(sdsempty(), "%s\r\n\r\n%s", request_line, body);
  c->resp =
      sdscatprintf(sdsempty(), "%s\r\n\r\n%s", request_line, body);

  free(body);
  sdsfree(request_line);

  if (!header) {
    log_error("Could not construct HTTP Header: %s", strerror(errno));
    sdsfree(header);
    return -1;
  }

  // log_warn("Header: %s", header);
  log_warn("Header: %s", c->resp);

  sdsfree(header);

  return 0;
}

static int http_handle_get(client *c) {
  if (!strcmp(c->http_header->request_line.target, "/")) {
    strcpy(c->target, "index.html");

    if (http_build_header(c) == -1) {
      log_error("http response returned -1");
      return -1;
    }
  }
  return 0;
}

void http_handle_client(int sock) {
  client *c = (client*)malloc(sizeof(*c));
  if (c == NULL) pthread_exit((void *) -1);
  memset(c, 0xFF, sizeof(*c));

  c->sock = sock;
  c->req.cap = 4069;
  c->req.len = 0;
  c->req.buf = (char*)malloc(sizeof(char) * c->req.cap);

  while (1) {
    ssize_t byte_read = recv(c->sock, c->req.buf, c->req.cap, 0);
  }


  // client c = {0};
  //
  // request_t *req = (request_t*)malloc(sizeof(request_t) + 16);
  // req->size = 16;
  //
  // c.sock = client_sock;
  // c.header_buff_size = 64;
  // c.header_buff_len = 0;
  //
  // c.req = req;
  //
  // c.header_buff = (char *)malloc(sizeof(char) * c.header_buff_size);
  //
  // while (true) {
  //   // Bytes read from the socket
  //   ssize_t byte_read = recv(c.sock, c.req->buf, c.req->size, 0);
  //
  //   if ((int)byte_read == 0) {
  //     log_info("Tutti i dati dal socket sono stati letti!");
  //     break;
  //   }
  //   if ((int)byte_read == -1) {
  //     log_info("Errore leggendo i dati dal socket: %s", strerror(errno));
  //     break;
  //   }
  //
  //   // Controllo che in header buffer ci sia ancora spazio in caso rialloco
  //   if (c.header_buff_len + byte_read + 1 >= c.header_buff_size) {
  //     c.header_buff_size *= 2;
  //     c.header_buff = (char *)realloc(c.header_buff, c.header_buff_size);
  //     if (c.header_buff == NULL) {
  //       log_error("OOM durante la riallocazione della memoria!");
  //       break;
  //     }
  //     log_info("Header buffer riallocato di %d bytes.", c.header_buff_size);
  //   }
  //
  //   // Copio i dati dal buffer di lettura in header
  //   memcpy(c.header_buff + c.header_buff_len, c.req->buf, byte_read);
  //   c.header_buff_len += byte_read;
  //
  //   if (is_end_of_header(c.header_buff, c.header_buff_len)) {
  //     log_info("Header completo ricevuto!");
  //
  //     // Lo trasformo in stringa ed esco dal while
  //     c.header_buff[c.header_buff_len] = '\0';
  //     break;
  //   }
  // }
  //
  // c.http_header = (http_header_t *)malloc(sizeof(http_header_t));
  //
  // http_parse_header(&c);
  //
  // // log_info("HTTP Header Request Method: %s",
  // // c.http_header.request_line.method); log_info("HTTP Header Request Target:
  // // %s", c.http_header.request_line.target); log_info("HTTP Header Request HTTP
  // // Version: %s",
  // //          c.http_header.request_line.http_version);
  // // log_info("HTPP Headers count: %d", c.http_header.headers_count);
  // //
  // // for (int i = 0; i < c.http_header.headers_count; i++) {
  // //   log_info("HTTP %s:%s", c.http_header.headers[i].key,
  // //            c.http_header.headers[i].value);
  // // }
  //
  // c.http_response = sdsempty();
  //
  // if (strcmp(c.http_header->request_line.method, "GET") == 0) {
  //   int res = http_handle_get(&c);
  //
  //   if (res == -1)
  //     log_error("Error in handle get");
  //
  //   if (c.http_response &&
  //       send(client_sock, c.http_response, strlen(c.http_response), 0) == -1) {
  //     log_error("Errore nell'invio del messaggio!\n");
  //     pthread_exit((void *)-1);
  //   }
  //   log_info("Inviata una risposta al socket: %d\n", c.sock);
  //
  //   if (close(client_sock) == -1) {
  //     log_error("Errore nella chiusura del socket: %s\n", strerror(errno));
  //     pthread_exit((void *)-1);
  //   }
  //
  //   pthread_exit((void *)0);
  // }
}
