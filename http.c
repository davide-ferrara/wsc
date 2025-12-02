#include "http.h"
#include "log.h"

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

int consume_token(char **cursor, char delimeter, char **out_token) {
  char *p = *cursor;
  *out_token = p;

  while (*p && *p != delimeter && *p != '\r' && *p != '\n') {
    p++;
  }

  if (*p == delimeter) {
    *p = '\0';       // Taglio la stringa
    *cursor = p + 1; // Incremento il puntatore del chiamante
    return 0;
  }

  return -1;
}

int is_end_of_header(const char *buff, size_t len) {
  // Se il buffer é piú piccolo di 4 byte non ha senso controllare i
  // caratteri di escape in quanto ancora il client devi inviare almeno 4
  // caratteri per contenere la sequenza di escape!
  if (len < 4) {
    return -1;
  }

  // Calcolo il puntatore alla fine del buffer
  const char *end = buff + len;
  // Controllo a ritroso gli ultimi 4 byte:
  // end[-4] è il quartultimo
  // end[-3] è il terzultimo
  // end[-2] è il penultimo
  // end[-1] è l'ultimo
  return (end[-4] == '\r' && end[-3] == '\n' && end[-2] == '\r' &&
          end[-1] == '\n');
}

char *http_build_message(char *html_name) {
  long int content_length;
  char *html_content = NULL;
  char *http_message = NULL;

  FILE *stream = fopen(html_name, "r");
  if (stream == NULL) {
    log_error("Impossibile trovare %s", html_name);
    return NULL;
  }

  if (fseek(stream, 0, SEEK_END) == -1) {
    log_error("Impossibile posizionare il pointer alla fine del file: %s",
              strerror(errno));
    return NULL;
  }
  content_length = ftell(stream);
  // log_info("HTML Content-Lenght: %li", content_length);

  rewind(stream);
  html_content = (char *)malloc(sizeof(char) * content_length + 1);
  if (html_content == NULL) {
    log_error("Impossibile allocare memoria nell'heap");
    return NULL;
  }

  ulong byte_read = fread(html_content, sizeof(char), content_length, stream);
  fclose(stream);

  if (byte_read != content_length) {
    if (ferror(stream)) {
      log_error("Errore di I/O nella lettura di %s: %s", html_name,
                strerror(errno));
      free(html_content);
      return NULL;
    } else if (feof(stream)) {
      log_error("EOF raggiunto inaspettatamente per il file %s", html_name);
      free(html_content);
      return NULL;
    } else {
      log_error("Errore nella lettura del file: byte letti %zu, attesi %ld",
                byte_read, content_length);
      free(html_content);
      return NULL;
    }
  }
  const char *http_header_format =
      "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ";

  int res = asprintf(&http_message,
                     "%s %ld"
                     "\r\n\r\n%s",
                     http_header_format, content_length, html_content);
  if (res == -1) {
    log_error("Errore nella costruzione del messaggio HTTP: %s",
              strerror(errno));
    return NULL;
  }
  // log_info("HTTP Response: %s", http_message);
  return http_message;
}

int http_parse_header(char *header_buff, http_header_t *http_header) {
  // Cursore locale
  char *p = header_buff;

  // Parse Request Line
  if (consume_token(&p, ' ', &http_header->request_line.method) == -1) {
    log_error("Errore parsing Method (manca spazio)");
    return -1;
  }

  if (consume_token(&p, ' ', &http_header->request_line.target) == -1) {
    log_error("Errore parsing Target (manca spazio)");
    return -1;
  }

  if (consume_token(&p, '\r', &http_header->request_line.http_version) == -1) {
    log_error("Errore parsing Version (manca CRLF)");
    return -1;
  }

  // Salto la \n che sará presente dopo \r
  if (*p == '\n')
    p++;

  // Parse Headers
  http_header->headers_count = 0;

  while (*p && http_header->headers_count < MAX_HTTP_HEADERS) {

    // Se la riga inizia con \r o \n, è la riga vuota che segna la fine.
    if (*p == '\r' || *p == '\n') {
      break;
    }

    http_header_item_t *curr =
        &http_header->headers[http_header->headers_count];

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
    http_header->headers_count++;
  }

  return 0;
}

void http_handle_get() {
  log_info("Metodo GET ricevuto dal client");
  return;
}

void http_handle_post() {
  log_info("Metodo POST ricevuto dal client");
  return;
}

void http_handle_error() { return; }

void http_handle_client(int client_sock) {
  char *read_buff = NULL;
  char *header_buff = NULL;
  size_t read_buff_size = 16;
  size_t header_buff_size = 64;
  size_t header_buff_len = 0; // Numero di bytes scritti nel buffer

  read_buff = (char *)malloc(sizeof(char) * read_buff_size);
  header_buff = (char *)malloc(sizeof(char) * header_buff_size);

  while (true) {
    // Leggo n bytes dal socket
    long int read_bytes = recv(client_sock, read_buff, read_buff_size, 0);

    // Controllo lo stato della lettrua
    if (read_bytes == 0) {
      log_info("Tutti i dati dal socket sono stati letti!");
      break;
    }
    if (read_bytes == -1) {
      log_info("Errore leggendo i dati dal socket: %s", strerror(errno));
      break;
    }

    // Controllo che in header buffer ci sia ancora spazio in caso rialloco
    if (header_buff_len + read_bytes + 1 >= header_buff_size) {
      header_buff_size *= 2;
      header_buff = (char *)realloc(header_buff, header_buff_size);
      if (header_buff == NULL) {
        log_error("OOM durante la riallocazione della memoria!");
        break;
      }
      log_info("Header buffer riallocato di %d bytes.", header_buff_size);
    }

    // Copio i dati dal buffer di lettura in header
    memcpy(header_buff + header_buff_len, read_buff, read_bytes);
    header_buff_len += read_bytes;

    if (is_end_of_header(header_buff, header_buff_len)) {
      log_info("Header completo ricevuto!");

      // Lo trasformo in stringa ed esco dal while
      header_buff[header_buff_len] = '\0';
      break;
    }
  }

  // header_buff adesso contiene l'hader sotto forma di stringa
  free(read_buff);

  http_header_t http_header;

  // Parse dell'header
  http_parse_header(header_buff, &http_header);

  log_info("HTTP Header Request Method: %s", http_header.request_line.method);
  log_info("HTTP Header Request Target: %s", http_header.request_line.target);
  log_info("HTTP Header Request HTTP Version: %s",
           http_header.request_line.http_version);
  log_info("HTPP Headers count: %d", http_header.headers_count);

  for (int i = 0; i < http_header.headers_count; i++) {
    log_info("HTTP %s:%s", http_header.headers[i].key,
             http_header.headers[i].value);
  }

  if (strcmp(http_header.request_line.method, "GET") == 0) {
    http_handle_get();
  } else if (strcmp(http_header.request_line.method, "POST") == 0) {
    http_handle_post();
  } else
    log_error("Metodo non supportato!");

  char *html_name = "index.html";
  char *http_message = http_build_message(html_name);
  if (http_message == NULL) {
    log_error("HTTP Messagge é nullo!");
    // Da implementare meglio
    http_message = "HTTP/1.1 400 Bad Request\r\n"
                   "Content-Type : application / json\r\n"
                   "Content-Length : 0\r\n\r\n";
    // "\{ \"error\" : \"Bad request\", \"mersage\" : \"Request "
    // "body could not be read properly.\",}";
  }

  // Invio il messaggio al Socket
  if (send(client_sock, http_message, strlen(http_message), 0) == -1) {
    log_error("Errore nell'invio del messaggio!\n");
    pthread_exit((void *)-1);
  }
  log_info("Inviata una risposta al socket: %d\n", client_sock);

  // Chiudo il Socket
  if (close(client_sock) == -1) {
    log_error("Errore nella chiusura del socket: %s\n", strerror(errno));
    pthread_exit((void *)-1);
  }

  pthread_exit((void *)0);
}
