#include "wsc.h"
#include "http.h"
#include "log.h"

int wsc_create_tcp_server(char *addr, int port) {
  int s, opt = 1, backlog = 511;
  struct sockaddr_in sa; // socket address

  // Creazione del socket
  if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    log_error("Impossibile creare il server socket: %s\n", strerror(errno));
    return -1;
  }

  // SO_REUSEADDR per riutilizzare l'indirizzo immediatamente e non aspettare
  // 60s
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
    log_error("Setsockopt fallito: %s", strerror(errno));
    close(s);
    return -1;
  }

  // Inizializzazione pulita
  sa = (struct sockaddr_in){0};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port); // int to binary

  // Gestione IP address
  if (addr == NULL) {
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
  } else {
    if (inet_pton(AF_INET, addr, &sa.sin_addr) <= 0) {
      log_error("Invalid bind address: %s", addr);
      close(s);
      return -1;
    }
  }

  // Bind & Ascolto
  if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
    log_error("Errore nel bind: %s\n", strerror(errno));
    close(s);
    return -1;
  };

  int listening = listen(s, backlog);
  if (listening == -1) {
    log_error("Impossibile ascoltare sulla porta %d: %s\n", port,
              strerror(errno));
    close(s);
    return -1;
  }
  return s;
}

static void *client_thread_handler(void *args) {
  int client_sock = *(int *)args;
  free(args);

  httpHandleClient(client_sock);

  return NULL;
}

int wsc_run(char *addr, int16_t port) {
  FILE *log_fp = fopen("log.txt", "w+");

  // Setup del logging
  log_add_fp(log_fp, 0);

  // Creo il server TCP
  int server_sock = wsc_create_tcp_server(addr, port);
  if (server_sock == -1) {
    return -1;
  }

  log_info("Server HTTP in ascolto su %s:%d", addr ? addr : "unkown", port);

  while (true) {
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    int client_sock =
        accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len);

    if (client_sock == -1) {
      // Se l'errore è "Interrupted system call" riprovo
      if (errno == EINTR)
        continue;

      // Altrimenti loggo l'errore ma NON esco dal loop
      log_error("Impossibile accettare il client: %s", strerror(errno));
      continue;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, (void *)&client_addr.sin_addr, client_ip,
              INET_ADDRSTRLEN);

    log_info("%s si é connesso!", client_ip);

    // Delego la risposta a un thread
    pthread_t thread;

    int *args = malloc(sizeof(int));
    if (args == NULL) {
      log_error("OOM: Impossibile allocare memoria per il thread");
      close(client_sock);
      continue;
    }

    *args = client_sock;

    if (pthread_create(&thread, NULL, client_thread_handler, (void *)args) !=
        0) {
      log_error("Thread creation failed");
      free(args);
      close(client_sock);
      continue;
    }

    pthread_detach(thread);
  }

  close(server_sock);
  return 0;
}
