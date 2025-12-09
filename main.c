#include "http.h"
#include <stdio.h>
#include <stdlib.h>

/*
 * Simple HTTP Server entry point.
 */
int main(int argc, char **argv) {
  int port = 6969;
  char *addr = INADDR_ANY;

  // Parse simple args (optional)
  if (argc > 1)
    port = atoi(argv[1]);

  // 1. Initialize Server
  http_server_t *server = httpCreateServer(addr, port);

  if (server == NULL) {
    fprintf(stderr, "Fatal: Could not start server on port %d\n", port);
    return 1;
  }

  // 2. Start Main Loop (Blocking)
  // This will handle accept() and thread spawning internally
  httpServe(server);

  // 3. Cleanup (Unreachable in this simple loop, but good practice)
  httpFreeServer(server);

  return 0;
}
