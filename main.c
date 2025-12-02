#include "log.h"
#include "wsc.h"

int main(int argc, char *argv[]) {
  int wsc = wsc_run("0.0.0.0", 6969);

  if (wsc == -1) {
    log_error("Impossibile avviare il server!");
    return -1;
  }

  return 0;
}
