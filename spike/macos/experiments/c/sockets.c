// Can root cut another process's open connections without NetworkExtension?
// pid_shutdown_sockets(2) is a private syscall (436) used by iOS-style app
// suspension. This tries it.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#define SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL 0x2
int main(int argc, char **argv) {
  if (argc < 2) return 2;
  int pid = atoi(argv[1]);
  int r = syscall(436, pid, SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL);
  printf("uid=%d pid_shutdown_sockets(%d) -> %d errno=%d (%s)\n", getuid(), pid, r, r ? errno : 0, r ? strerror(errno) : "ok");
  return r != 0;
}
