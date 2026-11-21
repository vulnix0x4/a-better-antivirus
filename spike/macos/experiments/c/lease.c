// lease experiment: hold a lease on a file, see what an opener experiences.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <mach/mach_time.h>
static double now_ms(void){ struct timeval tv; gettimeofday(&tv,0); return tv.tv_sec*1000.0+tv.tv_usec/1000.0; }
int main(int argc,char**argv){
  const char*path=argv[1]; int type = argc>2? atoi(argv[2]) : F_WRLCK; int hold_ms = argc>3? atoi(argv[3]) : 500;
  int oflag = argc>4 ? atoi(argv[4]) : O_RDONLY;
  int fd=open(path,oflag);
  if(fd<0){perror("open");return 1;}
  int r=fcntl(fd,F_SETLEASE,F_SETLEASE_ARG(type,1));
  printf("F_SETLEASE type=%d -> %d errno=%d (%s)\n",type,r,r<0?errno:0,r<0?strerror(errno):"ok");
  if(r<0) return 1;
  printf("F_GETLEASE -> %d\n", fcntl(fd,F_GETLEASE));
  int kq=kqueue(); struct kevent ev; EV_SET(&ev,fd,EVFILT_VNODE,EV_ADD|EV_CLEAR,NOTE_LEASE_DOWNGRADE|NOTE_LEASE_RELEASE,0,0);
  if(kevent(kq,&ev,1,0,0,0)<0){perror("kevent add");return 1;}
  pid_t c=fork();
  if(c==0){
    usleep(200000);
    double t0=now_ms();
    int f=open(path,O_RDONLY);
    double t1=now_ms();
    char b[16]; ssize_t n = f>=0? read(f,b,sizeof b):-1;
    double t2=now_ms();
    printf("child: open returned fd=%d errno=%d after %.2f ms (t0=%.3f); read %zd bytes after %.2f more\n",f,f<0?errno:0,t1-t0,t0,n,t2-t1);
    _exit(0);
  }
  struct kevent out; struct timespec ts={10,0};
  int n=kevent(kq,0,0,&out,1,&ts);
  double te=now_ms();
  if(n<=0){printf("holder: no lease event in 10s\n");}
  else { printf("holder: lease event fflags=0x%x at %.3f\n",out.fflags,te);
    usleep(hold_ms*1000);
    r=fcntl(fd,F_SETLEASE,F_SETLEASE_ARG(F_UNLCK,1));
    printf("holder: released after holding %d ms -> %d errno=%d\n",hold_ms,r,r<0?errno:0);
  }
  int st; waitpid(c,&st,0);
  return 0;
}
