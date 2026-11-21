// Which ways of suspending a process exist, and who can undo them?
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <libproc.h>
int pid_suspend(int pid); int pid_resume(int pid);
static char pstat(pid_t p){ struct proc_bsdinfo bi; if(proc_pidinfo(p,PROC_PIDTBSDINFO,0,&bi,sizeof bi)<=0) return '?'; return bi.pbi_status==4?'T': (bi.pbi_status==2?'R':'0'+bi.pbi_status); }
static int tsusp(pid_t p){ struct proc_taskinfo ti; if(proc_pidinfo(p,PROC_PIDTASKINFO,0,&ti,sizeof ti)<=0) return -1; return ti.pti_numrunning; }
int main(int argc,char**argv){
  if(argc<3){fprintf(stderr,"usage: susp <op> <pid>\n");return 2;}
  pid_t p=atoi(argv[2]); int r=-9; errno=0;
  if(!strcmp(argv[1],"stop")) r=kill(p,SIGSTOP);
  else if(!strcmp(argv[1],"cont")) r=kill(p,SIGCONT);
  else if(!strcmp(argv[1],"pid_suspend")) r=pid_suspend(p);
  else if(!strcmp(argv[1],"pid_resume")) r=pid_resume(p);
  else if(!strcmp(argv[1],"task_suspend")||!strcmp(argv[1],"task_resume")){
    mach_port_t t; kern_return_t kr=task_for_pid(mach_task_self(),p,&t);
    if(kr){printf("uid=%d task_for_pid(%d) failed: %d (%s)\n",getuid(),p,kr,mach_error_string(kr));return 1;}
    kr = !strcmp(argv[1],"task_suspend")? task_suspend(t):task_resume(t);
    printf("uid=%d %s(%d) -> %d (%s)\n",getuid(),argv[1],p,kr,mach_error_string(kr)); return kr!=0;
  }
  else if(!strcmp(argv[1],"state")){ printf("pid %d bsd-status=%c running-threads=%d\n",p,pstat(p),tsusp(p)); return 0; }
  printf("uid=%d %s(%d) -> %d errno=%d (%s)\n",getuid(),argv[1],p,r,errno,strerror(errno));
  return r!=0;
}
