#include <stdio.h>
#include <unistd.h>
#include <time.h>
int main(int c,char**v){ FILE*f=fopen(v[1],"w"); for(long i=0;;i++){ struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts); rewind(f); fprintf(f,"%ld %ld.%09ld\n",i,ts.tv_sec,ts.tv_nsec); fflush(f); usleep(2000);} }
