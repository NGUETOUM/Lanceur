#define _POSIX_SOURCE
#define _XOPEN_SOURCE_EXTENDED 1
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <thread>
#include <functional>
#include <iostream>
#include <vector>
#include <thread>
#include <strings.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <fstream>
#include <bits/stdc++.h>
#include <sstream>
#include "shared/prio_table.h"
#include "experiments/prio_table_helper.h"
#include "shared/ghost.h"




#define SCHED_GHOST 18

/*#define PROC_DIRECTORY "/proc/"
#define CASE_SENSITIVE    1
#define CASE_INSENSITIVE  0
#define EXACT_MATCH       1
#define INEXACT_MATCH     0
#define INTERVAL 20*/

#define SCHED_FLAG_RESET_ON_FORK 0x01

namespace fs = std::filesystem;
std::string threads_table[5];
static const char *enclave_path = "/sys/fs/ghost/enclave_1/ctl";
static char *progname;
pid_t pid;
int policy, enclave_fd = -1;
int word_count_pid;
int sh_fd = -1;


// For various glibc reasons, this isn't available in glibc/grte.  Including
// uapi/sched.h or sched/types.h will run into conflicts on sched_param.

typedef struct sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;  // overloaded for is/is not an agent
  uint64_t sched_runtime;   // overloaded for enclave ctl fd
  uint64_t sched_deadline;
  uint64_t sched_period;
}sched_attr_aliase;

int counter = 0;
int numThreads = 0;
static void usage(int rc) {
  fprintf(stderr, "Usage: %s <policy>\n", progname);
  fprintf(stderr, "To push tasks into ghOSt:\n");
  fprintf(stderr, "    $ cat /dev/cgroup/cpu/mine/tasks | %s 18\n", progname);
  fprintf(stderr, "To push tasks into CFS\n");
  fprintf(stderr, "    $ cat /dev/cgroup/cpu/your/tasks | %s 0\n", progname);
  exit(rc);
}


namespace {
// We do not need a different class of service (e.g., different expected
// runtimes, different QoS (Quality-of-Service) classes, etc.) across workers in
// our experiments. Furthermore, all workers are ghOSt one-shots. Thus, put all
// worker sched items in the same work class.
static constexpr uint32_t kWorkClassIdentifier = 0;
}  // namespace

int sched_enter_ghost(pid_t pid, int enclave_fd) {

  //printf("\n Thread number %d with pid %d \n", counter++, pid);
  // Enter ghOSt sched class.
  struct sched_attr attr = {
      .size = sizeof(sched_attr_aliase),
      .sched_policy = SCHED_GHOST,
      .sched_flags = SCHED_ITEM_RUNNABLE,
      .sched_priority = GHOST_SCHED_TASK_PRIO,  // GHOST_SCHED_TASK_PRIO
      .sched_runtime = enclave_fd,
  };

  return syscall(__NR_sched_setattr, pid, &attr, /*flags=*/0);
}

int sched_enter_other(pid_t pid, int policy) {
  struct sched_param param = { 0 };
  return sched_setscheduler(pid, policy, &param);
}

void spawn_threads(pid_t pid, int threads_numbers, int num_app){

  ghost_test::PrioTableHelper prioTableHelper_(threads_numbers + 1, threads_numbers + 1);

  uint32_t num_items = 0;
  uint64_t gtid_app = (uint64_t) pid;
  int last_thread = -1;
  int thread = -1;
  int thread_id[threads_numbers];

  std::string path = "/proc/" + std::to_string(pid) + "/task";
  for (auto& f : fs::directory_iterator(path)) {
    std::string p = fs::path(f);
    std::stringstream check(p);
    std::string intermediate;
    int j = 0;
    while(getline(check, intermediate, '/')){
      if(j == 4){
        thread = atoi(intermediate.c_str());
       if(pid != (pid_t)thread){
         prioTableHelper_.table_.Attach((pid_t)thread);
         printf("\n thread : %d \n", (pid_t)thread);
         thread_id[num_items] = thread;

       printf("sched_getscheduler(pid) = %d\n", sched_getscheduler((pid_t)thread));
       if (sched_getscheduler((pid_t)thread) == policy){
         printf("sched_getscheduler(pid) is equal to policy\n");
         //continue;
        }else{
          printf("sched_getscheduler(pid) is not equal to policy\n");
        }

       int ret;
       if (policy == SCHED_GHOST){
         fprintf(stderr, "sched is still enter on ghost\n");
         ret = sched_enter_ghost((pid_t)thread, enclave_fd);
        }else{
         ret = sched_enter_other((pid_t)thread, policy);
         fprintf(stderr, "sched is still enter on other with ret = %d\n", ret);
         }

       // Trust but verify.
       if (!ret) {
         printf("\n Migration of Thread number %d with pid %d \n", counter++, (pid_t)thread);
         int actual = sched_getscheduler((pid_t)thread);
         if (actual != policy) {
           fprintf(stderr, "scheduling policy of %d: want %d, got %d: %s\n",
                   (pid_t)thread, policy, actual, strerror(errno));
           //thread_id[num_items] = actual;
         }
       } else {
         fprintf(stderr, "setscheduler(%d) failed: %s\n", pid, strerror(errno));
         exit(1);
       }

        num_items++;
       /***************************END***************************/
     }
     }
      j++;
    }
  }

for(int k = 0; k <= threads_numbers; k++){
  ghost::sched_item si;
  prioTableHelper_.GetSchedItem(k, si);
  si.sid = k;
  si.wcid = kWorkClassIdentifier;
  ghost::Gtid gtid((uint64_t)thread_id[k]);
  si.gpid = gtid.id();
  si.flags |= SCHED_ITEM_RUNNABLE;
  prioTableHelper_.SetSchedItem(k, si);
  prioTableHelper_.table_.MarkUpdatedIndex(k, /* num_retries = */ 3);

}

}

int main(int argc, char *argv[])
{

  pid_t threads_pid[6] = {0};
  int word_count_pid = -1;
  progname = basename(argv[0]);
  int app_num = 1;

    if (argc != 3)
      usage(1);

  policy = atoi(argv[1]);
  pid_t out_pid = (pid_t)atoi(argv[2]);

  if (policy == SCHED_GHOST) {
    enclave_fd = open(enclave_path, O_RDWR);
    if (enclave_fd < 0) {
      fprintf(stderr, "open(%s): %s\n", enclave_path, strerror(errno));
      exit(1);
    }
  }

  if(out_pid <= 0){
    exit(0);
  }
  int threads_numbers = 0;

  //Define the numbers of threads of multithread app
  std::string path_location = "/proc/" + std::to_string(out_pid) + "/task";
  for (auto& f : fs::directory_iterator(path_location)) {
      threads_numbers++;
  }

  app_num++;

  FILE* fp;
  fp = fopen("/tmp/ghost_fd.txt","w");

  std::string line1 = std::to_string(getpid())+ " "+std::to_string(1)+"\n";
  std::string line2 = std::to_string(out_pid)+ " "+std::to_string(app_num)+"\n";

  if (fp != NULL)
    {
        fputs(line1.c_str(), fp);
        fputs(line2.c_str(), fp);
    }

  fclose(fp);
  //removing parent pid since it live on CFS Scheduler during the scheduling process
  threads_numbers = threads_numbers - 1;
  spawn_threads(out_pid, threads_numbers, app_num);

  exit(0);
}
