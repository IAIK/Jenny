#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <ucontext.h>
#include <time.h>

#include "test8.h"
#include "pk.h"
#include "sf.h"
#include "pk_internal.h"

const size_t NTHREADS = 2;
const size_t NUM_SIGNALS_PER_THREAD = 20;

volatile int sigalarm = 0;
volatile int sigusr = 0;

pthread_mutex_t test8_mutex;

void sigalarm_handler(int sig, siginfo_t* siginfo, void* frame) {
  printf("sigalarm_handler invoked\n");
  printf("siginfo came from pid %d\n", siginfo->si_pid);
  sigalarm++;
}
//------------------------------------------------------------------------------

void sigusr_handler(int sig, siginfo_t* siginfo, void *frame) {
  // Hope that we do not have a race condition
  sigusr++;
}
//------------------------------------------------------------------------------

#define ASSERT_SIGMASKUNCHANGED(currset, origset) do { \
    assert(0 == sigprocmask(0, NULL, &currset)); \
    assert(0 == memcmp(&currset, &origset, sizeof(sigset_t))); \
  } while(0)
//------------------------------------------------------------------------------

#define ASSERT_PKRUUNCHANGED(origpkru) do { \
    pkru_config_t currpkru = _read_pkru_reg(); \
    assert(currpkru == origpkru); \
  } while(0)
//------------------------------------------------------------------------------

// Test if kill-syscall that triggers a signal handler restores callee-
// saved registers appropriately.
// For METHOD=indirect, this bypasses syscall interception, and we can
// test whether the signal handler invocation destroys our registers.
//
// For other METHODs, the kill syscall will be filtered and impersonated
// by the monitor, similar to test8_kill_libcwrapper_calleeregisters
void test8_kill_direct_calleeregisters(long pid, long signo) {

    long mismatch = 0;
    long reg_wrong = 0;
    long reg_expected = 0;
    long reg_savedsp = 0;
    asm volatile (
        // save callee-saved registers via the clobber list
        // save rsp
        //"mov %%rsp, %%r10\n"

        // prime registers with magic word
        "mov $0x7AAADEAD, %%rbx\n"
        //"mov $0x7BBBDEAD, %%rsp\n"
        "mov $0x7CCCDEAD, %%rbp\n"
        "mov $0x7DDDDEAD, %%r12\n"
        "mov $0x7EEEDEAD, %%r13\n"
        "mov $0x7FFFDEAD, %%r14\n"
        "mov $0x7000DEAD, %%r15\n"

        // perform direct syscall
        // shift arguments accordingly
        // syscall(rax=sysno, rdi=pid, rsi=signo)
        "mov %%rdi, %%rax\n"
        "mov %%rsi, %%rdi\n"
        "mov %%rdx, %%rsi\n"
        "syscall\n"
        "test %%rax, %%rax\n"
        "jnz .Lcleanup1\n" // syscall error code is in %%rax

        // check if callee-saved registers changed during the syscall
        // if yes, _expected_rdx and _wrong_rcx contain the expected and wrong register value, respectively
        "mov $0x7AAADEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%rbx\n cmovne %%rbx, %[_wrong_rcx]\n jne .Lmismatch1\n"
        //"mov $0x7BBBDEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%rsp\n cmovne %%rsp, %[_wrong_rcx]\n jne .Lmismatch1\n"
        "mov $0x7CCCDEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%rbp\n cmovne %%rbp, %[_wrong_rcx]\n jne .Lmismatch1\n"
        "mov $0x7DDDDEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%r12\n cmovne %%r12, %[_wrong_rcx]\n jne .Lmismatch1\n"
        "mov $0x7EEEDEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%r13\n cmovne %%r13, %[_wrong_rcx]\n jne .Lmismatch1\n"
        "mov $0x7FFFDEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%r14\n cmovne %%r14, %[_wrong_rcx]\n jne .Lmismatch1\n"
        "mov $0x7000DEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%r15\n cmovne %%r15, %[_wrong_rcx]\n jne .Lmismatch1\n"
        "jmp .Lcleanup1\n"
".Lmismatch1:\n"
        "movq $1, %[_mismatch_rax]\n"
".Lcleanup1:\n"
        // restore rsp
        //"mov %%r10, %%rsp\n"
        // restore callee-saved registers via the clobber list

        // For register naming see https://gcc.gnu.org/onlinedocs/gcc/Machine-Constraints.html#Machine-Constraints
        : /* output */ [_mismatch_rax] "=a"(mismatch),
                       [_wrong_rcx]    "=c"(reg_wrong),
                       [_expected_rdx] "=d"(reg_expected) // aliases with signo. No problem since signo is used *before* the syscall
        : /*input*/ [_sys_nr_rdi]      "D"(SYS_kill),
                    [_sys_pid_rsi]     "S"(pid),
                    [_sys_pid_rdx]     "d"(signo)
        : /*clobber*/ "rbx", "rsp", "rbp", "r12", "r13", "r14", "r15"
    );

    switch (mismatch) {
        case 0: return;
        case 1:
        {
            ERROR("Signal: Callee-saved register not clobbered correctly");
            ERROR("Signal: Register=0x%lx, expected 0x%lx", reg_wrong, reg_expected);
            assert(false);
        }
        default:
        {
            ERROR("Signal: kill syscall failed with %ld", mismatch);
            perror("kill failed");
            assert(false);
        }
    }
}
//------------------------------------------------------------------------------

// Test if kill-syscall that triggers a signal handler restores callee-
// saved registers appropriately.
// The kill syscall will be filtered and impersonated by the monitor,
// thus the signal handler will interrupt the monitor code, and we can
// test whether deferring the signal destroys our registers.
void test8_kill_libcwrapper_calleeregisters(long pid, long signo) {

    long mismatch = 0;
    long reg_wrong = 0;
    long reg_expected = 0;
    asm volatile (
        // save callee-saved registers via the clobber list
        
        // prime registers with magic word
        "mov $0x7AAADEAD, %%rbx\n"
        // since we use the libc syscall wrapper, we preserve %rsp
        // "mov $0x7BBBDEAD, %%rsp\n"
        "mov $0x7CCCDEAD, %%rbp\n"
        "mov $0x7DDDDEAD, %%r12\n"
        "mov $0x7EEEDEAD, %%r13\n"
        "mov $0x7FFFDEAD, %%r14\n"
        "mov $0x7000DEAD, %%r15\n"

        // syscall registers are already in-order
        "call syscall\n"
        "test %%rax, %%rax\n"
        "jnz .Lcleanup2\n" // syscall error code is in %%rax

        // check if callee-saved registers changed during the syscall
        // if yes, _expected_rdx and _wrong_rcx contain the expected and wrong register value, respectively
        "mov $0x7AAADEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%rbx\n cmovne %%rbx, %[_wrong_rcx]\n jne .Lmismatch2\n"
        // since we use the libc syscall wrapper, we preserved %rsp
        // "mov $0x7BBBDEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%rsp\n cmovne %%rsp, %[_wrong_rcx]\n jne .Lmismatch2\n"
        "mov $0x7CCCDEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%rbp\n cmovne %%rbp, %[_wrong_rcx]\n jne .Lmismatch2\n"
        "mov $0x7DDDDEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%r12\n cmovne %%r12, %[_wrong_rcx]\n jne .Lmismatch2\n"
        "mov $0x7EEEDEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%r13\n cmovne %%r13, %[_wrong_rcx]\n jne .Lmismatch2\n"
        "mov $0x7FFFDEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%r14\n cmovne %%r14, %[_wrong_rcx]\n jne .Lmismatch2\n"
        "mov $0x7000DEAD, %[_expected_rdx]\n cmpq %[_expected_rdx], %%r15\n cmovne %%r15, %[_wrong_rcx]\n jne .Lmismatch2\n"
        "jmp .Lcleanup2\n"
".Lmismatch2:\n"
        "movq $1, %[_mismatch_rax]\n"
".Lcleanup2:\n"
        // restore callee-saved registers via the clobber list

        // For register naming see https://gcc.gnu.org/onlinedocs/gcc/Machine-Constraints.html#Machine-Constraints
        : /* output */ [_mismatch_rax] "=a"(mismatch),
                       [_wrong_rcx]    "=c"(reg_wrong),
                       [_expected_rdx] "=d"(reg_expected) // aliases with signo. No problem since signo is used *before* the syscall
        : /*input*/ [_sys_nr_rdi]      "D"(SYS_kill),
                    [_sys_pid_rsi]     "S"(pid),
                    [_sys_pid_rdx]     "d"(signo)
        : /*clobber*/ "rbx", "rsp", "rbp", "r12", "r13", "r14", "r15"
    );

    switch (mismatch) {
        case 0: return;
        case 1:
        {
            ERROR("Signal: Callee-saved register not clobbered correctly");
            ERROR("Signal: Register=0x%lx, expected 0x%lx", reg_wrong, reg_expected);
            assert(false);
        }
        default:
        {
            ERROR("Signal: kill syscall failed with %ld", mismatch);
            perror("kill failed");
            assert(false);
        }
    }
}
//------------------------------------------------------------------------------

void alarm_nsec(long nsec) {
  timer_t timer;
  if (timer_create(CLOCK_REALTIME, NULL, &timer)) {
    perror("timer_create failed");
    assert(false);
  }

  struct itimerspec its;
  memset(&its, 0, sizeof(struct itimerspec));
  its.it_value.tv_sec = 0;
  its.it_value.tv_nsec = nsec;

  if (timer_settime(timer, 0, &its, NULL)) {
    perror("timer_settime failed");
    assert(false);
  }
}
//------------------------------------------------------------------------------

void perform_test8(const char* caller) {
  sigset_t currset, origset;
  memset(&currset, 0, sizeof(sigset_t));
  memset(&origset, 0, sizeof(sigset_t));
  assert(0 == sigprocmask(0, NULL, &origset));
  pkru_config_t config = _read_pkru_reg();

  printf("%s: testing register-preserving1...\n", caller);
  printf("%s: sending SIGUSR1\n", caller);
  test8_kill_direct_calleeregisters(getpid(), SIGUSR1);
  while(!sigusr) {
    ;
  }
  sigusr = 0;

  ASSERT_PKRUUNCHANGED(config);

  printf("%s: testing register-preserving2...\n", caller);
  printf("%s: sending SIGUSR1\n", caller);
  test8_kill_libcwrapper_calleeregisters(getpid(), SIGUSR1);
  while(!sigusr) {
    ;
  }
  sigusr = 0;

  ASSERT_PKRUUNCHANGED(config);

  printf("%s: starting alarm...\n", caller);

  //alarm(1);
  alarm_nsec(100*1000*1000);

  printf("%s: Waiting for alarm to raise...\n", caller);
  while(!sigalarm) {
    ;
  }
  printf("%s: SIGALRM received\n", caller);
  sigalarm = 0;
  ASSERT_SIGMASKUNCHANGED(currset, origset);
  ASSERT_PKRUUNCHANGED(config);

  printf("%s: starting alarm...\n", caller);
  //alarm(1);
  alarm_nsec(100*1000*1000);

  printf("%s: Waiting for alarm to raise...\n", caller);
  while(!sigalarm) {
    ;
  }
  printf("%s: SIGALRM received\n", caller);
  sigalarm = 0;
  ASSERT_SIGMASKUNCHANGED(currset, origset);
  ASSERT_PKRUUNCHANGED(config);

  printf("%s: Sending synchronous SIGUSR1...\n", caller);
  kill(getpid(), SIGUSR1);
  while(!sigusr) {
    ;
  }
  printf("%s: SIGUSR1 received\n", caller);
  sigusr = 0;
  ASSERT_SIGMASKUNCHANGED(currset, origset);
  ASSERT_PKRUUNCHANGED(config);
}
//------------------------------------------------------------------------------

// ecall_test8 calls this function
void test8() {
  perform_test8("Child-Domain");
}
//------------------------------------------------------------------------------

void printsigmask() {
  sigset_t currset;
  memset(&currset, 0, sizeof(sigset_t));
  assert(0 == sigprocmask(0, NULL, &currset));
  uint64_t* currptr = (void*)&currset;
  printf("mask: 0x%lx\n", *currptr);
}
//------------------------------------------------------------------------------

void* test8_thread(void* arg) {
  printf("Thread spawned\n");
  printsigmask();
  for (size_t i = 0; i < NUM_SIGNALS_PER_THREAD; i++) {
    kill(getpid(), SIGUSR1);
    usleep(100000);
  }
  printf("Thread exiting now\n");
  return NULL;
}
//------------------------------------------------------------------------------

void test8_enter() {
  printf("-------------------------------------------\n");
  if (sf_data.sf_mechanism_current != SF_INDIRECT &&
      sf_data.sf_mechanism_current != SF_SYSMODULE &&
      sf_data.sf_mechanism_current != SF_PTRACE_DELEGATE) {
      WARNING("skipping test8");
      return;
  }
  int ret = pthread_mutex_init(&test8_mutex, NULL);
  assert(0 == ret);

  struct sigaction alarm_act;
  memset(&alarm_act, 0, sizeof(alarm_act));
  alarm_act.sa_sigaction = sigalarm_handler;
  alarm_act.sa_flags = SA_SIGINFO;
  if (0 != sigaction(SIGALRM, &alarm_act, NULL)) {
    perror("sigaction failed");
    assert(false);
  }

  struct sigaction usr_act;
  memset(&usr_act, 0, sizeof(usr_act));
  usr_act.sa_sigaction = sigusr_handler;
  usr_act.sa_flags = SA_SIGINFO;
  if (0 != sigaction(SIGUSR1, &usr_act, NULL)) {
    perror("sigaction failed");
    assert(false);
  }

  perform_test8("Same-Domain1");

  ecall_test8(); // Child-Domain

  perform_test8("Same-Domain2");

  sigusr = 0;

  printsigmask();
  pthread_t thread[NTHREADS];
  for (size_t i = 0; i < NTHREADS; i++) {
      assert(pk_pthread_create(&thread[i], NULL, test8_thread, NULL) == 0);
  }
  printf("Created %zu threads\n", NTHREADS);
  fflush(stdout);
  for (size_t i = 0; i < NTHREADS; i++) {
      assert(pthread_join(thread[i], NULL) == 0);
  }
  printf("Joined all threads\n");
  printf("Number signals: %d\n", sigusr);
  // We expect at least half the signals to arrive
  assert(sigusr <= NTHREADS * NUM_SIGNALS_PER_THREAD);
  assert(sigusr >= NTHREADS * NUM_SIGNALS_PER_THREAD / 2);
  sigusr = 0;

  // Ignore signals
  alarm_act.sa_handler = SIG_IGN;
  alarm_act.sa_flags = 0;
  if (0 != sigaction(SIGALRM, &alarm_act, NULL)) {
    perror("sigaction failed");
    assert(false);
  }
  usr_act.sa_handler = SIG_IGN;
  usr_act.sa_flags = 0;
  if (0 != sigaction(SIGUSR1, &usr_act, NULL)) {
    perror("sigaction failed");
    assert(false);
  }

  printf("Sending ignored signals...\n");
  kill(getpid(), SIGUSR1);
  //alarm(1);
  alarm_nsec(100*1000*1000);
  sleep(1);
  assert(sigusr == 0);
  assert(sigalarm == 0);
  sigusr = 0;
  printf("Sending ignored signals done\n");

  // Comment this in to test abort behavior
  // Test default action
  //~ usr_act.sa_handler = SIG_DFL;
  //~ usr_act.sa_flags = 0;
  //~ if (0 != sigaction(SIGUSR1, &usr_act, NULL)) {
    //~ perror("sigaction failed");
    //~ assert(false);
  //~ }
  //~ printf("Sending default signal...\n");
  //~ kill(getpid(), SIGUSR1);
  //~ printf("Should not reach here!\n");
  //~ assert(false);
}
//------------------------------------------------------------------------------
