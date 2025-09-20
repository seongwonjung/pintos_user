#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>

#include "threads/interrupt.h"

#ifdef VM
#include "vm/vm.h"
#endif

// 🚧 
#ifdef USERPROG
struct child;     // 전방선언만(process.h에 정의됨
struct file;      // 실행파일/FD 테이블 포인터용 전방선언
#endif


struct lock;   // waiting_lock 용

/* States in a thread's life cycle. */
enum thread_status {
  THREAD_RUNNING, /* Running thread. */
  THREAD_READY,   /* Not running but ready to run. */
  THREAD_BLOCKED, /* Waiting for an event to trigger. */
  THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */

// ⓞ FD 범위(표준: 0=stdin, 1=stdout는 예약, 실제 파일은 2부터)
#define FD_MIN 2            // 0,1은 표준입출력 예약
#define FD_MAX 64

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
  /* Owned by thread.c. */
  tid_t tid;                 /* Thread identifier. */
  enum thread_status status; /* Thread state. */
  char name[16];             /* Name (for debugging purposes). */
  int priority;              /* Priority. */
  int base_priority;         // 3️⃣ Donation 해제 시 복원할 원래
                             // 우선순위(-one)
  int64_t wakeup_tick;       // 1️⃣ 깨울 시각

  // 3️⃣ donate-multiple
  struct lock *waiting_lock;  // 지금 기다리는 락 (중첩 기부 전파용)
  struct list donations;      // 나에게 기부한 스레드들
  struct list_elem donation_elem;  // 내가 남 donations에 들어갈 때 쓰는 elem

  /* Shared between thread.c and synch.c. */
  struct list_elem elem; /* List element. */

  struct intr_frame fork_if;   // 🅵 부모 intr_frame 저장 ★

#ifdef USERPROG
  // 🚧  프로세스 관계
  struct thread *parent;     // 부모
  struct list children;      // 내 자식들의 struct child 노드들을 연결하는 리스트
  struct child *as_child;    // 부모가 만들어준 내 child 노드 가리킴
  int exit_status;           // 종료 코드

  // 🚧 실행 파일(rox-*) 
  struct file *running_file; // 실행 중인 ELF 파일 핸들(실행 중 write 금지/해제 위해 보관)

  // 🅾 스레드(=프로세스)별 FD 테이블
  struct file *fd_table[FD_MAX];   // FD번호 → 파일객체 매핑
  int fd_next;                     // 다음 탐색 시작 위치   

  /* 주소 공간 */
  uint64_t *pml4; /* Page map level 4 */
#ifdef VM
  /* Table for whole virtual memory owned by thread. */
  struct supplemental_page_table spt;
#endif
#endif


  /* Owned by thread.c. */
  struct intr_frame tf; /* Information for switching */
  unsigned magic;       /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;
void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void do_iret(struct intr_frame *tf);

// 3️⃣ Donation helpers (multiple & nest)
void thread_refresh_priority(struct thread *t);
void thread_remove_donations_with_lock(
    struct lock *lock);                          // 락 해제 시 기부 회수
void thread_donate_chain(struct thread *donor);  // [NEST] 최대 8단계 전파
void thread_yield_if_lower(void);  // 최고 우선순위가 아니면 양보
struct list *get_ready_list(void);
#endif /* threads/thread.h */