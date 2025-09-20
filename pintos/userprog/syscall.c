#include "userprog/syscall.h"

#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "intrinsic.h"
#include "lib/kernel/stdio.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static void sys_read(struct intr_frame *f);
static void sys_write(struct intr_frame *f);
static void sys_exit(struct intr_frame *f);
static void sys_exit_with_error(struct intr_frame *f);
static void sys_create(struct intr_frame *f);
static void sys_halt(struct intr_frame *f);
static void sys_open(struct intr_frame *f);
static void sys_filesize(struct intr_frame *f);
static void sys_close(struct intr_frame *f);
static void sys_fork(struct intr_frame *f);
static void sys_wait(struct intr_frame *f);
static void sys_exec(struct intr_frame *f);
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */
#define STRLEN_FAIL ((size_t)-1)
// 파일 시스템 락
struct lock filesys_lock;
// 유효 주소 검사
static bool validate_user_addr(const void *addr);

/* 커널 버퍼 생성을 위한 헬퍼 함수들 */
/*
유저 공간 문자열 u의 길이를 최대 limit까지 측정한다.
측정 중 (u+i)가 다른 페이지로 넘어갈 때마다 해당 페이지가
유저가 읽을 수 있는 유효 매핑인지 validate_user_addr로 검증한다.
limit을 넘기거나 검증 실패 시 STRLEN_FAIL을 반환한다.

왜 페이지 단위 검증인가?
- 문자열이 페이지 끝에서 시작해 다음 페이지로 넘어갈 수 있음.
- 다음 페이지가 미매핑/무권한이면 경계에서 안전하게 중단해야 함.
*/
static size_t strnlen_usr(const char *u, size_t limit) {
  size_t i = 0;
  void *last_pg = NULL;  // 마지막으로 검증한 페이지의 시작 주소
  while (i < limit) {
    void *pg = pg_round_down(u + i);  // (u+i)가 속한 페이지의 시작 주소
    if (pg != last_pg) {              // 새 페이지로 넘어간 시점에만 검증
      if (!validate_user_addr(u + i))
        return STRLEN_FAIL;  // 해당 주소(페이지)가 유효한지
      last_pg = pg;
    }
    if (*(uint8_t *)(u + i) == '\0') return i;  // 널 종료 발견
    i++;
  }
  return STRLEN_FAIL;  // limit 내에 널 없음 → 실패
}
/*
유저 버퍼 usrc에서 커널 버퍼 kdst로 n바이트를 복사한다.
바이트를 진행하다가 페이지 경계(pg_round_down)로 바뀌면 그때마다
새 페이지가 유효한지(validate_user_addr) 확인한다.
한 페이지에서 여러 바이트는 검증 1회로 처리(효율성).
*/
static bool copy_from_user(void *kdst, const void *usrc, size_t n) {
  size_t i = 0;
  void *last_pg = NULL;
  while (i < n) {
    void *pg =
        pg_round_down((const uint8_t *)usrc + i);  // 현재 바이트의 페이지 시작
    if (pg != last_pg) {  // 페이지가 바뀐 경우에만 검증
      if (!validate_user_addr((const uint8_t *)usrc + i))
        return false;  // 유저가 읽을 수 있는가?
      last_pg = pg;
    }
    ((uint8_t *)kdst)[i] = *((const uint8_t *)usrc + i);  // 실제 1바이트 복사
    i++;
  }
  return true;
}
/*
유저 문자열 u를 한 페이지(PGSIZE) 한도 내에서 커널에 새 페이지를 할당해
복사한다.
- 길이 측정은 strnlen_usr(u, PGSIZE)로 수행(널 포함 길이가 PGSIZE 이내여야 함)
- 문자열이 '현재 페이지의 남은 공간 + 다음 페이지 일부' 같은 형태로
  PGSIZE를 넘어가면 STRLEN_FAIL 처리된다(목적지 버퍼도 한 페이지이기 때문).
*/
static char *copy_in_string(const char *u) {
  const size_t LIMIT = PGSIZE;         // 목적지 버퍼(1페이지) 용량 한도
  size_t len = strnlen_usr(u, LIMIT);  // 페이지 경계 검증 포함 길이 측정
  if (len == STRLEN_FAIL) return NULL;
  char *k = palloc_get_page(PAL_ZERO);  // 커널 공간 1페이지 할당
  if (!k) {
    return NULL;
  }
  // 널 포함(len+1)만큼 복사(복사 중에도 페이지 경계 검증 수행)
  if (!copy_from_user(k, u, len + 1)) {
    palloc_free_page(k);
    return NULL;
  }
  return k;  // 호출자가 palloc_free_page로 해제
}
/* NULL체크, 빈문자열인지 체크
 빈문자열이거나 NULL 일 경우 0 return
 아니면 1 반환 */
static int copy_check(char *buf) {
  if (!buf || buf[0] == '\0') {
    if (buf) palloc_free_page(buf);
    return -1;
  }
  return 1;
}

/* FD를 위한 헬퍼 함수들 */
// fd테이블에서 할당 가능 fd_entry 찾아주기
int fd_alloc(struct thread *t, struct file *f) {
  for (t->next_fd; t->next_fd < FD_MAX; t->next_fd++) {
    if (t->fd_table[t->next_fd] == NULL) {
      t->fd_table[t->next_fd] = f;
      return t->next_fd++;
    }
  }
  return -1;
}
// fd테이블 fd_close 해주기
void fd_close(struct thread *t, int fd) {
  struct file *f = t->fd_table[fd];
  t->fd_table[fd] = NULL;
  t->next_fd = fd;
  lock_acquire(&filesys_lock);
  file_close(f);
  lock_release(&filesys_lock);
}

/* 사용자 주소 addr이 유효한지(NULL이 아니고, 사용자 영역에 있으며,
 * 매핑되었는지) 확인 */
static bool validate_user_addr(const void *addr) {
  if (addr == NULL) {
    return false;
  }
  if (!is_user_vaddr(addr)) {  // KERN_BASE보다 낮은 주소인지 확인
    return false;
  }
  // 현재 프로세스의 페이지 테이블에서 가상 주소에 매핑된 물리 주소가 있는지
  // 확인
  if (pml4_get_page(thread_current()->pml4, addr) == NULL) {
    return false;
  }
  return true;
}

typedef void (*syscall_handler_t)(
    struct intr_frame *f);  // 함수 포인터 형 재선언

static const syscall_handler_t syscall_tbl[] = {
    [SYS_HALT] = sys_halt,
    [SYS_EXIT] = sys_exit,
    [SYS_FORK] = sys_fork,
    [SYS_EXEC] = NULL,
    [SYS_WAIT] = sys_wait,
    [SYS_CREATE] = sys_create,
    [SYS_REMOVE] = NULL,
    [SYS_OPEN] = sys_open,
    [SYS_FILESIZE] = sys_filesize,
    [SYS_READ] = sys_read,
    [SYS_WRITE] = sys_write,
    [SYS_SEEK] = NULL,
    [SYS_TELL] = NULL,
    [SYS_CLOSE] = sys_close,
};

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG)
                                                               << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
  // filesys_lock init
  lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
  // TODO: Your implementation goes here.
  uint64_t n = f->R.rax;
  if ((n >= sizeof(syscall_tbl) / sizeof(syscall_tbl[0])) ||
      (syscall_tbl[n] == NULL)) {
    sys_exit_with_error(f);
    return;
  }
  syscall_tbl[n](f);
}

static void sys_exit(struct intr_frame *f) {
  int status = (int)f->R.rdi;
  thread_current()->exit_status = status;
  thread_exit();
}

static void sys_halt(struct intr_frame *f) { power_off(); }

static void sys_read(struct intr_frame *f) {
  int fd = (int)f->R.rdi;
  // bad-fd 검사
  if (fd < 0 || fd > FD_MAX) return;
  // fd == 1 -> stdout
  if (fd == 1) return;

  const void *buf = (const void *)f->R.rsi;
  unsigned size = (unsigned)f->R.rdx;
  // 유효 주소인지 확인
  if (!validate_user_addr(buf)) {
    sys_exit_with_error(f);
    return;
  }

  if (fd == 0) {  // fd == 0 -> stdin
    input_getc();
  } else {  // 다른 열린 파일일때
    struct file *file = thread_current()->fd_table[fd];
    if (!file) {
      f->R.rax = -1;
      return;
    }
    lock_acquire(&filesys_lock);
    size = file_read(file, buf, size);
    lock_release(&filesys_lock);
  }
  f->R.rax = size;
  return;
}

static void sys_write(struct intr_frame *f) {
  int fd = (int)f->R.rdi;
  // bad-fd 검사
  if (fd < 0 || fd > FD_MAX) return;
  // fd == 0 -> stdin
  if (fd == 0) return;

  const void *buf = (const void *)f->R.rsi;
  unsigned size = (unsigned)f->R.rdx;
  // 유효 주소인지 확인
  if (!validate_user_addr(buf)) {
    sys_exit_with_error(f);
    return;
  }

  // 커널영역의 버퍼로 담아서 하기
  char *k_buf = palloc_get_page(PAL_ZERO);
  k_buf = copy_in_string(buf);
  // NULL체크, 빈문자열인지 체크
  if (copy_check(k_buf) == -1) {
    f->R.rax = -1;
    return;
  }

  if (fd == 1) {  // fd == 1 -> stdout
    putbuf(k_buf, size);
  } else {  // 다른 열린 파일일때
    struct file *file = thread_current()->fd_table[fd];
    if (!file) {
      palloc_free_page(k_buf);
      f->R.rax = -1;
      return;
    }
    lock_acquire(&filesys_lock);
    size = file_write(file, k_buf, size);
    lock_release(&filesys_lock);
  }
  palloc_free_page(k_buf);
  f->R.rax = size;
  return;
}

static void sys_create(struct intr_frame *f) {
  const char *u_filename = (const char *)f->R.rdi;
  unsigned init_size = (unsigned)f->R.rsi;
  // 유효 주소인지 확인
  if (!validate_user_addr(u_filename)) {
    sys_exit_with_error(f);
    return;
  }

  // k_filename 으로 복사(유저 -> 커널)
  char *k_filename = copy_in_string(u_filename);
  // 빈 문자열, NULL 체크
  if (copy_check(k_filename) == -1) {
    f->R.rax = 0;  // create-empty 일 때 0 반환
    return;
  }
  lock_acquire(&filesys_lock);
  bool succ = filesys_create(k_filename, init_size);
  lock_release(&filesys_lock);

  palloc_free_page(k_filename);
  f->R.rax = succ ? 1 : 0;
}

static void sys_exit_with_error(struct intr_frame *f) {
  f->R.rdi = (uint64_t)-1;
  sys_exit(f);
}

static void sys_open(struct intr_frame *f) {
  const char *u_filename = f->R.rdi;
  // 유효 주소인지 확인
  if (!validate_user_addr(u_filename)) {
    sys_exit_with_error(f);
    return;
  }
  // 커널에 복사
  char *k_filename = copy_in_string(u_filename);
  // 빈 문자열, NULL 체크
  if (copy_check(k_filename) == -1) {
    f->R.rax = -1;
    return;
  }
  lock_acquire(&filesys_lock);
  struct file *file = filesys_open(k_filename);
  lock_release(&filesys_lock);
  palloc_free_page(k_filename);

  if (file == NULL) {
    f->R.rax = -1;
    return;
  }
  // FD 배정해주기
  int fd = fd_alloc(thread_current(), file);
  if (fd < 2 || fd >= FD_MAX) {
    file_close(file);
    f->R.rax = -1;
    return;
  }
  f->R.rax = fd;
}

static void sys_filesize(struct intr_frame *f) {
  int fd = (int)f->R.rdi;
  if (thread_current()->fd_table[fd] == NULL) {
    f->R.rax = -1;
    return;
  }
  lock_acquire(&filesys_lock);
  off_t file_size = file_length(thread_current()->fd_table[fd]);
  lock_release(&filesys_lock);

  f->R.rax = file_size;
  return;
}

static void sys_close(struct intr_frame *f) {
  int fd = (int)f->R.rdi;
  struct thread *cur = thread_current();

  if ((fd < 2) || (fd > FD_MAX) || cur->fd_table[fd] == NULL) {
    return;
  }

  fd_close(cur, fd);
}

static void sys_fork(struct intr_frame *f) {
  const char *thread_name = f->R.rdi;
  // 유효성 검사
  if (!validate_user_addr(thread_name)) {
    sys_exit_with_error(f);
    return;
  }
  // 커널 버퍼에 복사
  char *k_thread_name = palloc_get_page(PAL_ZERO);
  k_thread_name = copy_in_string(thread_name);
  // 빈 문자열, NULL 체크
  if (copy_check(k_thread_name) == -1) {
    f->R.rax = -1;
    return;
  }
  tid_t child_pid = process_fork(k_thread_name, f);
  if (child_pid == TID_ERROR) {
    f->R.rax = -1;
  } else {
    f->R.rax = child_pid;
  }
  palloc_free_page(k_thread_name);
  return;
}

static void sys_wait(struct intr_frame *f) {
  tid_t pid = f->R.rdi;  // 자식 프로세스 pid
  f->R.rax = process_wait(pid);
  return;
}

// static void sys_exec(struct intr_frame *f) {
//   const char *cmd_line = f->R.rdi;
//   if (!validate_user_addr(cmd_line)) {
//     sys_exit_with_error(f);
//   }
//   char *f_cmd_line = copy_in_string(cmd_line);
//   if (copy_check(f_cmd_line) == 0) {
//     f->R.rax = -1;
//     return;
//   }

//   /* 커맨드라인 복사용 임시 페이지 버퍼 */
//   char *cmd_tmp = palloc_get_page(PAL_ZERO);
//   if (cmd_tmp == NULL) {
//     f->R.rax = -1;
//     return;
//   }
//   strlcpy(cmd_tmp, f_cmd_line, PGSIZE);
//   char *saveptr = NULL;
//   char *file_name = strtok_r(cmd_tmp, "\t\r\n ", &saveptr);
//   struct file *file = file_open(file_name);
//   if (file == NULL) {
//     printf("%s: -1\n", file_name);
//     f->R.rax = -1;
//     return;
//   }

//   int status = process_exec((void *)f_cmd_line);
//   f->R.rax = status;
// }