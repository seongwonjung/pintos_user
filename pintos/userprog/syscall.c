#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

// 🚧
#include <stddef.h>  // size_t

#include "lib/kernel/stdio.h"  // putbuf()

// 🅲
#include <string.h>  // memcpy, strlen, strnlen 등

#include "filesys/filesys.h"  // filesys_create(), remove()
#include "threads/mmu.h"      // pml4_get_page()
#include "threads/palloc.h"   // palloc_get_page(), palloc_free_page(), PGSIZE
#include "threads/synch.h"  // struct lock, lock_init(), lock_acquire(), lock_release()
#include "threads/vaddr.h"  // is_user_vaddr()

// 🅾, 🆂, 🆁, tell
#include "filesys/file.h"  // struct file, file_open(), file_close(), file_read()  (일반 파일에서 읽기 위해)

// 🆁
#include <stdint.h>  // uintptr_t

#include "devices/input.h"  // input_getc()      (stdin(0) 읽을 때 키보드에서 한 바이트씩 가져오려면)
#include "filesys/file.h"  // file_length(), file_tell()

// 🅵
#include "userprog/process.h"  // process_fork, process_wait, process_exit

// halt
#include "threads/init.h"

typedef int pid_t;
void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_exit(int status);
void sys_exit_with_error(void);
static bool sys_create(const char *file, unsigned initial_size);
static void sys_halt(void);
static int sys_open(const char *u_filename);
static int sys_filesize(int fd);
static void sys_close(int fd);
static pid_t sys_fork(const char *thread_name);
static int sys_wait(pid_t pid);
static int sys_exec(const char *cmd_line);
static void sys_seek(int fd, unsigned position);
static bool remove(const char *file);
static unsigned tell(int fd);
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
  for (int fd = 2; fd < FD_MAX; fd++) {
    if (t->fd_table[fd] == NULL) {
      t->fd_table[fd] = f;
      return fd;
    }
  }
  return -1;
}
// fd테이블 fd_close 해주기
void fd_close(struct thread *t, int fd) {
  struct file *f = t->fd_table[fd];
  t->fd_table[fd] = NULL;
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

void syscall_handler(struct intr_frame *f) {
  uint64_t n = f->R.rax;

  switch (n) {
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_EXIT:
      sys_exit(f->R.rdi);
      break;
    case SYS_FORK:
      thread_current()->fork_if = *f;
      pid_t child_pid = sys_fork(f->R.rdi);
      f->R.rax = child_pid;
      break;
    case SYS_EXEC:
      int state = sys_exec(f->R.rdi);
      f->R.rax = state;
      break;
    case SYS_WAIT:
      int exit_status = sys_wait((pid_t)f->R.rdi);
      f->R.rax = exit_status;
      break;
    case SYS_CREATE:
      bool create_succ = sys_create((const char *)f->R.rdi, (unsigned)f->R.rsi);
      f->R.rax = create_succ;
      break;
    case SYS_REMOVE:
      bool remove_succ = remove((const char *)f->R.rdi);
      f->R.rax = remove_succ;
      break;
    case SYS_OPEN:
      int fd = sys_open((const char *)f->R.rdi);
      f->R.rax = fd;
      break;
    case SYS_FILESIZE:
      int f_size = sys_filesize((int)f->R.rdi);
      f->R.rax = f_size;
      break;
    case SYS_READ:
      int read_size =
          sys_read((int)f->R.rdi, (void *)f->R.rsi, (unsigned)f->R.rdx);
      f->R.rax = read_size;
      break;
    case SYS_WRITE:
      int write_size =
          sys_write((int)f->R.rdi, (const void *)f->R.rsi, (unsigned)f->R.rdx);
      f->R.rax = write_size;
      break;
    case SYS_SEEK:
      sys_seek((int)f->R.rdi, (unsigned)f->R.rsi);
      break;
    case SYS_TELL: /* 미구현: 호출 시 -1로 종료 */
      unsigned pos = (unsigned)tell((int)f->R.rdi);
      f->R.rax = pos;
      break;
    case SYS_CLOSE:
      sys_close((int)f->R.rdi);
      break;

    default:
      /* 범위를 벗어난 콜 번호 */
      sys_exit_with_error();
      break;
  }
}

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

static void sys_exit(int status) {
  struct thread *curr = thread_current();
  curr->exit_status = status;
  printf("%s: exit(%d)\n", thread_name(), curr->exit_status);
  thread_exit();
}

static void sys_halt() { power_off(); }

static int sys_read(int fd, void *buffer, unsigned size) {
  // 유효 주소인지 확인
  if (!validate_user_addr(buffer)) {
    sys_exit_with_error();
  }
  // bad-fd 검사
  if (fd < 0 || fd >= FD_MAX) return -1;
  // fd == 1 -> stdout
  if (fd == 1) {
    return -1;
  }

  if (fd == 0) {  // fd == 0 -> stdin
    unsigned i = 0;
    for (; i < size; i++) {
      ((uint8_t *)buffer)[i] = input_getc();
    }
    return (int)i;
  } else {  // 다른 열린 파일일때
    struct file *file = thread_current()->fd_table[fd];
    if (!file) return -1;
    lock_acquire(&filesys_lock);
    size = file_read(file, buffer, size);
    lock_release(&filesys_lock);
  }
  return size;
}

static int sys_write(int fd, const void *buffer, unsigned size) {
  // 유효 주소인지 확인
  if (!validate_user_addr(buffer)) {
    sys_exit_with_error();
  }
  // bad-fd 검사
  if (fd < 0 || fd >= FD_MAX) return -1;
  // fd == 0 -> stdin
  if (fd == 0) return -1;
  if (size == 0) return 0;

  // fd == 1 -> stdout
  if (fd == 1) {
    putbuf((const char *)buffer, (size_t)size);
    return (int)size;
  } else {  // 다른 열린 파일일때
    struct file *file = thread_current()->fd_table[fd];
    if (!file) return -1;

    lock_acquire(&filesys_lock);
    size = file_write(file, buffer, size);
    lock_release(&filesys_lock);
  }
  return (int)size;
}

static bool sys_create(const char *file, unsigned initial_size) {
  // 유효 주소인지 확인
  if (!validate_user_addr(file)) {
    sys_exit_with_error();
    return -1;
  }

  // k_filename 으로 복사(유저 -> 커널)
  char *k_filename = copy_in_string(file);
  // 빈 문자열, NULL 체크
  if (copy_check(k_filename) == -1) {
    palloc_free_page(k_filename);
    return 0;  // create-empty 일 때 0 반환
  }
  lock_acquire(&filesys_lock);
  bool succ = filesys_create(k_filename, initial_size);
  lock_release(&filesys_lock);

  palloc_free_page(k_filename);
  return succ;
}

void sys_exit_with_error(void) { sys_exit((uint64_t)-1); }

static int sys_open(const char *u_filename) {
  // 유효 주소인지 확인
  if (!validate_user_addr(u_filename)) {
    sys_exit_with_error();
  }
  // 커널에 복사
  char *k_filename = palloc_get_page(PAL_ZERO);
  if (k_filename == NULL) return -1;
  k_filename = copy_in_string(u_filename);
  // 빈 문자열, NULL 체크
  if (copy_check(k_filename) == -1) {
    palloc_free_page(k_filename);
    return -1;
  }
  lock_acquire(&filesys_lock);
  struct file *file = filesys_open(k_filename);
  lock_release(&filesys_lock);
  palloc_free_page(k_filename);

  if (file == NULL) {
    return -1;
  }
  // FD 배정해주기
  int fd = fd_alloc(thread_current(), file);
  if (fd < 2 || fd >= FD_MAX) {
    lock_acquire(&filesys_lock);
    file_close(file);
    lock_release(&filesys_lock);
    return -1;
  }
  return fd;
}

static int sys_filesize(int fd) {
  if (thread_current()->fd_table[fd] == NULL || (fd < 0 || fd >= FD_MAX)) {
    return -1;
  }
  lock_acquire(&filesys_lock);
  off_t file_size = file_length(thread_current()->fd_table[fd]);
  lock_release(&filesys_lock);

  return (int)file_size;
}

static void sys_close(int fd) {
  struct thread *cur = thread_current();
  if ((fd < 2) || (fd >= FD_MAX) || cur->fd_table[fd] == NULL) {
    return;
  }
  fd_close(cur, fd);
}

static pid_t sys_fork(const char *thread_name) {
  pid_t child_pid = -1;
  // 유효성 검사
  if (!validate_user_addr(thread_name)) {
    sys_exit_with_error();
    return -1;
  }
  // 버퍼에 복사
  char *k_thread_name = palloc_get_page(PAL_ZERO);
  k_thread_name = copy_in_string(thread_name);
  // 빈 문자열, NULL 체크
  if (copy_check(k_thread_name) == -1) {
    palloc_free_page(k_thread_name);
    return -1;
  }

  // 부모 레지스터 상태 복사
  struct thread *parent = thread_current();
  struct intr_frame *parent_if = &parent->fork_if;

  child_pid = process_fork(k_thread_name, parent_if);

  palloc_free_page(k_thread_name);
  if (child_pid == TID_ERROR) {
    return -1;
  } else {
    return child_pid;
  }
  return child_pid;
}

static int sys_wait(pid_t pid) {
  int exit_status = process_wait(pid);
  return exit_status;
}

static int sys_exec(const char *cmd_line) {
  if (!validate_user_addr(cmd_line)) {
    sys_exit_with_error();
    return -1;
  }

  char *k_cmd_line = copy_in_string(cmd_line);
  if (copy_check(k_cmd_line) == 0) {
    palloc_free_page(k_cmd_line);
    return -1;
  }

  int status = process_exec(k_cmd_line);
  if (status == -1) sys_exit_with_error();
  return status;
}

static void sys_seek(int fd, unsigned position) {
  if (fd < 2 || fd >= FD_MAX) sys_exit_with_error();
  struct thread *cur = thread_current();
  lock_acquire(&filesys_lock);
  file_seek(cur->fd_table[fd], position);
  lock_release(&filesys_lock);
  return;
}

static bool remove(const char *file) {
  if (!validate_user_addr(file)) sys_exit_with_error();
  return filesys_remove(file);
}

static unsigned tell(int fd) {
  if (fd < 0 || fd >= FD_MAX) sys_exit_with_error();
  return file_tell(thread_current()->fd_table[fd]);
}