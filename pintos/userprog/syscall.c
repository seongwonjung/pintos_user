#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "lib/kernel/stdio.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static void sys_write(struct intr_frame *f);
static void sys_exit(struct intr_frame *f);
static void sys_exit_with_error(struct intr_frame *f);
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
    NULL,      /* SYS_HALT */
    sys_exit,  /* SYS_EXIT */
    NULL,      /* SYS_FORK */
    NULL,      /* SYS_EXEC */
    NULL,      /* SYS_WAIT */
    NULL,      /* SYS_CREATE */
    NULL,      /* SYS_REMOVE */
    NULL,      /* SYS_OPEN */
    NULL,      /* SYS_FILESIZE */
    NULL,      /* SYS_READ */
    sys_write, /* SYS_WRITE */
    NULL,      /* SYS_SEEK */
    NULL,      /* SYS_TELL */
    NULL,      /* SYS_CLOSE */
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

static void sys_write(struct intr_frame *f) {
  int fd = (int)f->R.rdi;
  const void *buf = (const void *)f->R.rsi;
  unsigned size = (unsigned)f->R.rdx;
  if (!validate_user_addr(buf)) {
    sys_exit_with_error(f);
    return;
  }
  if (fd == 1) {
    putbuf(buf, size);
    f->R.rax = size;
  } else {
    f->R.rax = -1;
  }
  return;
}

static void sys_exit_with_error(struct intr_frame *f) {
  f->R.rdi = (uint64_t)-1;
  sys_exit(f);
}