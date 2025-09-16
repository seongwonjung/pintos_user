#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

// 🚧 
#include <stddef.h>            // 🔹 size_t
#include "userprog/process.h"   // process_set_exit()

/* 🚧  헤더 없이 직접 선언 (콘솔 드라이버에 구현돼 있음) */
void putbuf (const char *buffer, size_t n);


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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


void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

// 🚧 
/* ---- 최소 시스템콜 구현 ---- */
static void sys_exit (int status) {
   /* 🔸 테스트가 기대하는 종료 메시지 출력 */
  printf("%s: exit(%d)\n", thread_name(), status);
  
  process_set_exit(status);
  thread_exit();
  __builtin_unreachable();
}

static int sys_write (int fd, const void *buf, unsigned size) {
  if (fd == 1) {                /* stdout */
    if (buf && size) putbuf((const char *)buf, (size_t)size);
    return (int)size;
  }
  return -1;
}

void syscall_handler (struct intr_frame *f) {
  uint64_t num = f->R.rax;
  switch (num) {
    case SYS_EXIT:
      sys_exit((int)f->R.rdi);         // rdi: status
      break;

    case SYS_WRITE:                    // rdi=fd, rsi=buf, rdx=size
      f->R.rax = (uint64_t)sys_write((int)f->R.rdi,
                                     (const void *)f->R.rsi,
                                     (unsigned)f->R.rdx);
      break;

    default:
      sys_exit(-1);
  }
}


// 🚧 

/* The main system call interface */
// TODO: Your implementation goes here.
// typedef void(*syscall_handler_t)(
//   struct intr_frame *f);                  // 함수 포인트형 재선언
// )
// typedef const syscall_handler_t syscall_tbl[] = {
//   NULL,
//   sys_exit,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   sys_write,
//   NULL,
//   NULL,
//   NULL,
// };

// void syscall_handler (struct intr_frame *f UNUSED) {	
	
// 	printf ("system call!\n");
// 	thread_exit ();
// }
