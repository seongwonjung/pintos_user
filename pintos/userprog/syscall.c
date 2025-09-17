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
#include <stddef.h>                 // size_t
#include "lib/kernel/stdio.h"       // putbuf()


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

// “프로세스가 나 끝낼게요!”라고 말할 때 해야 할 일
static void sys_exit (int status) {
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", thread_name(), status);   /* 테스트가 기대하는 종료 메시지 출력 */
  
  cur->exit_status = status;                       // 종료 코드 "현재 스레드 구조체"에 저장
  thread_exit();                                   // 커널 스레드 종료
  // __builtin_unreachable();                         // 컴파일러 힌트 코드
}

// “쓰기(sys_write) 요청 들어오면 어디로 내보낼까?”
static int sys_write (int fd, const void *buf, unsigned size) {
  if (fd == 1) {                /* stdout */
    if (buf && size) putbuf((const char *)buf, (size_t)size);
    return (int)size;
  }
  return -1;
}

// 유저 프로그램이 syscall을 부르면, 무슨 번호인지 보고 맞는 함수로 보내기
void syscall_handler (struct intr_frame *f) {
  uint64_t num = f->R.rax;                    // 시스템콜 번호(RAX 확인)
  switch (num) {
    case SYS_EXIT:                            // exit(status) => RDI만 사용
      sys_exit((int)f->R.rdi);                // 첫 번째 인자(RDI)를 int로 변환해서 sys_exit에 넘김
      break;

    case SYS_WRITE:                    // rdi=fd, rsi=buf(유저 주소), rdx=size
      f->R.rax = (uint64_t)sys_write((int)f->R.rdi, (const void *)f->R.rsi, (unsigned)f->R.rdx);
      break;

    default:
      sys_exit(-1);      // 모르는 시스템콜 번호면 "프로세스 종료(-1)"로 처리
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
