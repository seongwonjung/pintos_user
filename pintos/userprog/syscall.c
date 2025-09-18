#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h" 
// 추가할 헤더들:
#include "threads/palloc.h"    // palloc_get_page용
#include "threads/vaddr.h"     // is_user_vaddr용
#include "userprog/process.h"  // pml4_get_page용
#include <string.h>            // memcpy용

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static void sys_exit(int status);
static void validate_user_buffer(const void *uaddr, size_t size);
static int sys_write(int fd, const void *user_buf, unsigned size);

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

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch ((int)f->R.rax) {              // 시스템콜 번호
		case SYS_EXIT:
		sys_exit((int)f->R.rdi);
		// 관례상 return 안 함(종료). 방어적으로 break 없어도 됨.
		break;

		case SYS_WRITE:
		f->R.rax = sys_write((int)f->R.rdi, (const void*)f->R.rsi, (unsigned)f->R.rdx);
		break;

		default:
		sys_exit(-1);                      // 미지원 → 종료
  }
}


// threads/thread.h 등에 현재 스레드의 종료코드 저장용 필드가 필요할 수 있음
// int exit_status;  // thread 구조체에 추가 (process_wait와도 연계)
// userprog/syscall.c
static void sys_exit(int status) {
  struct thread *t = thread_current();
  t->exit_status = status;

  thread_exit();   // 돌아오지 않음
}

static void validate_user_buffer(const void *uaddr, size_t size) {
  // 가장 단순한 버전(프로젝트2 수준): 유저 영역 + 매핑 존재 확인
  // 페이지 경계도 고려하면 좋음. 우선은 보수적으로 한 페이지 범위로 제한해도 OK(임시).
  if (uaddr == NULL || !is_user_vaddr(uaddr) ||
      pml4_get_page(thread_current()->pml4, uaddr) == NULL) {
    sys_exit(-1);
  }
}

static int sys_write(int fd, const void *user_buf, unsigned size) {
  if (fd == 1) { // stdout
    if (size == 0) return 0;
    validate_user_buffer(user_buf, size);

    // 커널 버퍼에 안전 복사(간단 버전). 큰 size는 나눠서 처리 권장.
    size_t n = size;
    if (n > PGSIZE) n = PGSIZE;  // 임시로 4KB만 (테스트 통과 후 확장)
    void *kbuf = palloc_get_page(0);
    if (kbuf == NULL) sys_exit(-1);

    memcpy(kbuf, user_buf, n);   // 엄밀히는 copy-from-user 루틴이 바람직
    putbuf(kbuf, n);             // 콘솔 출력
    palloc_free_page(kbuf);
    return (int) n;
  }

  // 파일 디스크립터는 추후 과제에서 구현
  return -1;
}

