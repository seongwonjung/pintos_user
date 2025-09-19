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
#include "filesys/filesys.h"
#include "filesys/directory.h"   // NAME_MAX
#include "threads/synch.h"       // lock
#include "threads/mmu.h"         // pml4_get_page (매핑 확인)

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static void sys_exit(int status);
static void validate_user_buffer(const void *uaddr, size_t size);
static int sys_write(int fd, const void *user_buf, unsigned size);
static int copy_string (char *dst, const char *us, size_t limit);
static bool sys_create(const char* u_name, unsigned init_size);
static void bad_addr(const void* uaddr);
int sys_open(const char* u_name);
void sys_close(int fd);
int fdtable_insert(struct thread *t, struct file *f);
static int take_free_fd(struct thread *t);


// 전역변수
static struct lock filesys_lock;  // 전역 락

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

  lock_init(&filesys_lock);
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

    case SYS_CREATE:
    f->R.rax = sys_create((const char*)f->R.rdi, (unsigned)f->R.rsi);
    break;

    case SYS_OPEN:
    f->R.rax = sys_open((const char*)f->R.rdi);
    break;

    case SYS_CLOSE:
    sys_close((int)f->R.rdi);
    break;

    case SYS_READ:
    f->R.rax = sys_read()
    break;
    
		default:
		sys_exit(0);                      // 미지원 → 종료
  }
}


// threads/thread.h 등에 현재 스레드의 종료코드 저장용 필드가 필요할 수 있음
// int exit_status;  // thread 구조체에 추가 (process_wait와도 연계)
// userprog/syscall.c

// exit
static void sys_exit(int status) {
  struct thread *t = thread_current();
  t->exit_status = status;

  thread_exit();   // 돌아오지 않음
}

// write
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

// create
static bool sys_create(const char* u_name, unsigned init_size) {
  char kname[NAME_MAX + 1];

  int n = copy_string(kname, u_name, NAME_MAX);
  // 이름길이 초과
  if (n == -2) {
    return false;
  }

  // 빈 이름 false
  if (kname[0] == '\0') {
    return false;
  }
  
  lock_acquire(&filesys_lock);
  bool ok = filesys_create(kname, init_size);
  lock_release(&filesys_lock);

  return ok;
}

// // open
// static int sys_open (const char* file) {
//   char* kname[NAME_MAX + 1];
//   int fd;
//   // 입력값 검증
//   if (file == NULL) {
//     sys_exit(-1);
//   }

//   int n = copy_string(kname, file, NAME_MAX + 1);
//   // 입력값 바이트단위 검증
//   if (kname[0] == '\0') {
//     return -1;
//   }
//   if (n == -2) {
//     return -1;
//   }
//   // 파일 open
//   lock_acquire(&filesys_lock);
//   struct file* f = filesys_open(file);
//   lock_release(&filesys_lock);
//   //open파일 검증
//   if (f == NULL) {
//     sys_exit(-1);
//   }
//   // fd 할당
//   fd = fdtable_insert(thread_current(), f);
//   //fd 검증
//   if (fd > 0) {
//     sys_exit(-1);
//   }
// }

// open
int sys_open(const char* u_name) {
  if (u_name == NULL) sys_exit(-1);

  char kname[NAME_MAX + 1];

  int n = copy_string(kname, u_name, sizeof kname);   // 사용자 포인터 검증+복사
  if (n < 0 || kname[0] == '\0') return -1;

  lock_acquire(&filesys_lock);
  struct file* f = filesys_open(kname);               // kname 사용!
  lock_release(&filesys_lock);
  if (f == NULL) return -1;

  struct thread *t = thread_current();                // 인자 없이 호출
  int fd = fdtable_insert(t, f);                      // ← 여기서 fd 선언 필요
  if (fd < 0) { 
    file_close(f); return -1; // 실패시 누수 방지
  }           

  return fd;
}


// close
void sys_close(int fd) {
  struct thread *t = thread_current();
  struct list_elem *e;
  // ??
  for (e = list_begin(&t->fds); e != list_end(&t->fds); e = list_next(e)) {
    struct fd_entry *ent = list_entry(e, struct fd_entry, elem);

    if (ent->fd == fd) {
      list_remove(e);
      file_close(ent->file);
      // 재사용 등록
      struct fd_free *n = malloc(sizeof *n);
      if (n) { 
        n->fd = fd; list_push_back(&t->free_fds, &n->elem); 
      }
      free(ent);
      return;
    }
  }
  // 잘못된 fd면 과제 정책에 맞게 -1 반환 또는 exit 처리
}

// 유저 문자열을 널까지 안전 복사
// - limit(NAME_MAX)를 넘기면 -2 반환(→ 의미 오류로 false 반환)
// - 포인터 불량이면 내부에서 sys_exit(-1)
static int copy_string (char *dst, const char *us, size_t limit) {
  size_t i = 0;
  while (1) {
    const char *p = us + i;
    bad_addr(p);       // 페이지 경계마다 매핑 검증
    char c = *(const char *)p;      // 이제 읽기
    if (i >= limit) return -2;      // NAME_MAX 초과(널 미도달) → 의미 오류
    dst[i++] = c;
    if (c == '\0') break;
  }
  return (int)i; 
}


// 잘못된 유저 주소 접근시, 해당 프로세스를 -1로 종료
static void bad_addr(const void* uaddr) {
  if (uaddr == NULL ||
    !is_user_vaddr(uaddr) ||
    pml4_get_page(thread_current()->pml4, uaddr) == NULL) {
    sys_exit(-1);
  }
}

// 반환된 free가 있으면 재사용, 아니면 새로운 fd 할당
int fdtable_insert(struct thread *t, struct file *f) {
  if (t == NULL || f == NULL) return -1;

  int fd = take_free_fd(t);
  if (fd < 0) {
    if (t->next_fd >= FD_MAX) return -1;  // 공간 없음
    fd = t->next_fd++;
  }

  struct fd_entry *ent = malloc(sizeof *ent);
  if (!ent) {
    // 엔트리 못 만들었으면 FD를 free_fds로 되돌려놓기(최소 손실화)
    struct fd_free *n = malloc(sizeof *n);
    if (n) { n->fd = fd; list_push_front(&t->free_fds, &n->elem); }
    return -1;
  }

  ent->fd = fd;
  ent->file = f;
  list_push_back(&t->fds, &ent->elem);
  return fd;
}

// free_fds에서 하나 꺼내기
static int take_free_fd(struct thread *t) {
  if (list_empty(&t->free_fds)) return -1;
  struct list_elem *e = list_pop_front(&t->free_fds);
  struct fd_free *n = list_entry(e, struct fd_free, elem);
  int fd = n->fd;
  free(n);
  return fd;
}

static void validate_user_buffer(const void *uaddr, size_t size) {
  // 가장 단순한 버전(프로젝트2 수준): 유저 영역 + 매핑 존재 확인
  // 페이지 경계도 고려하면 좋음. 우선은 보수적으로 한 페이지 범위로 제한해도 OK(임시).
  if (uaddr == NULL || !is_user_vaddr(uaddr) ||
      pml4_get_page(thread_current()->pml4, uaddr) == NULL) {
    sys_exit(-1);
  }
}