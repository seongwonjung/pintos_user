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
#include "devices/input.h"   // input_getc()
#include "lib/kernel/console.h"
#include "filesys/file.h"   // 반드시 추가 (file_read/write/length/close)
#include "threads/malloc.h" // malloc/free 쓰면 명시적으로 포함


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
static struct file *fd_to_file_find(struct thread *t, int fd);
static int sys_read(int fd, void *user_buf, unsigned size);
static int sys_filesize (int fd);



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
#define FD_STDIN    0
#define FD_STDOUT   1
#define MIN_USER_FD 2 

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

    case SYS_READ:
    f->R.rax = sys_read((int)f->R.rdi, (void*)f->R.rsi, (unsigned)f->R.rdx);
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

    case SYS_FILESIZE:
    f->R.rax = sys_filesize((int)f->R.rdi);
    break;

		default:
		sys_exit(-1);                      // 미지원 → 종료
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
// 이미 있던 stdout 전용 버전을 "파일도 지원"하도록 확장
static int sys_write(int fd, const void *user_buf, unsigned size) {
  if (size == 0) {
    return 0;
  }
  
  if (fd == FD_STDIN) {
    return -1;
  }

  validate_user_buffer(user_buf, size);  // 최소 접근성 확인(추가로 페이지 경계 검증 OK)
  // 1) 콘솔(stdout)
if (fd == FD_STDOUT) {

  // 전체 범위 검증
  validate_user_buffer(user_buf, size);
  // 중간복사 없이 바로 출력
  putbuf((const char *)user_buf, (size_t)size);  

  return (int)size;
}

}

// read
// 필요 헤더: file_* 사용 시
// #include "filesys/file.h"

static int sys_read(int fd, void *ubuf, unsigned size) {
  if (!size) return 0;
  validate_user_buffer(ubuf, size);

  if (fd == FD_STDIN) {
    uint8_t *p = ubuf;
    for (unsigned i = 0; i < size; i++) p[i] = input_getc();
    return (int)size;
  }
  if (fd == FD_STDOUT) return -1;

  struct file *f = fd_to_file_find(thread_current(), fd);
  if (!f) return -1;

  void *k = palloc_get_page(0);
  if (!k) sys_exit(-1);

  unsigned done = 0;
lock_acquire(&filesys_lock);
while (done < size) {
  unsigned chunk = (size - done > PGSIZE) ? PGSIZE : (size - done);
  int r = file_read(f, k, (off_t)chunk);
  if (r < 0) { done = -1; break; }  // 에러
  if (r == 0) break;                // EOF
  memcpy((uint8_t*)ubuf + done, k, (size_t)r);
  done += (unsigned)r;              // ★ r<chunk 여도 계속 시도
}
lock_release(&filesys_lock);


  palloc_free_page(k);
  return (int)done;
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

  if (fd == FD_STDIN || fd == FD_STDOUT) {
    return;
  }
  // fds리스트를 순회
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

// 파일을 바이트단위로 읽고 읽은 크기를 반환
static int sys_filesize (int fd) {
  
  if (fd == FD_STDIN || fd == FD_STDOUT) {
    return -1;
  }

  struct file *f = fd_to_file_find(thread_current(), fd);

  if (!f) {
    return -1;
  }

  lock_acquire(&filesys_lock);
  int len = (int)file_length(f);
  lock_release(&filesys_lock);

  return len;
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
// static int take_free_fd(struct thread *t) {
//   if (list_empty(&t->free_fds)) return -1;
//   struct list_elem *e = list_pop_front(&t->free_fds);
//   struct fd_free *n = list_entry(e, struct fd_free, elem);
//   int fd = n->fd;
//   free(n);
//   return fd;
// }

// free_fds리스트에서 노드 한개 꺼내기
static int take_free_fd (struct thread* t) {
  while (!list_empty(&t->free_fds)) {
    if (list_empty(&t->free_fds)) return -1;
      struct list_elem *e = list_pop_front(&t->free_fds);
      struct fd_free *n = list_entry(e, struct fd_free, elem);
      int fd = n->fd;
      free(n);
      if (fd >= MIN_USER_FD) {
        return fd;
    }
  }
  return -1;
}

static void validate_user_buffer(const void *uaddr, size_t size) {
  if (size == 0) return;

  const uint8_t *start = (const uint8_t *)uaddr;
  const uint8_t *end   = start + size - 1;
  if (end < start) sys_exit(-1);  // 오버플로 방지

  // [start, end]가 걸치는 모든 페이지의 매핑 확인
  for (const uint8_t *p = pg_round_down(start);
       p <= pg_round_down(end);
       p += PGSIZE) {
    bad_addr(p);
  }
}


// 현재 스레드의 fds 리스트에서 fd에 대응하는 file* 찾기
static struct file *fd_to_file_find(struct thread *t, int fd) {
  if (fd < MIN_USER_FD || fd >= FD_MAX) return NULL;
  for (struct list_elem *e = list_begin(&t->fds);
      e != list_end(&t->fds); e = list_next(e)) {
    struct fd_entry *ent = list_entry(e, struct fd_entry, elem);
    if (ent->fd == fd) return ent->file;
  }
  return NULL;
}
