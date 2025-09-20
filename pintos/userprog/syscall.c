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

// 🅲
#include "threads/palloc.h"           // palloc_get_page(), palloc_free_page(), PGSIZE
#include "threads/vaddr.h"            // is_user_vaddr()
#include "threads/mmu.h"              // pml4_get_page()
#include "filesys/filesys.h"          // filesys_create()
#include <string.h>                   // memcpy, strlen, strnlen 등
#include "threads/synch.h"            // struct lock, lock_init(), lock_acquire(), lock_release()

// 🅾, 🆂, 🆁
#include "filesys/file.h"     // struct file, file_open(), file_close(), file_read()  (일반 파일에서 읽기 위해)

// 🆁
#include "devices/input.h"   // input_getc()      (stdin(0) 읽을 때 키보드에서 한 바이트씩 가져오려면)
#include <stdint.h>          // uintptr_t
#include "filesys/file.h"  // file_length(), file_tell()

// 🅵
#include "userprog/process.h"  // process_fork, process_wait, process_exit

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

static void sys_exit (int status);
static int  sys_write (int fd, const void *buf, unsigned size);

static struct lock filesys_lock;         // 파일시스템 락(전역)

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


// 🅲 CREATE 헬퍼: 유저 문자열을 커널 페이지로 안전 복사
//  - 성공: palloc 페이지(4KB)에 NULL-terminated로 복사하여 포인터 반환
//  - 실패: 프로세스 종료(exit -1)
static char* copy_in_string_or_exit (const char *uaddr) {
  /* 1. 준비 & 예외처리*/ 
  if (uaddr == NULL) sys_exit(-1);                // 예외처리(NULL)
  struct thread *cur = thread_current();          // 현재 스레드 구조체 포인터

  char *kpage = palloc_get_page(0);               // 커널 전용 4KB 페이지 할당
  if (!kpage) sys_exit(-1);                       // 예외 처리(메모리 부족) 

  /* 2. 무한 루프로 문자 하나씩 검사/복사*/
  size_t i = 0;            // 복사할 인덱스

  while (1) {
    const char *p = uaddr + i;          // 현재 복사할 유저 주소(i번째 글자 위치)

    // IF, 커널 공간 / 미매핑 주소 -> 예외 처리
    if (!is_user_vaddr(p) || pml4_get_page(cur->pml4, p) == NULL) {
      palloc_free_page(kpage);
      sys_exit(-1);
    }

    /*안전하다고 판단 후 커널 버퍼에 복사*/    
    kpage[i] = *p;                         
    if (kpage[i] == '\0') break;           // 문자열 끝(널문자)이면 복사 완료
    i++;                                   // 다음 글자로 이동

    // 너무 긴 문자열 방지(테스트 create-long 대비)
    if (i + 1 >= PGSIZE) {               // 널문자 한 칸까지 고려했을 때 공간이 없으면
      kpage[i] = '\0';                   // 현재 위치에 강제로 '\0'을 넣고 종료
      break;
    }
  }
  return kpage;                          // NULL-종결 문자열 버퍼 반환
}


// 🅾 OPEN 헬퍼: 비어있는 FD 슬롯에 file* 등록하고 FD 번호 반환(없으면 -1)
static int fd_install(struct thread *t, struct file *f){

  for(int fd = FD_MIN; fd < FD_MAX; fd++){            
    if(t->fd_table[fd] == NULL){          // NULL이면 아직 아무 파일도 안 꽂혀 있음 → 사용 가능한 슬롯
      t->fd_table[fd] = f;
      // t->fd_next = fd + 1;
    // if(t->fd_next >= FD_MAX) t->fd_next = FD_MIN;      // 예외 처리(랩어라운드)  
    
    return fd;         // 성공 -> fd번호 반환
    } 
  }
  return -1;            // 실패
}




void syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

  lock_init(&filesys_lock);       // 🅲 파일시스템 락 초기화
  
}


// 🚧 sys_exit
// “프로세스가 나 끝낼게요!”라고 말할 때 해야 할 일
static void sys_exit (int status) {
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", thread_name(), status);   /* 테스트가 기대하는 종료 메시지 출력 */
  
  cur->exit_status = status;                       // 종료 코드 "현재 스레드 구조체"에 저장
  thread_exit();                                   // 커널 스레드 종료
}

// 🚧

// 🅲 CREATE: sys_create
  //  ufile == NULL / bad ptr / kernel addr  -> exit(-1)
  //  ""(빈문자열)           -> return 0(false)
static int sys_create (const char *ufile, unsigned initial_size) {
  char *kname = copy_in_string_or_exit(ufile);   // ufile(유저가 준 포인터)을 안전한 커널 버퍼로 가져옴(실패 시 내부에서 exit(-1))
  int ok = 0;                   // 기본값: 실패 (0)

  if (kname[0] != '\0') {                        // 빈 문자열: false
    lock_acquire(&filesys_lock);
    ok = filesys_create(kname, (off_t)initial_size) ? 1 : 0;    // "파일 생성"
    lock_release(&filesys_lock);
  } // else ok=0

  palloc_free_page(kname);           // 커널 버퍼(4KB) 를 꼭 반납
  return ok;                         // 0(실패), 1(성공) 값을 반환
}

// 🅾 OPEN
static int sys_open(const char *ufile){
  // 1) 준비
  char *kname = copy_in_string_or_exit(ufile);  // 유저 포인터 검증 & 커널 버퍼로 복사
  int ret = -1;             // 기본값: 실패(-1)

  // 2) 파일 열기
  if (kname[0] != '\0') {                        // 빈 문자열: false
    lock_acquire(&filesys_lock);
    struct file *f = filesys_open(kname);         // "파일 열기"(성공 시 file*)
    lock_release(&filesys_lock);
    
    // 3) FD테이블에 등록(IF, 파일 실제 존재)
    if (f){
      struct thread *cur = thread_current();
      int newfd = fd_install(cur, f);         // FD테이블 장착
      
      if(newfd >= FD_MIN){
        ret = newfd;                     // 성공
      } else{                            // 실패(FD 공간 부족)→ 열린 파일 닫고 실패
        lock_acquire(&filesys_lock);
        file_close(f);         
        lock_release(&filesys_lock);
      }
    }
  } 

  // 4) 정리
  palloc_free_page(kname);            // 커널 버퍼(4KB) 해제
  return ret;                         // newfd(성공), -1(실패) 값을 반환
}

// 🆂 CLOSE
void sys_close(int fd){
  struct thread *cur = thread_current();

  // 1. 예외 처리
  if(fd < FD_MIN || fd >= FD_MAX) return;         // 범위

  struct file *f = cur->fd_table[fd];
  if(f == NULL) return;                           // NULL
  
  // 2. CLOSE
  cur->fd_table[fd] = NULL;             // 먼저 비우기            
  
  lock_acquire(&filesys_lock);        
  file_close(f);                         // "파일 닫기"    
  lock_release(&filesys_lock);
}

// 🆁 🆆 헬퍼(파일 사이즈)
int filesize(int fd){
    if(fd < 0 || fd >= FD_MAX){
        return -1;
    }
    struct thread *t = thread_current();
    struct file *target_file = t->fd_table[fd];
    if(target_file == NULL){
        return -1;
    }
    lock_acquire(&filesys_lock);
    int size = file_length(target_file);
    lock_release(&filesys_lock);
    return size;
}

// 🆁 READ
static int sys_read(int fd, void *buffer, unsigned size){
  struct thread *cur = thread_current();

  // 1. 예외 처리
  if(size == 0) return 0;                     // 0바이트 -> 검사 필요X (즉시 통과)
                        
  if (fd < 0 || fd >= FD_MAX) return -1;      // FD 범위 (실패)
  if (!buffer || !is_user_vaddr(buffer) || !pml4_get_page(cur->pml4, buffer)) sys_exit(-1);  // 버퍼 (종료)
  
  // 2. 표준 입출력
  if(fd == 1) return -1;                          // STDOUT(출력)
  
  // STDIN(입력)
  else if(fd == 0){                         
     unsigned i = 0;
     for (; i < size; i++)                           
       ((uint8_t *)buffer)[i] = input_getc();     // 한 글자씩 키보드에서 읽어와 버퍼에 채움  
     return (int)i;                               // 읽은 바이트 수 반환
  }
  // 3. 일반 파일
  else{
    struct file *f = cur->fd_table[fd];
    if (!f) return -1;                               // 미할당 FD

    lock_acquire(&filesys_lock);
    int nread = file_read(f, buffer, size);
    lock_release(&filesys_lock);
    return nread;
  }
}

// 🆆 WRITE
static int sys_write(int fd, const void *buffer, unsigned size){
  struct thread *cur = thread_current();

  // 1. 예외 처리
  if(size == 0) return 0;                            // 0바이트 -> 검사 필요X (즉시 통과)
  if (fd < 0 || fd >= FD_MAX) return -1;             // FD 범위 (실패)
  if (!buffer || !is_user_vaddr(buffer) || !pml4_get_page(cur->pml4, buffer)) sys_exit(-1);  // 버퍼 (종료)
  
  // 2. 표준 입출력
  if(fd == 0) return -1;                          // STDIN(입력)
  
  // STDOUT(출력) 
  else if(fd == 1){                         
    putbuf((const char *)buffer, (size_t)size);
    return (int)size;
  }

  // 3. 일반 파일
  else{
    struct file *f = cur->fd_table[fd];
    if (!f) return -1;                               // 미할당 FD

    lock_acquire(&filesys_lock);
    int nwrite = file_write(f, buffer, size);
    lock_release(&filesys_lock);
    return nwrite;
  }
}


// 🅵 FORK(부모): 유저가 준 인자(프로세스 이름 등)를 안전하게 커널로 들여와 process_fork() 호출
// fork 하기 -> (fork O)자식프로세스 생성 -> 그 자식 프로세스의 pid 반환
static tid_t sys_fork(const char *thread_name){
  // 1. 유효성 검사 & 커널 버퍼로 복사 
  char *fbuf = copy_in_string_or_exit(thread_name);

  // 2. 부모 레지스터 상태 복사(유저->커널)
  struct thread *parent = thread_current();
  struct intr_frame *parent_if = &parent->fork_if;    
  
  // 3. 포크 실행
  tid_t child_pid = process_fork(fbuf, parent_if);

  // 4. 정리
  palloc_free_page(fbuf);     // 버퍼 반납
  return (tid_t)child_pid;    // 반환
}

static int sys_wait (tid_t pid){
  return process_wait(pid);
}


// 유저 프로그램이 syscall을 부르면, 무슨 번호인지 보고 맞는 함수로 보내기
void syscall_handler (struct intr_frame *f) {
  uint64_t num = f->R.rax;                    // 시스템콜 번호(RAX 확인)
  switch (num) {
    
    case SYS_EXIT:                            // exit(status) => RDI만 사용
      sys_exit((int)f->R.rdi);                // 첫 번째 인자(RDI)를 int로 변환해서 sys_exit에 넘김
      break;
    
    case SYS_CREATE: {
      const char *ufile = (const char *)f->R.rdi;      // RDI: 1번째 인자 → filename 포인터
      unsigned size = (unsigned)f->R.rsi;              // RSI: 2번째 인자 → size
      f->R.rax = (uint64_t)sys_create(ufile, size);
      break;
    }

    case SYS_OPEN: {
      const char *ufile = (const char *)f->R.rdi;      // RDI: 1번째 인자 → fd
      f->R.rax = (int)sys_open(ufile);
      break;
    }

    case SYS_CLOSE: {
      int fd = (int)f->R.rdi;      // RDI → 첫 번째 인자(filename 포인터)
      sys_close(fd);
      break;
    }

    case SYS_FILESIZE:
      f->R.rax = filesize(f->R.rdi);
      break;

    case SYS_READ: {
      int fd = (int)f->R.rdi;                             // RDI: 1번째 인자 → fd
      void *buffer = (void *)f->R.rsi;                    // RSI: 2번째 인자 → 사용자 버퍼 포인터
      unsigned size = (unsigned)f->R.rdx;                 // RDX: 3번째 인자 → 읽을 바이트 수
      f->R.rax = (int)sys_read(fd, buffer, size);         // 리턴값을 RAX에 실어줌
      break;
    }

    case SYS_WRITE: {
      int fd = (int)f->R.rdi;                             // RDI: 1번째 인자 → fd
      void *buffer = (const void *)f->R.rsi;              // RSI: 2번째 인자 → 사용자 버퍼 포인터
      unsigned size = (unsigned)f->R.rdx;                 // RDX: 3번째 인자 → 읽을 바이트 수
      f->R.rax = (int)sys_write(fd, buffer, size);        // 리턴값을 RAX에 실어줌
      break;
    }

   case SYS_FORK: {
      thread_current()->fork_if = *f;                       // ★ 부모 유저 프레임 복사  
      const char *thread_name = (const char *)f->R.rdi;     // RDI: 1번째 인자 → 이름 포인터
      f->R.rax = (uint64_t)sys_fork(thread_name);           // 리턴값을 RAX에 실어줌
      break;
    }

    case SYS_WAIT: {  
      f->R.rax = (int)sys_wait((tid_t) f->R.rdi);           // 리턴값을 RAX에 실어줌
      break;
    }
    default:
      sys_exit(-1);      // 모르는 시스템콜 번호면 "프로세스 종료(-1)"로 처리
  }
}





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
