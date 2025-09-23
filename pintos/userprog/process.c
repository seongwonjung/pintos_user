#include "userprog/process.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
/* src로부터 n 바이트를 사용자 스택에 푸시하고, 스택 오버플로우 시 false를
 * 반환합니다. */
static inline bool push_bytes(struct intr_frame *if_, const void *src,
                              size_t n);
/* push_bytes()를 이용해 포인터 등 8바이트 데이터를 사용자 스택에 푸시하는 래퍼
 * 함수입니다. */
static inline bool push_pointer(struct intr_frame *if_, uint64_t val);
/* 프로그램 실행에 필요한 초기 사용자 스택을 인자(argc, argv)를 이용해
 * 구성합니다. */
static bool build_user_stack(struct intr_frame *if_, char **argv, int argc);

static struct thread *find_child(struct thread *parent, tid_t child_tid) {
  struct list_elem *e;
  struct thread *child = NULL;
  for (e = list_begin(&parent->child_list); e != list_end(&parent->child_list);
       e = list_next(e)) {
    struct thread *t = list_entry(e, struct thread, child_elem);
    if (t->tid == child_tid) {
      child = t;
      return child;
    }
  }
  return NULL;
}

/* General process initializer for initd and other process. */
static void process_init(void) { struct thread *current = thread_current(); }

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */

/* 최초 유저 프로그램 "initd"를 실행할 스레드를 생성한다.
   스레드는 즉시 스케줄될 수 있으며, 생성 실패 시 TID_ERROR를 반환한다.
   부팅 시 1회만 호출되는 것을 전제로 한다. */
tid_t process_create_initd(const char *file_name) {
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
   * Otherwise there's a race between the caller and load(). */
  /* file_name을 한 페이지에 복사(호출자/로더 간 race_condition 방지) */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  char tname[32];
  {
    char *tn_copy = palloc_get_page(0);
    if (tn_copy == NULL) return TID_ERROR;
    strlcpy(tn_copy, file_name, PGSIZE);
    char *saveptr;
    char *token = strtok_r(tn_copy, " \t\r\n", &saveptr);
    strlcpy(tname, token, sizeof(tname));
  }

  /* Create a new thread to execute FILE_NAME. */
  /* initd 엔트리(initd)로 실행할 커널 스레드 생성(자식 프로세스) */
  tid = thread_create(tname, PRI_DEFAULT, initd, fn_copy);
  if (tid != TID_ERROR) {
    struct thread *child = get_thread(tid);
    if (child) {
      list_push_back(&thread_current()->child_list, &child->child_elem);
    }
  }
  /* 생성 실패 시 임시 버퍼 해제 */
  if (tid == TID_ERROR) palloc_free_page(fn_copy);
  return tid;
}

/* A thread function that launches first user process. */
static void initd(void *f_name) {
#ifdef VM
  supplemental_page_table_init(&thread_current()->spt);
#endif

  process_init();

  if (process_exec(f_name) < 0) PANIC("Fail to launch initd\n");
  NOT_REACHED();
}

struct fork_aux {
  struct thread *parent;
  struct intr_frame *parent_if;
  struct semaphore fork_wait;
  bool succ_fork;
};

/* 현재 프로세스를 `name`이라는 이름으로 복제(clone)합니다.
 * 새 프로세스의 스레드 ID를 반환하며,
 * 스레드를 생성할 수 없으면 TID_ERROR를 반환합니다. */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED) {
  /* Clone current thread to new thread.*/
  struct fork_aux *aux = palloc_get_page(PAL_ZERO);
  {
    aux->parent = thread_current();
    aux->parent_if = if_;
    sema_init(&aux->fork_wait, 0);
    aux->succ_fork = false;
  }

  tid_t child_tid = thread_create(name, PRI_DEFAULT, __do_fork, aux);
  if (child_tid == TID_ERROR) {
    palloc_free_page(aux);
    return TID_ERROR;
  }
  sema_down(&aux->fork_wait);
  bool succ = aux->succ_fork;
  palloc_free_page(aux);
  if (succ) {
    return child_tid;
  } else {
    return TID_ERROR;
  }
}

#ifndef VM
/* pml4_for_each에 이 함수를 넘겨 호출함으로써 부모의 주소 공간을 복제합니다.
 * 이 함수는 프로젝트 2에서만 사용됩니다. */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
  struct fork_aux *fork_aux = aux;
  struct thread *current = thread_current();
  struct thread *parent = fork_aux->parent;
  void *parent_page;
  void *newpage;
  bool writable;

  /* 1. TODO: parent_page가 커널 페이지라면, 즉시 반환합니다. */
  if (is_kernel_vaddr(va)) return true;
  /* 2. 부모의 PML4에서 VA에 해당하는 실제 페이지 주소를 얻습니다. */
  parent_page = pml4_get_page(parent->pml4, va);
  if (parent_page == NULL) {
    // printf("Debug: parent page for VA %p not found\n", va);
    return true;
  }
  /* 3. TODO: 자식용으로 PAL_USER 플래그로 새 페이지를 할당하고,
   *    TODO: 결과 주소를 NEWPAGE에 저장합니다. */
  newpage = palloc_get_page(PAL_USER);
  if (newpage == NULL) {
    // printf("Debug: palloc failed for child page\n");
    return false;
  }
  /* 4. TODO: 부모 페이지의 내용을 새 페이지로 복사하고,
   *    TODO: 부모 페이지가 쓰기 가능한지 확인합니다(결과에 따라 WRITABLE을
   * 설정). */
  memcpy(newpage, parent_page, PGSIZE);
  writable = (*pte & PTE_W) != 0;
  /* 5. WRITABLE 권한으로 새 페이지를 자식의 페이지 테이블의 주소 VA에
   * 매핑합니다. */
  if (!pml4_set_page(current->pml4, va, newpage, writable)) {
    /* 6. TODO: 페이지 매핑 삽입에 실패한 경우 에러 처리를 수행합니다. */
    // printf("Debug: pml4_set_page failed for child\n");
    palloc_free_page(newpage);
    return false;
  }
  return true;
}
#endif

/* 부모의 실행 컨텍스트를 복사하는 스레드 함수.
 * 힌트) parent->tf 는 프로세스의 사용자 모드 컨텍스트를 담고 있지 않다.
 *       즉, process_fork 의 두 번째 인자(부모의 intr_frame)를
 *       이 함수로 전달해 주어야 한다. */
static void __do_fork(void *aux) {
  struct intr_frame if_;
  struct fork_aux *fork_aux = aux;
  struct thread *parent = fork_aux->parent;
  struct thread *current = thread_current();
  /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
  struct intr_frame *parent_if = fork_aux->parent_if;
  bool succ = true;
  // 부모-자식 관계 리스트 연결
  list_push_back(&parent->child_list, &current->child_elem);
  /* 1. CPU 컨텍스트를 로컬 스택(if_)으로 읽어온다. */
  memcpy(&if_, parent_if, sizeof(struct intr_frame));
  // 자식 RAX = 0 설정
  if_.R.rax = 0;

  /* 2. 페이지 테이블(PT)을 복제한다. */
  current->pml4 = pml4_create();
  if (current->pml4 == NULL) goto error;

  process_activate(current);
#ifdef VM
  supplemental_page_table_init(&current->spt);
  if (!supplemental_page_table_copy(&current->spt, &parent->spt)) goto error;
#else
  if (!pml4_for_each(parent->pml4, duplicate_pte, fork_aux)) goto error;
#endif

  /* TODO: 여기에 네 코드를 작성하라.
   * TODO: 힌트) 파일 객체를 복제하려면 include/filesys/file.h 의
   * TODO:       `file_duplicate` 를 사용하라. 또한, 부모는 이 함수가
   * TODO:       부모의 자원(리소스) 복제를 성공적으로 마칠 때까지
   * TODO:       fork() 에서 반환하면 안 된다. */
  for (int i = 2; i < FD_MAX; i++) {
    if (parent->fd_table[i]) {
      lock_acquire(&filesys_lock);
      struct file *file = file_duplicate(parent->fd_table[i]);
      lock_release(&filesys_lock);
      current->fd_table[i] = file;
    }
  }

  process_init();

  if (succ) {
    // 성공 여부
    fork_aux->succ_fork = true;
    // fork 기다리는 부모 프로세스 깨우기
    sema_up(&fork_aux->fork_wait);
    // 마지막으로, 새로 생성된 프로세스로 전환(do_iret)한다.
    do_iret(&if_);
  }

error:
  sema_up(&fork_aux->fork_wait);
  thread_exit();
}

/* 현재 실행 컨텍스트를 종료하고 f_name으로 지정된 프로그램을 실행한다.
   실패 시 -1 반환, 성공 시 사용자 모드로 전환되므로 반환하지 않는다. */
int process_exec(void *f_name) {
  char *file_name = f_name;
  bool success;

  /* 스레드 구조체의 intr_frame는 스케줄링 시 덮어쓰일 수 있으므로
 지역 intr_frame를 생성하여 사용자 모드 진입 정보를 준비한다. */
  struct intr_frame _if;
  _if.ds = _if.es = _if.ss = SEL_UDSEG; /* 사용자 데이터 세그먼트 */
  _if.cs = SEL_UCSEG;                   /* 사용자 코드 세그먼트 */
  _if.eflags = FLAG_IF | FLAG_MBS;      /* 인터럽트 활성화, 필수 비트 설정 */

  /* 현재 프로세스의 유저 주소공간과 리소스 정리 */
  process_cleanup();

  /* 실행 파일 로드: ELF 파싱, 페이지 매핑, 스택 구성, 진입점/레지스터 설정 */
  success = load(file_name, &_if);

  /* 커맨드라인 버퍼 해제(호출 전 한 페이지로 복사해 둔 버퍼) */
  palloc_free_page(file_name);
  if (!success) return -1;

  /* 준비된 intr_frame으로 사용자 모드로 점프(복귀하지 않음) */
  do_iret(&_if);
  NOT_REACHED();
}

/* 스레드 TID가 종료할 때까지 기다리고, 그 종료 상태(exit status)를 반환합니다.
 * 만약 커널에 의해 종료되었다면(예: 예외로 강제 종료된 경우) -1을 반환합니다.
 * TID가 유효하지 않거나, 호출한 프로세스의 자식이 아니거나,
 * 혹은 해당 TID에 대해 process_wait()가 이미 한 번 성공적으로 호출된 적이
 * 있다면, 기다리지 않고 즉시 -1을 반환합니다.
 *
 * 이 함수는 문제 2-2에서 구현됩니다. 현재는 아무 작업도 하지 않습니다. */
int process_wait(tid_t child_tid UNUSED) {
  /* XXX: 힌트) initd에서 process_wait을 호출하면 Pintos가 종료됩니다.
   * XXX:       process_wait을 구현하기 전에는 커널이 꺼지지 않도록
   * XXX:       여기서 무한 루프를 넣어 두길 권장합니다.
   */
  struct thread *parent = thread_current();
  struct thread *child = NULL;

  child = find_child(parent, child_tid);

  if (child == NULL || child->is_waited || child->tid != child_tid) return -1;

  child->is_waited = true;
  // 자식이 끝날 때까지 wait
  sema_down(&child->wait_sema);
  int status = child->exit_status;
  list_remove(&child->child_elem);
  return status;
}

/* 프로세스를 종료합니다. 이 함수는 thread_exit()에 의해 호출됩니다. */
void process_exit(void) {
  struct thread *curr = thread_current();
  if (curr->running_file) {
    file_close(curr->running_file);
    curr->running_file = NULL;
  }
  // file_allow_write(curr->running_file);
  /* TODO: 여기에 코드를 작성하세요.
   * TODO: 프로세스 종료 메시지를 구현하세요
   * TODO: (project2/process_termination.html 참고).
   * TODO: 프로세스 자원 정리를 이곳에서 구현할 것을 권장합니다. */
  for (int i = 0; i < FD_MAX; i++) {
    if (curr->fd_table[i]) fd_close(curr, i);
  }

  sema_up(&curr->wait_sema);
  process_cleanup();
}

/* Free the current process's resources. */
static void process_cleanup(void) {
  struct thread *curr = thread_current();

#ifdef VM
  supplemental_page_table_kill(&curr->spt);
#endif

  uint64_t *pml4;
  /* Destroy the current process's page directory and switch back
   * to the kernel-only page directory. */
  pml4 = curr->pml4;
  if (pml4 != NULL) {
    /* Correct ordering here is crucial.  We must set
     * cur->pagedir to NULL before switching page directories,
     * so that a timer interrupt can't switch back to the
     * process page directory.  We must activate the base page
     * directory before destroying the process's page
     * directory, or our active page directory will be one
     * that's been freed (and cleared). */
    curr->pml4 = NULL;
    pml4_activate(NULL);
    pml4_destroy(pml4);
  }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next) {
  /* Activate thread's page tables. */
  pml4_activate(next->pml4);

  /* Set thread's kernel stack for use in processing interrupts. */
  tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct ELF64_PHDR {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* src로부터 n 바이트를 사용자 스택에 푸시하고, 스택 오버플로우 시 false를
 * 반환합니다. */
static inline bool push_bytes(struct intr_frame *if_, const void *src,
                              size_t n) {
  // 스택 한 페이지의 최저 유저주소
  uint64_t low = (uint64_t)USER_STACK - PGSIZE;
  if (n > (size_t)(if_->rsp - low)) return false;  // 한 페이지 넘김 방지
  if_->rsp -= n;
  memcpy((void *)if_->rsp, src, n);
  return true;
}

/* push_bytes()를 이용해 포인터 등 8바이트 데이터를 사용자 스택에 푸시하는 래퍼
 * 함수 */
static inline bool push_pointer(struct intr_frame *if_, uint64_t val) {
  return push_bytes(if_, &val, sizeof(val));
}

/* 프로그램 실행에 필요한 초기 사용자 스택을 인자(argc, argv)를 이용해
 * 구성합니다. */
static bool build_user_stack(struct intr_frame *if_, char **argv, int argc) {
  uint64_t arg_addr[MAX_ARGS];
  // 1. 문자열 역순 push -> arg_addr[]
  for (int i = argc - 1; i >= 0; i--) {
    size_t len = strlen(argv[i]) + 1;  // '\0' 을 포함하니 +1
    if (!push_bytes(if_, argv[i], len)) return false;
    arg_addr[i] = if_->rsp;
  }

  // 2. 8바이트 정렬을 위한 패딩 추가
  size_t total_pointers_size = (argc + 1) * sizeof(char *);
  size_t remainder = (if_->rsp - total_pointers_size) % 8;
  if (remainder > 0) {
    if_->rsp -= remainder;
    memset((void *)if_->rsp, 0, remainder);
  }

  // 3. NULL, argv[i] 포인터들, fake ret
  if (!push_pointer(if_, 0)) return false;  // NULL push

  for (int i = argc - 1; i >= 0; i--) {  // argv[i] 포인터들 push
    if (!push_pointer(if_, (uint64_t)arg_addr[i])) return false;
  }

  // 현재 rsp가 argv 배열의 시작 주소
  uint64_t argv_user = if_->rsp;
  if_->R.rdi = (uint64_t)argc;
  if_->R.rsi = argv_user;
  if (!push_pointer(if_, 0)) return false;  // return address

  ASSERT((if_->rsp & 0x7) == 0);

  return true;
}

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
/* ELF 실행 파일을 유저 주소공간에 적재하고, 스택과 진입점을 설정한다.
   성공 시 true, 실패 시 false를 반환한다. */
static bool load(const char *file_name, struct intr_frame *if_) {
  struct thread *t = thread_current();
  struct ELF ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* 커맨드라인 복사용 임시 페이지 버퍼 */
  char *cmd_tmp = palloc_get_page(PAL_ZERO);
  if (cmd_tmp == NULL) {
    goto done;
  }
  strlcpy(cmd_tmp, file_name, PGSIZE);

  /* 공백 단위 토크나이즈하여 argv/argc 구성 */
  char *argv[MAX_ARGS];
  int argc = 0;

  char *saveptr = NULL;
  char *token = strtok_r(cmd_tmp, "\t\r\n ", &saveptr);

  while (token != NULL && argc < MAX_ARGS - 1) {
    argv[argc++] = token;
    token = strtok_r(NULL, "\t\r\n ", &saveptr);
  }

  argv[argc] = NULL;
  file_name = argv[0]; /* argv[0]: 실행 파일 경로 */

  /* Allocate and activate page directory.
  주소공간 생성 & 활성화
  새 페이지 테이블(PML4)를 만들고, 현재 스레드(프로세스)의 주소공간으로 스위치*/
  t->pml4 = pml4_create();
  if (t->pml4 == NULL) goto done;
  process_activate(thread_current());

  /* Open executable file.
  실행 파일 열기 */
  lock_acquire(&filesys_lock);
  file = filesys_open(file_name);
  lock_release(&filesys_lock);
  if (file == NULL) {
    // printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header.
  ELF 헤더 읽기 & 검증 */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 0x3E  // amd64
      || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) ||
      ehdr.e_phnum > 1024) {
    // printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers.
  프로그램 헤더 나열을 순회하며 세그먼트 처리 */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file)) goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint64_t file_page = phdr.p_offset & ~PGMASK;
          uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint64_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
             * Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes =
                (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
             * Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void *)mem_page, read_bytes,
                            zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack.
  유저 스택 만들기 */
  if (!setup_stack(if_)) goto done;

  /* Start address.
  진입점(rip 시작 주소) 설정 */
  if_->rip = ehdr.e_entry;

  /* TODO: Your code goes here.
   * TODO: Implement argument passing (see project2/argument_passing.html). */

  /* 인자 전달: 스택 위에 argv/argc 배치 및 레지스터 갱신 */
  build_user_stack(if_, argv, argc);

  success = true;
  t->running_file = file;
  file_deny_write(file);
done:
  /* We arrive here whether the load is successful or not. */
  /* 정리: 파일 닫기, 임시 페이지 해제 */
  palloc_free_page(cmd_tmp);
  return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (uint64_t)file_length(file)) return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0) return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr)) return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz))) return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE) return false;

  /* It's okay. */
  return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Do calculate how to fill this page.
     * We will read PAGE_READ_BYTES bytes from FILE
     * and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL) return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      printf("fail\n");
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool setup_stack(struct intr_frame *if_) {
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
    if (success)
      if_->rsp = USER_STACK;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
   * address, then map our page there. */
  return (pml4_get_page(t->pml4, upage) == NULL &&
          pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool lazy_load_segment(struct page *page, void *aux) {
  /* TODO: Load the segment from the file */
  /* TODO: This called when the first page fault occurs on address VA. */
  /* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0) {
    /* Do calculate how to fill this page.
     * We will read PAGE_READ_BYTES bytes from FILE
     * and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* TODO: Set up aux to pass information to the lazy_load_segment. */
    void *aux = NULL;
    if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable,
                                        lazy_load_segment, aux))
      return false;

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack(struct intr_frame *if_) {
  bool success = false;
  void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

  /* TODO: Map the stack on stack_bottom and claim the page immediately.
   * TODO: If success, set the rsp accordingly.
   * TODO: You should mark the page is stack. */
  /* TODO: Your code goes here */

  return success;
}
#endif /* VM */
