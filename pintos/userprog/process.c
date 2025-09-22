#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"        
#include "threads/malloc.h"    // 🚧 malloc (작은 구조체: struct child, struct start_info)
#include "userprog/syscall.h"   // 
#include "intrinsic.h"


#ifdef VM
#include "vm/vm.h"
#endif

#ifndef MAX_ARGC
#define MAX_ARGC 64
#endif


 // 🚧
/* initd 시작용 패키지 */
struct start_info {
  char *file_name;        // 자식에게 넘길 명령줄 복사본
  struct child *c;        // 부모가 만든 child 노드 포인터(핸드셰이크용)
};
// 🚧


static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

static struct lock filesys_lock;         // 파일시스템 락(전역)


/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd (const char *file_name) {    // file_name: 부모가 넘겨준 커맨드라인 전체(예: "echo hello").
	char *fn_copy;                         // 커맨드라인을 커널 페이지에 안전하게 복사해둘 버퍼 포인터
	tid_t tid;                             // 새로 만들 자식 스레드 저장용

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);                     // 4KB 페이지 하나 할당
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);             // 최대 PGSIZE까지 복사(→ 오버런 방지)

	// 🚧
	
	/*  스레드 이름은 “첫 토큰”만 사용 */
    char tname[16];                   // 버퍼(최대 15자 + NULL)
    {
      const char *p = file_name;
      while (*p == ' ' || *p == '\t') p++;               // 공백/탭 건너뛰고 첫 글자에 맞춰 둠
      size_t n = 0;
      while (*p && *p!=' ' && *p!='\t' && *p!='\r' && *p!='\n') {
         if (n + 1 < sizeof tname) tname[n++] = *p;       // 첫 토큰(공백/개행 전까지)을 tname에 복사
         p++;
      }

      tname[n] = '\0';
      if (n == 0) strlcpy(tname, "initd", sizeof tname);   // 토큰이 하나도 없으면(빈 문자열이면) 예비 이름 "initd" 사용
    }

	 /* ⬇️ 자식 상태 노드 1개 생성 + 부모 리스트에 연결 */
     struct child *c = malloc(sizeof *c);                      // 부모가 자식을 식별/대기하기 위한 상태 노드(struct child)를 힙에 생성
     if (!c) { palloc_free_page(fn_copy); return TID_ERROR; }  //예외처리
     
	 c->tid = TID_ERROR; c->exit_status = -1;                    // 초기값: 아직 스레드 생성 전이니 tid는 임시 TID_ERROR, 종료코드도 미정(-1)
     
	 sema_init(&c->load_sema, 0); c->load_success = false;       // 결과 플래그/종료 플래그는 기본값 false
     sema_init(&c->wait_sema, 0); c->exited = false;  
     
	 list_push_back(&thread_current()->children, &c->elem);      // 현재 스레드(=부모)의 children 리스트에 이 노드를 연결 -> 나중에 정확한 매칭 위해

   
	 /* ⬇️ initd에 넘길 aux 패키지 */
    struct start_info *si = malloc(sizeof *si);           // 자식에게 전달해야 할 2가지(커맨드라인 페이지, child 노드)를 구조체로 포장
    if (!si) { list_remove(&c->elem); free(c); palloc_free_page(fn_copy); return TID_ERROR; }    // 예외 처리
    si->file_name = fn_copy;       // 커맨드라인 페이지
    si->c = c;                     // child 노드 저장

	tid = thread_create (tname, PRI_DEFAULT, initd, si);            //새 커널 스레드 생성(시작 함수는 initd, aux로 si 포인터 전달)
    
	if (tid == TID_ERROR) {
       free(si); list_remove(&c->elem); free(c); palloc_free_page(fn_copy);
       return TID_ERROR;
    }

    c->tid = tid;                // 진짜 자식의 tid를 child 노드에 기록

    
	/* ⬇️ 로드 결과만 1회 대기(전역 세마 대체) */
    sema_down(&c->load_sema);                    // 부모는 여기서 딱 한 번 기다림. (초기값 0이니 자식이 sema_up할 때까지 슬립)
    if (!c->load_success) return TID_ERROR;      // 실패

    // 🚧

	/* Create a new thread to execute FILE_NAME. */
	// tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	// tid = thread_create (tname, PRI_DEFAULT, initd, fn_copy);
	// if (tid == TID_ERROR)
	// 	palloc_free_page (fn_copy);
	return tid;                              // 성공 -> 자식의 tid를 반환
}

/* A thread function that launches first user process. */
static void initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);      //새 스레드의 SPT 준비
#endif   

	process_init ();       // 공통 프로세스 초기화


	// 🚧
	// aux(=f_name) 포장 풀기
	struct start_info *si = f_name;
    struct thread *cur = thread_current();

    /* aux 내용 보관하고 si는 해제해도 됨 */
    struct child *c = si->c;                  // child 노드
    char *fname = si->file_name;              // file_name(palloc된 한 페이지)
    free(si);                                 //포장 자체는 더 쓸 일 X -> 즉시 free

    cur->as_child = c;                        // 부모와 통신할 핸드셰이크 창구로 child 노드를 연결

    if (process_exec (fname) < 0) {                   // 진짜 유저 프로그램으로 갈아타기(process_exec() 호출) -> 실패(<0)면
   
      cur->exit_status = -1;                            // 종료코드 -1 설정
      thread_exit();                                    // 종료
    }
    
	NOT_REACHED ();                                    // 성공 -> do_iret()로 유저모드로 넘어감(돌아오지X)

	// 	if (process_exec (f_name) < 0)
    // 		PANIC("Fail to launch initd\n");
    // 	NOT_REACHED ();
}






/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
// 🅵 자식 시작에 필요한 정보를 aux 구조체에 담아 두고, 자식 스레드 생성만 -> 부모 대기
struct fork_aux{
	struct thread *parent;              // 부모 스레드 포인터
	struct intr_frame *parent_if;       // 부모 '유저 컨텍스트' 스냅샷 주소
	struct semaphore done;              // 부모-자식 동기화
	bool result;                       // 자식 쪽 복제 성공 여부
	struct child *c;                   // 부모-자식 wait용 노드(부모 children 리스트의 '자식 정보' 포인터)
};

/* Clone current thread to new thread.*/
// return thread_create (name, PRI_DEFAULT, __do_fork, thread_current ());
// 자식프로세스를 fork 하는동안 sema_down 해줘야 됨
// 자식이 __do_fork 에서 fork가 완료되면 sema_up으로 꺠워야 됨

// 🅵 (부모) 자식 스레드 생성 + 부모-자식 연결 + 자식 준비 완료까지 부모 대기
tid_t process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	
	// 1. fork 전달용 aux 구조체 동적 할당
	struct fork_aux *aux = malloc(sizeof *aux);
	if(!aux) return TID_ERROR;         
	
	aux->parent = thread_current();
	aux->parent_if = if_;              // 자식이 그대로 복사해서 시작할 유저 레지스터
	aux->result = false;
	sema_init(&aux->done, 0);

	// 2. 부모가 들고 있을 “자식 정보(child)” 만들기
	struct child *c = malloc(sizeof *c);
	 if (!c) { free(aux); return TID_ERROR; }
     c->tid = TID_ERROR;
     c->exit_status = -1;
     c->load_success = false;
     sema_init(&c->load_sema, 0);
     sema_init(&c->wait_sema, 0);
     c->exited = false;

    /* (레이스 방지) 부모 리스트에 먼저 등록 + 자식에게 포인터 전달 */
    list_push_back(&aux->parent->children, &c->elem);  // 부모 명부에 등록
    aux->c = c;

	// 3. 자식 스레드 생성
	tid_t child_tid = thread_create (name, PRI_DEFAULT, __do_fork, aux);
	if (child_tid == TID_ERROR) {      // 실패
		list_remove(&c->elem);
		free(c);
		free(aux);
		return TID_ERROR;
	}
	c->tid = child_tid;         // 성공: 자식 tid 기록
	
	// 4. 자식 준비 완료까지 부모 대기
    sema_down(&aux->done);    

	// 5. 성공, 실패 분기
	bool result = aux->result;
	free(aux);                                      // aux 메모리 해제
	return result ? child_tid : TID_ERROR;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	/* 1) 커널 VA는 복제 대상 아님 */
    if (is_kernel_vaddr(va)) return true;

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to NEWPAGE. */
	/* 3) 자식용 유저 페이지 할당 */
	newpage = palloc_get_page(PAL_USER);
    if (newpage == NULL) return false;

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	/* 4) 내용 복제 + writable 비트 반영 */
    memcpy(newpage, parent_page, PGSIZE);
    writable = (*pte & PTE_W) != 0;

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		/* 6) 매핑 실패 시 해제 */
        palloc_free_page(newpage);
       return false;
    }
    return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to this function. */
// => parent->tf 시용X, process_fork()의 두 번째 인자(부모 유저 프레임) 사용 필요

// 🅵 (자식) 자식이 “부모의 현재 상태”를 자기 것으로 만듦 -> 부모에게 “준비 끝!”을 알린 뒤 자식으로서 유저모드에 진입
static void __do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *current = thread_current ();
	// /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */


	// 1. aux를 올바른 타입으로 꺼내기
	struct fork_aux *fa = (struct fork_aux *)aux; 
	struct thread *parent = fa->parent;               // 부모 스레드 포인터
	struct intr_frame *parent_if = fa->parent_if;     // 부모 유저 레지스터 스냅샷 주소
	bool succ = true;

	// 2. 부모-자식 연결
	current->as_child = fa->c;     // 부모-자식 wait 핸드셰이크 연결
    current->parent   = parent;    // (권장) 부모 포인터도 세팅
	
	// 3. 자식 시작값을 부모 유저 레지스터 값으로 
	/* 1. Read the cpu context to local stack. */ /*부모 intr_frame 스냅샷을 자식 로컬 if_에 '값 복사'*/
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	if_.R.rax = 0;         // 자식의 fork() 반환값 0으로 만들기

	// 4. 주소공간 복제(메모리)
	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL){
	    //⬇️ 실패 통지 후 부모 깨우고 에러로
		fa->result = false;
		sema_up(&fa->done);
		goto error;
	}
	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt)){
	   // ⬇️ 실패 통지 후 부모 깨우고 에러로
		fa->result = false;
		sema_up(&fa->done);
		goto error;
	}
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent)){
	   // ⬇️ 실패 통지 후 부모 깨우고 에러로
		fa->result = false;
		sema_up(&fa->done);
		goto error;
	}
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/


	// 5. FD Table 복제 (file_duplicate 사용)
	for(int fd = FD_MIN; fd < FD_MAX; fd++){
		struct file *pf = parent->fd_table[fd];      // 부모용 핸들
		if(!pf) {current->fd_table[fd] = NULL; continue;}

		struct file *cf = file_duplicate(pf);       // 자식용 새 핸들 cf
		
		// 실패: 지금까지 꽂은 핸들 닫기
		if (!cf) {
			for (int i = FD_MIN; i < fd; i++) {
				if (current->fd_table[i]) {
					file_close(current->fd_table[i]);
					current->fd_table[i] = NULL;
				}
			}
			fa->result = false;      // 자식 쪽에서 "복제 실패" 표시
			sema_up(&fa->done);      // 부모 깨워서 실패 알림
			goto error;              // 자식 스레드 종료 경로로
		}

		current->fd_table[fd] = cf;     // 성공: 자식 테이블의 같은 칸에 새 핸들을 꽂음
	}

//    /* 🅧 (3) ROX: 실행파일 핸들 복제 + deny-write (부모가 같은 ELF를 실행 중인 경우) */
//     if(parent->running_file){
// 		lock_acquire(&filesys_lock);

// 		current->running_file = file_reopen(parent->running_file);      // 같은 inode를 가리키는 새 file 핸들 생성

// 		if(current->running_file){
// 			file_deny_write(current->running_file);
// 		} 
// 		lock_release(&filesys_lock);
// 	}

	// 6. 부모에게 “복제 끝!” 신호 보내기
	fa->result = true;
    sema_up(&fa->done);

	process_init ();

	// 7. 성공, 실패 분기
	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);     // 자식으로 출발(유저모드 진입)
error:
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec (void *f_name) {
	char *file_name = f_name;               // initd()가 넘겨준 fname(=palloc 페이지)       
	bool success;

	// // (4) 🅧 Rox 이전 실행파일 해제 (exec 전)
	// struct thread *cur = thread_current();
    // if (cur->running_file) {
    //     lock_acquire(&filesys_lock);
    //     file_allow_write(cur->running_file);
    //     file_close(cur->running_file);
    //     lock_release(&filesys_lock);
    //     cur->running_file = NULL;
    // }

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	// 1. 유저모드 진입용 레지스터 세트를 담을 _if 준비
	struct intr_frame _if;               
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;
	
	// 2. 새 유저 주소공간을 위해 기존 커널/스레드 문맥 비우기(돌아갈 곳 사라짐!)
	process_cleanup ();                       

	// 3. 새 프로그램 로드(코드/데이터 매핑, 스택 구성, rip/rsp 채움)
	success = load (file_name, &_if);   


	/* 🚧 4. 부모에게 로드 결과 통지(핸드셰이크) */
    struct thread *cur = thread_current();
    if (cur->as_child) {
       cur->as_child->load_success = success;
       sema_up(&cur->as_child->load_sema);                 //sema_up으로 부모의 sema_down(&load_sema)를 딱 한 번 깨움
    }
    // 🚧

	/* 5-1. 실패 -> 즉시 종료(리턴X) */
	palloc_free_page (file_name);
	if (!success){	    /*  이미 부모에게 load 결과 통지는 위에서 했으니 여기서 바로 종료해도 안전 */
       printf("%s: exit(%d)\n", thread_name(), -1);   // 테스트가 요구하는 출력
       thread_current()->exit_status = -1;            // 종료 코드 기록
       thread_exit();                                 // 실제 종료
       NOT_REACHED();
	// return -1;                                     // 실패하면 return 금지 -> 페이지폴트(이미 주소공간을 지웠으므로 복귀 불가)
}
		
	/* 5-2. 성공: 준비된 레지스터로 유저모드 점프(복귀 없음)*/
	do_iret (&_if);           // 유저모드로 점프(do_iret)
	NOT_REACHED ();           // 성공 시 커널로 돌아오지 않음
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */

// 🚧 부모가 “내 자식 중 child_tid인 애가 끝날 때까지 기다렸다가, 그 애의 종료코드를 받아오는” 함수
int process_wait (tid_t child_tid) {
  struct thread *parent = thread_current();

  /* 부모의 children 리스트에서 child_tid와 매칭되는 노드 찾기 */
  struct child *c = NULL;
  for (struct list_elem *e = list_begin(&parent->children); e != list_end(&parent->children); e = list_next(e)) {
    struct child *x = list_entry(e, struct child, elem);         // 리스트 노드(e)를 우리가 만든 struct child 구조체로 변환
    if (x->tid == child_tid) { c = x; break; }                    // 찾던 자식이 맞으면 c에 잡고 루프 종료
  }
  if (!c) return -1;           // 실패: -1

  /* 자식 종료 대기(이미 종료면 즉시 통과) */
  sema_down(&c->wait_sema);                        // 자식이 끝났다는 신호(세마포어 up)를 기다림
  int status = c->exit_status;                    

  /* 리스트에서 자식 제거 후 해제 */
  list_remove(&c->elem);          
  free(c);

  return status;                         // 자식의 종료코드를 부모에게 돌려줌
}


/* 자식(현재 스레드)이 “나 이제 끝난다”를 부모에게 알려주는 곳. */
void process_exit (void) {
	struct thread *curr = thread_current ();              //지금 끝나려고 하는 스레드(= 자식)
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	 /* 🚧 부모에게 종료 알림 */
    if (curr->as_child) {                                     // 핸드셰이크 존재O
		curr->as_child->exit_status = curr->exit_status;      // 데이터 쓰기: “내 종료코드”를 부모의 노드에 저장
        curr->as_child->exited = true;                        // 상태 플래그(참고용)
        sema_up(&curr->as_child->wait_sema);                  // 시그널 보내기: 부모가 sema_down()에서 기다리는 걸 깨움
    }
    
    // 🅧 (2) 실행 파일 rox 해제 + 닫기
	// if(curr->running_file){
	// 	lock_acquire(&filesys_lock);
	// 	file_allow_write(curr->running_file);    // deny 카운터 -1
	// 	file_close(curr->running_file);          // 핸들 달기
	// 	lock_release(&filesys_lock);
	// 	curr->running_file = NULL;
	// }

    // 🆂 FD테이블 일괄 정리
	for (int fd = FD_MIN; fd < FD_MAX; fd++){
		if(curr->fd_table[fd]) sys_close(fd);
	}
	    
	process_cleanup ();                        // 정리
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
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
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

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

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */

// 🅰️ load(): 커널 모드에서 “해당 프로세스의 유저 주소공간을 새로 만들고 채우는” 함수
static bool load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* 페이지 테이블 준비(주소 공간 만들기) */
	t->pml4 = pml4_create ();                               // 맨 위 레벨(PML4) 테이블 하나를 새로 할당, 초기화 => 새 유저 주소공간(pml4) 생성
	if (t->pml4 == NULL) goto done;                         // 예외 처리(메모리 부족)
	
	process_activate (thread_current ());                   // 지금부터 이 테이블 사용하라고 CPU에 통보 => 이후의 install_page()들이 이 주소공간에 매핑되도록 보장

	// 🅰️ 1. 토큰화 블록(프로그램명/인자 분리)

	// 0) 필요 함수 선언
    char *argv_kern[MAX_ARGC];       // 각 토큰의 시작 주소 포인터들 임시 저장 배열(커널 메모리에 존재)
    int argc = 0;                    // 인자 개수 카운터

    char * cmdline = NULL;
    char *prog_name = NULL;          // 첫 토큰(= 실행 파일 이름)
    char *saveptr = NULL;            // strtok_r()의 상태 저장용 포인터

	// 1) 수정 가능 복사본 확보
	cmdline = palloc_get_page(0);           // 커널 힙에서 한 페이지(4KB) 할당
	if(!cmdline) goto done;                       // 예외처리(메모리 부족)

	if(strnlen(file_name, PGSIZE) >= PGSIZE) goto done;    // 예외처리(페이지 크기 이상)

	strlcpy(cmdline, file_name, PGSIZE);                   // 커널 페이지 cmdline으로 안전 복사(항상 NULL 종료 보장)

	// 2-1) 첫 토큰: 프로그램명
	prog_name = strtok_r(cmdline, " \t\r\n", &saveptr);

	if(!prog_name) goto done;                            // 예외처리

	// 2-2) argv[0]에 프로그램명 저장(문자열 시작 주소)
	argv_kern[argc++] = prog_name;

	// 3) 나머지 인자 수집
	for(char *tok = strtok_r(NULL, " \t\r\n", &saveptr); tok != NULL && argc < MAX_ARGC; tok = strtok_r(NULL, " \t\r\n", &saveptr)){
		argv_kern[argc++] = tok;
	}

	// 4) file_name 재지정
	file_name = prog_name;                // 첫 토큰(프로그램 이름)

	/* 실행 파일 오픈*/
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* ELF 헤더 읽고 검증(정상 실행 파일인지 확인) */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* ELF 프로그램 헤더(Program Header) 읽기 -> 메모리에 필요한 세그먼트만 올리기 */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
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
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* 스택 페이지 생성 */
	if (!setup_stack (if_)) goto done;

	/* ELF 헤더에서 읽은 프로그램 진입 주소를 저장 */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	// 🅰️ 2. 스택 포장 + 레지스터 세팅
	// 1) 준비
	uint8_t *rsp    = (uint8_t *) if_->rsp;                 // setup_stack이 준 USER_STACK의 꼭대기
    uint8_t *bottom = (uint8_t *) USER_STACK - PGSIZE;      // 페이지의 바닥(낮은 주소)

    void *uaddr[MAX_ARGC];   // 유저 스택에 실제로 복사된 인자 문자열들의 시작 주소

	#define WOULD_UNDERFLOW(nbytes) ((rsp) < ((bottom) + (nbytes)))

	// 2) 문자열 “실물”을 마지막 인자부터 복사 + 복사된 유저 주소 기록 
	for(i = argc-1; i >= 0; --i){
		size_t len = strlen(argv_kern[i]) +1 ;

		if(WOULD_UNDERFLOW(len))  goto done;
		
		rsp -= len;
		memcpy(rsp, argv_kern[i], len);
		uaddr[i] = (void *)rsp;
	}

	// 3) 8 바이트 정렬 보장
	size_t mis = (size_t)((uintptr_t)rsp % 8);         // 8으로 나눈 나머지(이유: 포인터가 바이트)
	if (mis) {
		if (WOULD_UNDERFLOW(mis)) goto done;
		
        rsp -= mis;                                    // rsp 주소 부족한만큼 내리기
		memset(rsp, 0, mis);                           // 패딩
    }

	// 4) NULL sentinel 삽입
	if (WOULD_UNDERFLOW(sizeof(char*))) goto done;

    rsp -= sizeof(char *);                          // 8바이트 내림
    *(char **)rsp = NULL;                           // 해당 자리에 0(널 포인터) 삽입

    /// 5) argv[i] 포인터들(역순으로 푸시: 마지막 → 첫 번째)
	for (int i = argc - 1; i >= 0; i--) {
		if (WOULD_UNDERFLOW(sizeof(char*)))  goto done;
		
		rsp -= sizeof(char *);      // 자리 확보
        *(void **)rsp = uaddr[i];   // 방금 복사된 “유저” 문자열 주소
    }
		 
    void *argv_user = (void *)rsp;   // 이 시점의 rsp가 곧 argv(char**)의 시작 주소

	// 6) argv, argc, fake return 0 차례로 푸시 
	/*  argv 자체 포인터 푸시 (char** = 포인터 배열 시작 주소) */
    // if (WOULD_UNDERFLOW(sizeof(void*))) goto done;
    // rsp -= sizeof(void*);
    // *(void **)rsp = argv_user;   // 방금 만든 포인터 배열 블록의 시작 주소

    // /*  argc 푸시 (정수 8바이트) */
    // if (WOULD_UNDERFLOW(sizeof(uint64_t))) goto done;
    // rsp -= sizeof(uint64_t);
    // *(uint64_t *)rsp = (uint64_t)argc;

    /*  6) fake return address (0) 푸시 */
    if ((WOULD_UNDERFLOW(sizeof(uint64_t)))) goto done;
    rsp -= sizeof(uint64_t);
    *(uint64_t *)rsp = 0;  
	
	// 7) 최종 레지스터/스택포인터 세팅
	if_->rsp = (uint64_t)rsp;
	
	// 인자 레지스터는 R 묶음 안에 있음
    if_->R.rdi = (uint64_t)argc;
    if_->R.rsi = (uint64_t)argv_user;

	#undef WOULD_UNDERFLOW

	success = true;

	/* 🅧 (1) 성공: 실행 파일 핸들 보관 + 쓰기 금지(ROX) */
    t->running_file = file;
    file_deny_write(file);

    goto done;

done:
	// /* We arrive here whether the load is successful or not. */
	// if (file) file_close(file);             // 파일은 열렸을 때만 닫기
    // if (cmdline) palloc_free_page(cmdline); // 페이지는 할당됐을 때만 해제
    // return success;
	  /* 실패면 닫고, 성공이면 thread->running_file로 들고 감 */
    if (!success && file) {
       file_close(file);
    //    t->running_file = NULL;
    }
    if (cmdline) palloc_free_page(cmdline);
    return success;

}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

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
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
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
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
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
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
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
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
