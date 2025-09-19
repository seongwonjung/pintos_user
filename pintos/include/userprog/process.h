#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

// process.h 맨 아래쪽(헤더가드 내부)쯤에 추가
#include "threads/thread.h"   // tid_t
#include "threads/synch.h"    // struct semaphore
#include "lib/kernel/list.h"  // struct list_elem

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
struct child* find_child(struct list* child, tid_t tid);

struct child {
    tid_t tid;                 // 자식 TID
    int   exit_status;         // 종료 코드
    bool  exited;              // 종료 완료?
    bool  waited;              // 이미 wait 했는가?
    struct semaphore sema;     // 부모 대기용 세마포어
    struct list_elem elem;     // 부모 children 리스트에 연결
};


#endif /* userprog/process.h */



