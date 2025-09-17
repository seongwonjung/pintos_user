#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"      // 🚧 세마포어 실제크기 확인

// 🚧
/* 부모가 자식의 종료/로드 상태를 기다리기 위한 노드 */
struct child {
  tid_t tid;                   // 부모가 이 노드를 어떤 자식과 매칭할지 식별하는 키
  int exit_status;             // 자식이 sys_exit(status)로 종료할 때 넘겨준 상태 코드를 저장

  /* 부모-자식 신호 주고받기 */
  struct semaphore load_sema;   // load 성공/실패 부모에게 통지
  bool load_success;            // 결과 값 저장소

  struct semaphore wait_sema;   /* 자식 종료 통지 (현재 1회용) */
  bool exited;                   // 자식 종료 여부 기록

  struct list_elem elem;        /* 부모 children 리스트용 (지금은 1개만 씀) */
};
// 🚧


tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

 
#endif /* userprog/process.h */
