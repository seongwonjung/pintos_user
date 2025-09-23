#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"
void syscall_init(void);
/* 전방 선언 */
struct thread;
struct file;

extern struct lock filesys_lock;
void sys_exit_with_error();
int fd_alloc(struct thread *t, struct file *f);
void fd_close(struct thread *f, int fd);

#endif /* userprog/syscall.h */
