#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
struct thread;
struct file;

int fd_alloc(struct thread *t, struct file *f);
void fd_close(struct thread *f, int fd);

#endif /* userprog/syscall.h */
