#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

void syscall_init (void);

struct file_desc
{
  int fd;
  struct file *f;
  struct list_elem elem;
};

#endif /* userprog/syscall.h */
