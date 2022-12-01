#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void halt (void);
void exit (int status);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);

void get_argvs (struct intr_frame *f, int *argv[], int argc);

struct lock f_lock;

void
syscall_init (void)
{
  lock_init(&f_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int code = *(int*)f->esp;
  printf("syscall code = %d\n", code);

  int *argv[3];

  switch (code) {
    case SYS_HALT:
      printf("halt syscall\n");
      halt();
      break;
    case SYS_EXIT:
      printf("exit syscall\n");
      get_argvs(f, argv, 1);
      exit(*(int*)argv[0]);
      break;
    case SYS_EXEC:
      printf("execute syscall\n");
      break;
    case SYS_WAIT:
      printf("wait syscall\n");
      break;
    case SYS_CREATE:
      printf("create syscall\n");
      get_argvs(f, argv, 2);
      f->eax = create((const char*)argv[0], *(unsigned*)argv[1]);
      break;
    case SYS_REMOVE:
      printf("remove syscall\n");
      get_argvs(f, argv, 1);
      f->eax = remove((const char*)argv[0]);
      break;
    case SYS_OPEN:
      printf("open syscall\n");
      break;
    case SYS_FILESIZE:
      printf("filesize syscall\n");
      break;
    case SYS_READ:
      printf("read syscall\n");
      get_argvs(f, argv, 3);
      f->eax = read(*(int*)argv[0], (void*)*argv[1], *(unsigned*)argv[2]);
      break;
    case SYS_WRITE:
      printf("write syscall\n");
      get_argvs(f, argv, 3);
      f->eax = write(*(int*)argv[0], (const void*)*argv[1], *(unsigned*)argv[2]);
      break;
    case SYS_SEEK:
      printf("seek syscall\n");
      break;
    case SYS_TELL:
      printf("tell syscall\n");
      break;
    case SYS_CLOSE:
      printf("close syscall\n");
      break;
    default:
      printf("default syscall, syscall code = %d\n", code);
      break;
  }
  printf("\nEnd of syscall\n");

  thread_exit ();
}


void
halt (void)
{
  shutdown_power_off();
}


void
exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  printf("%s: exit_code(%d)\n", cur->name, status);
  thread_exit();
}


bool
create (const char *file, unsigned initial_size)
{
  lock_acquire(&f_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&f_lock);
  return success;
}


bool
remove (const char *file)
{
  if (file == NULL)
    return -1;

  lock_acquire(&f_lock);
  bool success = filesys_remove(file);
  lock_release(&f_lock);
  return success;
}


int
read (int fd, void *buffer, unsigned size)
{
  //validate address
  if (!is_user_vaddr(buffer)){
    printf("Invalid buffer pointer: %p\n", buffer);
    return -1;
  }
  printf("fd = %d, buffer = %s, size = %d\n", fd, (char*)buffer, size);

  int bytes = 0;

  lock_acquire(&f_lock);

  // if fd is 0 (STDIN)
  if (fd == 0){
    unsigned i;
    for (i = 0; i < size; i++){
      *((char *)buffer + i) = input_getc();
    }
    bytes = i;
  }
  else {
    struct thread *cur = thread_current();
    struct list_elem *e;
    struct file_desc *f_desc = NULL;

    // search through file list of current thread to find fd
    for (e=list_begin(&cur->file_list); e!=list_end(&cur->file_list); e=list_next(e)){
      struct file_desc *file_d = list_entry(e, struct file_desc, elem);
      if (file_d->fd == fd){
        f_desc = file_d;
      }
    }
    if (f_desc == NULL)
      lock_release(&f_lock);
      return -1;

    bytes = file_read(f_desc->f, buffer, size);
  }

  lock_release(&f_lock);
  printf("Bytes = %d\n", bytes);
  return bytes;
}


int
write (int fd, const void *buffer, unsigned size)
{
  //validate address
  if (!is_user_vaddr(buffer)){
    printf("Invalid buffer pointer: %p\n", buffer);
    return -1;
  }

  printf("fd = %d, buffer = %s, size = %d\n", fd, (char*)buffer, size);
  int bytes = 0;

  lock_acquire(&f_lock);

  // if fd is 1 (STDOUT)
  if (fd == 1){
    int size_left = (int)size;
    while (size_left > 128){
      putbuf(buffer, 128);
      size_left -= 128;
    }
    putbuf(buffer, size_left);
    bytes = size;
  }
  else {
    struct thread *cur = thread_current();
    struct list_elem *e;
    struct file_desc *f_desc = NULL;

    // search through file list to find fd
    for (e=list_begin(&cur->file_list); e!=list_end(&cur->file_list); e=list_next(e)){
      struct file_desc *file_d = list_entry(e, struct file_desc, elem);
      if (file_d->fd == fd){
        f_desc = file_d;
      }
    }
    if (f_desc == NULL)
      lock_release(&f_lock);
      return -1;

    bytes = file_write(f_desc->f, buffer, size);
  }

  lock_release(&f_lock);

  return bytes;
}


// gets stack arguments and adds them to the argv list
void
get_argvs (struct intr_frame *f, int *argv[], int argc)
{
  int *ptr;
  for (int i = 0; i < argc; i++){
    ptr = (int*)f->esp + (1 + (i*1));
    argv[i] = ptr;
  }
}
