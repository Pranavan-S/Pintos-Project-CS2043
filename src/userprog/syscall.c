#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define MAX_ARGS 3



static void syscall_handler (struct intr_frame *);
int add_file (struct file *file_name);
void get_args (struct intr_frame *f, int *arg, int num_of_args);
void syscall_halt (void);
pid_t syscall_exec(const char* cmdline);
int syscall_wait(pid_t pid);
bool syscall_create(const char* file_name, unsigned starting_size);
bool syscall_remove(const char* file_name);
int syscall_open(const char * file_name);
int syscall_filesize(int filedes);
int syscall_read(int filedes, void *buffer, unsigned length);
int syscall_write (int filedes, const void * buffer, unsigned byte_size);
void syscall_seek (int filedes, unsigned new_position);
unsigned syscall_tell(int fildes);
void syscall_close(int filedes);
void validate_str (const void* str);
void validate_buffer (const void* buf, unsigned byte_size);

bool FILE_LOCK_INIT = false;

/*
 * System call initializer
 * It handles the set up for system call operations.
 */
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*function triggers respective action based for the given system command*/
static void 
syscall_handler(struct intr_frame *f UNUSED) {
    if (!FILE_LOCK_INIT) {
        lock_init(&filesys_lock);
        FILE_LOCK_INIT = true;
    }

    int arg[MAX_ARGS];
    int esp = getpage_ptr((const void *)f->esp);

    int syscall_number = *((int *)esp);

    if (syscall_number == SYS_HALT) {
        // Halt the operating system.
        syscall_halt();
    } else if (syscall_number == SYS_EXIT) {
        // Get the exit status and terminate the current user program.
        get_args(f, &arg[0], 1);
        syscall_exit(arg[0]);
    } else if (syscall_number == SYS_EXEC) {
        // Execute a new process.
        get_args(f, &arg[0], 1);
        validate_str((const void *)arg[0]);
        arg[0] = getpage_ptr((const void *)arg[0]);
        f->eax = syscall_exec((const char *)arg[0]);
    } else if (syscall_number == SYS_FILESIZE) {
        // Obtain the size of a file.
        get_args(f, &arg[0], 1);
        f->eax = syscall_filesize(arg[0]);
    } else if (syscall_number == SYS_WAIT) {
        // Wait for a child process to terminate.
        get_args(f, &arg[0], 1);
        f->eax = syscall_wait(arg[0]);
    } else if (syscall_number == SYS_OPEN) {
        // Open a file.
        get_args(f, &arg[0], 1);
        validate_str((const void *)arg[0]);
        arg[0] = getpage_ptr((const void *)arg[0]);
        f->eax = syscall_open((const char *)arg[0]);
    } else if (syscall_number == SYS_WRITE) {
        // Write to a file descriptor from a buffer.
        get_args(f, &arg[0], 3);
        validate_buffer((const void *)arg[1], (unsigned)arg[2]);
        arg[1] = getpage_ptr((const void *)arg[1]);
        f->eax = syscall_write(arg[0], (const void *)arg[1], (unsigned)arg[2]);
    } else if (syscall_number == SYS_TELL) {
        // Return the position of the next byte to be read or written in an open file.
        get_args(f, &arg[0], 1);
        f->eax = syscall_tell(arg[0]);
    } else if (syscall_number == SYS_READ) {
        // Read from a file descriptor into a buffer.
        get_args(f, &arg[0], 3);
        validate_buffer((const void *)arg[1], (unsigned)arg[2]);
        arg[1] = getpage_ptr((const void *)arg[1]);
        f->eax = syscall_read(arg[0], (void *)arg[1], (unsigned)arg[2]);
    } else if (syscall_number == SYS_SEEK) {
        // Change the next byte to be read or written in an open file.
        get_args(f, &arg[0], 2);
        syscall_seek(arg[0], (unsigned)arg[1]);
    } else if (syscall_number == SYS_CREATE) {
        // Create a new file.
        get_args(f, &arg[0], 2);
        validate_str((const void *)arg[0]);
        arg[0] = getpage_ptr((const void *)arg[0]);
        f->eax = syscall_create((const char *)arg[0], (unsigned)arg[1]);
    } else if (syscall_number == SYS_REMOVE) {
        // Remove a file.
        get_args(f, &arg[0], 1);
        validate_str((const void *)arg[0]);
        arg[0] = getpage_ptr((const void *)arg[0]);
        f->eax = syscall_remove((const char *)arg[0]);
    }else if (syscall_number == SYS_CLOSE) {
        // Close a file descriptor.
        get_args(f, &arg[0], 1);
        syscall_close(arg[0]);
    } else {
        // Invalid system call number.
    }
}
/*SYSTEM CALLS RELATED TO FILE SYSTEM MANAGEMENT------------------------------------------------------------------------------------------------------------*/


/*
step 1: acquire file system lock
step 2: do the work
step 3: release file system lock
step 4: return

*/


// system call for file creation
bool
syscall_create(const char* file_name, unsigned starting_size){
  lock_acquire(&filesys_lock);
  bool successful = filesys_create(file_name, starting_size);
  lock_release(&filesys_lock);
  return successful;
}

// system call for opeing file
int
syscall_open(const char *file_name){
  struct file *f_ptr;
  lock_acquire(&filesys_lock);
  f_ptr = filesys_open(file_name); 
  if (!f_ptr){
    lock_release(&filesys_lock);
    return ERROR;
  }
  int filedes = add_file(f_ptr);
  lock_release(&filesys_lock);
  return filedes;
}

// system call for reading file
int
syscall_read(int filedes, void *buffer, unsigned length){
  uint8_t *local_buffer;
  if (length <= 0){
    return length;
  }
  
  if (filedes == STANDARD_INPUT){
    unsigned i = 0;
    local_buffer = (uint8_t *) buffer;
    for (;i < length; i++){
      // retrieve pressed key from the input buffer
      local_buffer[i] = input_getc(); 
    }
    return length;
  }
  
  struct file *f_ptr;
  lock_acquire(&filesys_lock);
  f_ptr = get_file(filedes);
  if (!f_ptr){
    lock_release(&filesys_lock);
    return ERROR;
  }
  int bytes_read = file_read(f_ptr, buffer, length); 
  lock_release (&filesys_lock);
  return bytes_read;
}

// system call for writing file
int 
syscall_write (int filedes, const void * buffer, unsigned byte_size){
    if (byte_size <= 0){
      return byte_size;
    }
    if (filedes == STANDARD_OUTPUT){
      putbuf (buffer, byte_size); 
      return byte_size;
    }
    
    struct file *f_ptr;
    lock_acquire(&filesys_lock);
    f_ptr = get_file(filedes);
    if (!f_ptr){
      lock_release(&filesys_lock);
      return ERROR;
    }
    // need to return no of bytes written
    int bytes_count = file_write(f_ptr, buffer, byte_size); 
    lock_release (&filesys_lock);
    return bytes_count;
}

// system call for get the file size,
int
syscall_filesize(int filedes){
  struct file *f_ptr;
  lock_acquire(&filesys_lock);
  f_ptr = filesys_open((const char *)filedes);
  if (!f_ptr){
    lock_release(&filesys_lock);
    return ERROR;
  }
  int filesize = file_length(f_ptr); 
  lock_release(&filesys_lock);
  return filesize;
}

// system call for changing the current position in a file
void
syscall_seek (int filedes, unsigned new_position){
  struct file *f_ptr;
  lock_acquire(&filesys_lock);
  f_ptr = get_file(filedes);
  if (!f_ptr){
    lock_release(&filesys_lock);
    return;
  }
  file_seek(f_ptr, new_position);
  lock_release(&filesys_lock);
}

// system call for getting the offset of new position from current position 
unsigned
syscall_tell(int filedes){
  struct file *f_ptr;
  lock_acquire(&filesys_lock);
  f_ptr = get_file(filedes);
  if (!f_ptr){
    lock_release(&filesys_lock);
    return ERROR;
  }
  off_t offset = file_tell(f_ptr);
  lock_release(&filesys_lock);
  return offset;
}

// system call for closing the file
void
syscall_close(int filedes){
  lock_acquire(&filesys_lock);
  process_close_file(filedes);
  lock_release(&filesys_lock);
}

// system call for file removal
bool
syscall_remove(const char* file_name){
  lock_acquire(&filesys_lock);
  bool successful = filesys_remove(file_name); 
  lock_release(&filesys_lock);
  return successful;
}

// include file in file_list and return file descriptor of the file
int
add_file (struct file *file_name){
  struct process_file *process_f_ptr = malloc(sizeof(struct process_file));
  if (!process_f_ptr){
    return ERROR;
  }
  process_f_ptr->file = file_name;
  process_f_ptr->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back(&thread_current()->file_list, &process_f_ptr->elem);
  return process_f_ptr->fd;
  
}

// retrieve file with given file descriptor */
struct file*
get_file (int filedes){
  struct thread *t = thread_current();
  struct list_elem* next;
  struct list_elem* e = list_begin(&t->file_list);
  
  while (e != list_end(&t->file_list)) {
    next = list_next(e);
    struct process_file *process_f_ptr = list_entry(e, struct process_file, elem);
    if (filedes == process_f_ptr->fd) {
      return process_f_ptr->file;
    }
    e = next;
  }
  // not found
  return NULL;
}


// close file with given file descriptor
void
process_close_file (int file_descriptor){
  struct thread *t = thread_current();
  struct list_elem *next;
  struct process_file *process_f_ptr;
  struct list_elem *e = list_begin(&t->file_list);
  
  while (e != list_end(&t->file_list)) {
    next = list_next(e);
    process_f_ptr = list_entry(e, struct process_file, elem);
    if (file_descriptor == process_f_ptr->fd || file_descriptor == CLOSE_ALL_FD) {
        file_close(process_f_ptr->file);
        list_remove(&process_f_ptr->elem);
        free(process_f_ptr);
        if (file_descriptor != CLOSE_ALL_FD) {
            return;
        }
    }
    e = next;
  }
}
//-----------------------------------------------------------------------------------------------------------------------------------------------------------
// shutdown the system
void
syscall_halt (void){
  shutdown_power_off(); // from shutdown.h
}

//pop args from stack
void
get_args (struct intr_frame *f, int *args, int num_of_args){
  int i;
  int *ptr;
  for (i = 0; i < num_of_args; i++){
    ptr = (int *) f->esp + i + 1;
    const void* vaddr = (const void *) ptr;
    if (vaddr < USER_VIRTUAL_ADDRESS_LIMIT || !is_user_vaddr(vaddr)){
      syscall_exit(ERROR);
    }
    args[i] = *ptr;
  }
}

// exit system call
void
syscall_exit (int status){
  struct thread *t;
  //Verifies whether the current thread to exit is a child process.
  //if it is, then it updates the relevant parent information for the child process.
  t = thread_current();
  if (is_thread_alive(t->parent) && t->cp){
    if (status < 0){
      status = -1;
    }
    t->cp->status = status;
  }
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

// system call for execution
pid_t
syscall_exec(const char* cmdline){   
    // executes the given cmd line and returns the pid of executing thread
    struct child_process *cp_ptr;
    pid_t pid = process_execute(cmdline);
    cp_ptr = find_child_process(pid);
    if (!cp_ptr){
      return ERROR;
    }
    // not loaded
    if (cp_ptr->load_status == NOT_LOADED){
      sema_down(&cp_ptr->load_sema);
    }

    // load failed
    if (cp_ptr->load_status == LOAD_FAIL){
      remove_child_process(cp_ptr);
      return ERROR;
    }
    return pid;
}

// system call for make process to wait
int
syscall_wait(pid_t pid){
  return process_wait(pid);
}


// string validation
void
validate_str (const void* str){    
    char* curr_char = (char*) getpage_ptr(str);
    while(*curr_char != 0){
      str = (char*) str + 1;
      curr_char = (char*) getpage_ptr(str);
    }
}

// buffer validation
void
validate_buffer(const void* buf, unsigned byte_size){
  char* local_buffer;
  unsigned itr = 0;

  local_buffer = (char*)buf;
  while (itr < byte_size) {
    if ((void *)local_buffer < USER_VIRTUAL_ADDRESS_LIMIT || !is_user_vaddr(local_buffer)){
      syscall_exit(ERROR);
    }
    local_buffer++;
    itr++;
  }
}

// retrieve the mem_addr corresponding to the page
int
getpage_ptr(const void *vaddr){
  struct thread * t = thread_current();
  void *ptr = pagedir_get_page(t->pagedir, vaddr);// need to fix
  if (!ptr){
    syscall_exit(ERROR);
  }
  return (int)ptr;
}

// locating child process using pid
struct child_process* find_child_process(int pid){
  struct thread *t = thread_current();
  struct list_elem *e;
  struct list_elem *next;
  
  for (e = list_begin(&t->child_list); e != list_end(&t->child_list); e = next){
    next = list_next(e);
    struct child_process *cp = list_entry(e, struct child_process, elem);
    if (pid == cp->pid){
      return cp;
    }
  }
  return NULL;
}

// delete child process
void
remove_child_process (struct child_process *cp){
  list_remove(&cp->elem);
  // free the memory
  free(cp);
}

// delete all child_process
void remove_all_child_processes (void) {
  struct thread *t = thread_current();
  struct list_elem *next;
  struct child_process * cp;
  struct list_elem *e = list_begin(&t->child_list);
  
  // loop through child_list and remove each child
  while (e != list_end(&t->child_list)) {
    next = list_next(e);
    cp = list_entry(e, struct child_process, elem);
    list_remove(&cp->elem); 
    free(cp); // free the memory
    e = next;
  }
}


