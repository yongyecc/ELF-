#include <unistd.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>


#define PTRACE_ERR_NONE			0	/* No error */
#define PTRACE_ERR_EXITED		1	/* Remote process exited */
#define PTRACE_ERR_PAGESIZE		2	/* Unsuitable page size */
#define PTRACE_ERR_ALTSTACK_ORIG	3	/* Original stack error */
#define PTRACE_ERR_ALTSTACK_INUSE	4	/* Stack currently in use */

/* libtrace error flags
 *  *
 *   * PTRACE_ERR_FLAG_REMOTE	Specifies an error occured in the remote process.
 *    * PTRACE_ERR_FLAG_EXTERNAL	Specifies the error is not an libptrace internal error.
 *     */
#define PTRACE_ERR_FLAG_NONE		0
#define PTRACE_ERR_FLAG_REMOTE		1
#define PTRACE_ERR_FLAG_EXTERNAL	2

#define PTRACE_ALTSTACK_NONE	0
#define PTRACE_ALTSTACK_ORIG	1
#define PTRACE_ERR_SET_EXTERNAL(p)					\
	do {								\
		p->error.external = errno;				\
		p->error.internal = PTRACE_ERR_NONE;			\
		p->error.flags = PTRACE_ERR_FLAG_EXTERNAL;		\
	} while(0)

#define PTRACE_ERR_SET_INTERNAL(p, e)					\
	do {								\
		p->error.external = 0;					\
		p->error.internal = e;					\
		p->error.flags = PTRACE_ERR_FLAG_NONE;			\
	} while(0)
#define PTRACE_ERR_CLEAR(p)						\
	do {								\
		p->error.external = 0;					\
		p->error.internal = PTRACE_ERR_NONE;			\
		p->error.flags = PTRACE_ERR_FLAG_NONE;			\
	} while(0)

typedef uint64_t ptrace_x86_register_t;

struct pt_load
{
	uint32_t text_filesz;
	uint32_t text_memsz;
	uint32_t text_offset;
	uint32_t text_vaddr;
	
	uint32_t data_filesz;
	uint32_t data_memsz;
	uint32_t data_offset;
	uint32_t data_vaddr;
};

struct ptrace_error
{
    int internal:24;
    int flags:8;

    int external;
    char    *errmsg;
};

struct ptrace_altstack {
    void            *base;
    size_t          size;
    ptrace_x86_register_t   stack_ptr;
    ptrace_x86_register_t   base_ptr;
    unsigned int        flags;
};

typedef pid_t	ptrace_pid_t;

struct ptrace_context
{
	int state;
	ptrace_pid_t tid;
	struct ptrace_error error;
	struct ptrace_altstack stack;
};

