#include <unistd.h>
#include <sys/ptrace.h>


#define PTRACE_ALTSTACK_NONE	0
#define PTRACE_ALTSTACK_ORIG	1
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
