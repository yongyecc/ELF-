#include "stdio.h"
#include <elf.h>
#include "rebuild.h"



void main(int argc, char* argv[]){

	int pid;
	char* name;
	if(argc < 2){
		printf("Usage: ./rebuild <args> <pid> <dumpelf>\n\n");
		printf("\t./rebuild -p <pid> <filename>\t");
	}else if(argc ==4  && argv[1] == "-p"){
		pid = atoi(argv[2]);
		name = argv[3];
		PDump2ELF(pid, name);
	}
}

int PDump2ELF(int pid, char *name)
{
	struct ptrace_context *ptc;
	uint8_t *pmem;
	long w;
	Elf32_Addr BaseVaddr, index_vaddr = 0, got;
	Elf32_Ehdr ehdr;
	Elf32_Phdr *phdr;
	struct pt_load pt_load;
	Elf32_Shdr shdr;
	uint32_t totlen;
	Elf32_Sym  *symtab;
	Elf32_Addr dynvaddr, interp_vaddr;
	Elf32_Off dynoffset, interp_off;
	uint32_t dynsize, interp_size;
	int TS, DS, i, j, fd, bss_len = 0, found_loadables = 0;

	//跟踪pid进程，并将其作为子进程进入中止状态
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
		printf("[-] Attach pid : %d failed", pid);
		return -1;
	}
	ptc->tid = pid;
	ptc->stack.flags = PTRACE_ALTSTACK_ORIG;

	//在 32 位系统中，默认的 text 虚拟地址为 0x08048000
	//使用ptrace读取ELF文件头结构到ehdr
	BaseVaddr = 0x8048000;
	size_t quot = sizeof(Elf32_Ehdr) / sizeof(void *);
	unsigned char *s = (unsigned char *) BaseVaddr;
	void* elfheader;
	elfheader = &ehdr;
	printf("aaaa%d", ptc->tid);
	while (quot-- != 0) {
		if(w = (ptrace(PTRACE_PEEKDATA, ptc->tid, s, NULL)) == -1){
			printf("[-]  : %d failed", pid);
	        return -1;
		}
		unsigned char *d = (unsigned char *) elfheader;
		*((long *)elfheader) = w;

		s += sizeof(long);
		elfheader += sizeof(long);
	}
	//分配栈空间,返回一个指向这个空间开始的指针
	//将文件头和所有程序头表读取到pmem地址处
	pmem = alloca(sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) + 0x100);
	size_t phslen = sizeof(Elf32_Ehdr) + ehdr.e_phentsize * ehdr.e_phnum;
	while (phslen-- != 0) {
        if(w = (ptrace(PTRACE_PEEKDATA, ptc->tid, s, NULL)) == -1){
            printf("[-]  : %d failed", pid);
            return -1;
        }
        unsigned char *d = (unsigned char *) pmem;
        *((long *)pmem) = w;

        s += sizeof(long);
        pmem += sizeof(long);
    }

	printf("[+] Beginning analysis for executable reconstruction of process image (pid: %d)\n", pid);
	printf("[+] Getting Loadable segment info...\n");
	//程序头表指针
	phdr = (Elf32_Phdr *)(pmem + ehdr.e_phoff);
	//遍历每个程序头表的条目
	//定位到text段、data段、bss节长度、动态段、动态链接器位置
	for(i=0; i<ehdr.e_phnum; i++)
	{
		//text段偏移为0
		if (phdr[i].p_type == PT_LOAD && !phdr[i].p_offset)
		{
			printf("[+] Found loadable segments: text segment, data segment\n");

			/* text段 */
			pt_load.text_offset = phdr[i].p_offset;
			pt_load.text_filesz = phdr[i].p_filesz;
			/* data段**/
			pt_load.data_offset = phdr[i + 1].p_offset;
			pt_load.data_filesz = phdr[i + 1].p_filesz;
			pt_load.data_vaddr =  phdr[i + 1].p_vaddr;
			
			//.bss节长度（程序加载进内存时才会被初始化为0）
			bss_len = phdr[i + 1].p_memsz - phdr[i + 1].p_filesz;
			TS = i;
			DS = i + 1;
		}
		else if(phdr[i].p_type == PT_DYNAMIC)
		{
			dynvaddr = phdr[i].p_vaddr;
			dynoffset = phdr[i].p_offset;
			dynsize = phdr[i].p_filesz;
		}
		/*动态链接器的位置*/
		else if(phdr[i].p_type == PT_INTERP)
		{
			interp_vaddr = phdr[i].p_vaddr;
			interp_off = phdr[i].p_offset;
			interp_size = phdr[i].p_filesz;
		}
	/* text段和data段的总长度 */
	totlen = (pt_load.data_offset + pt_load.data_filesz);
	pmem = alloca(totlen);

	}
}
