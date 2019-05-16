#include "stdio.h"
#include <elf.h>
#include "rebuild.h"
#include <alloca.h>
#include <assert.h>


void main(int argc, char* argv[]){

	int pid;
	char* name;
	if(argc < 2){
		printf("Usage: ./rebuild <args> <pid> <dumpelf>\n\n");
		printf("\t./rebuild -p <pid> <filename>\t\n");
	}else if(argc > 2 && strcmp(argv[1], "-p")==0){
		pid = atoi(argv[2]);
		name = argv[3];
		PDump2ELF(pid, name);
	}
}

int PDump2ELF(int pid, char *name)
{
	struct ptrace_context ptc;
	struct ptrace_context *p;
	uint8_t *pmem;
	long w;
	Elf32_Addr BaseVaddr, index_vaddr = 0, got;
	Elf32_Ehdr ehdr, *ep;
	Elf32_Phdr *phdr;
	Elf32_Dyn *dyn;
	struct pt_load pt_load;
	Elf32_Shdr shdr;
	uint32_t totlen;
	Elf32_Sym  *symtab;
	Elf32_Addr dynvaddr, interp_vaddr;
	Elf32_Off dynoffset, interp_off;
	Elf32_Off got_off;
	Elf32_Addr *GLOBAL_OFFSET_TABLE;
	char *StringTable;
	uint32_t dynsize, interp_size;
	int TS, DS, i, j, fd, bss_len = 0, found_loadables = 0;
	static int syscall_trap = SIGTRAP;

	p = &ptc;
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
		printf("[-] Attach pid : %d failed", pid);
		goto out;
	}
	do{
		int status;
		pid_t ret;
		do {
			ret = waitpid(pid, &status, 0);
		} while (ret == -1 && errno == EINTR);
		if(ret == -1)
			goto out_detach;
		if (!WIFSTOPPED(status))
			goto out;
		if ( WSTOPSIG(status) == SIGSTOP )
			break;
		if ( ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)) == -1 )
			goto out_detach;
	}while(1);
	#ifdef PTRACE_O_TRACESYSGOOD
if ( ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == 0 )
		syscall_trap |= 0x80;
	#endif
	PTRACE_ERR_CLEAR(p);
	p->error.errmsg = NULL;
	p->tid = pid;
	p->stack.flags = PTRACE_ALTSTACK_ORIG;
	BaseVaddr = 0x8048000;
	size_t quot = sizeof(Elf32_Ehdr) / sizeof(void *);
	size_t len = sizeof(Elf32_Ehdr);
	unsigned char *s = (unsigned char *) BaseVaddr;
	void* elfheader;
	size_t rem = len % sizeof(void *);
	elfheader = &ehdr;
	unsigned char *d = (unsigned char *) elfheader;
	printf("[+] Begin attach process[pid=%d]\n", p->tid);
	printf("[+] Src Address is : %p\n", s);
	printf("[+] file magic is : %s\n", s);
	while (quot-- != 0) {
		if((w = (ptrace(PTRACE_PEEKDATA, p->tid, s, NULL))) == -1){
			printf("[-]read elf file header[pid= %d] failed", pid);
			return -1;
		}
		*((long *)elfheader) = w;
		s += sizeof(long);
		elfheader += sizeof(long);
	}
	if (rem != 0) {
		long w;
		unsigned char *wp = (unsigned char *)&w;
		w = ptrace(PTRACE_PEEKDATA, p->tid, s, NULL);
		if (w == -1 && errno != 0) {
			s -= sizeof(long) - rem;
			w = ptrace(PTRACE_PEEKDATA, p->tid, s, NULL);
			printf("%x\n", &w);
			if (w == -1 && errno != 0)
				goto out;
			wp += sizeof(void *) - rem;
			}
		while (rem-- != 0)
			d[rem] = wp[rem];
	}
	PTRACE_ERR_CLEAR(p);
	//分配栈空间,返回一个指向这个空间开始的指针
	//将文件头和所有程序头表读取到pmem地址处
	//每个程序头大小为：0x20，这里多申请大概8个程序头，然后从文件头中获取具体程序头的数量，再经过计算去申请具体大小空间
	pmem = alloca(sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) + 0x100);
	printf("[+] ELF file header size: 0x%x\n", sizeof(Elf32_Ehdr));
	printf("[+] ELF one program header size: 0x%x\n", sizeof(Elf32_Phdr));
	printf("[+] copy elf file memory space: %p\n", pmem);
	size_t phslen = sizeof(Elf32_Ehdr) + ehdr.e_phentsize * ehdr.e_phnum;
	long w2;
	size_t rem2 = phslen % sizeof(void *);
	size_t quot2 = phslen / sizeof(void *);
	unsigned char *d2 = (unsigned char *) pmem;
	unsigned char *s2 = (unsigned char *) BaseVaddr;
	while (quot2-- != 0) {
		if((w2 = (ptrace(PTRACE_PEEKDATA, p->tid, s2, NULL))) == -1){
			printf("[-]read file header and program header [pid= %d] failed", pid);
			return -1;
		}
		*((long *)d2) = w2;
		s2 += sizeof(long);
		d2 += sizeof(long);
	}
	if (rem2 != 0) {
                long w2;
                unsigned char *wp = (unsigned char *)&w2;
                w2 = ptrace(PTRACE_PEEKDATA, p->tid, s2, NULL);
                if (w2 == -1 && errno != 0) {
                        s2 -= sizeof(long) - rem2;
                        w2 = ptrace(PTRACE_PEEKDATA, p->tid, s2, NULL);
                        printf("%x\n", &w2);
                        if (w2 == -1 && errno != 0)
                                goto out;
                        wp += sizeof(void *) - rem;
                        }
                while (rem-- != 0)
                        d2[rem] = wp[rem];
        }

	printf("[+] Beginning analysis for executable reconstruction of process image (pid: %d)\n", pid);
	printf("[+] Getting Loadable segment info...\n");
	//程序头表指针
	phdr = (Elf32_Phdr *)(pmem + ehdr.e_phoff);
	printf("[+] program offset is %x\n", ehdr.e_phoff);
	printf("[+] program number is %d\n", ehdr.e_phnum);
	for(i=0; i<ehdr.e_phnum; i++)
	{
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
			
			/*.bss 段长度*/
			bss_len = phdr[i + 1].p_memsz - phdr[i + 1].p_filesz;
	/* 准备将代码段和数据段写入pmem这个申请的空间中*/
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
	}
	/* data段偏移和data段的总长度，两个值的和=text段和data段的总长度 */
	totlen = (pt_load.data_offset + pt_load.data_filesz);
	pmem = alloca(totlen);
	/* 将text段写入pmem这个指针指向的内存空间的初始位置*/	
	if (ptrace_read(&ptc, pmem, (void *)BaseVaddr, pt_load.text_filesz) == -1)
	{
                  printf("ptrace_read() text segment failed\n");
                  return -1;
        }
	/* 将data段写入pmem这个指针指向的内存空间的data段偏移出的位置*/
	if (ptrace_read(&ptc, (pmem + pt_load.data_offset), (void *)pt_load.data_vaddr, pt_load.data_filesz) == -1)
        {
                  printf("ptrace_read() data segment failed\n");
                  return -1;
        }

	ep = (Elf32_Ehdr *)pmem;
	phdr = (Elf32_Phdr *)(pmem + ep->e_phoff);
	dyn = NULL;

	/* 解析动态段*/
	for (i = 0; i < ep->e_phoff; i++)
		if (phdr[i].p_type == PT_DYNAMIC)
		{
			dyn = (Elf32_Dyn *)(pmem + phdr[i].p_offset);
			break;
		}
	printf("[+] ELF dynamic segment address: %p\n", dyn);


	int plt_siz;
	if (!dyn)
		printf("Unable to locate dynamic segment, assuming no dynamic linking\n");
	else 
	for (i = 0; dyn[i].d_tag != DT_NULL; i++)
	{
		switch(dyn[i].d_tag)
		{
			case DT_PLTGOT:
				printf("Located PLT GOT Vaddr 0x%x\n", got = (Elf32_Addr)dyn[i].d_un.d_ptr);
				printf("Relevant GOT entries begin at 0x%x\n", (Elf32_Addr)dyn[i].d_un.d_ptr + 12);
				
				/* got[0] link_map */
				got_off = dyn[i].d_un.d_ptr - pt_load.data_vaddr;
				
				GLOBAL_OFFSET_TABLE = (Elf32_Addr *)(pmem + pt_load.data_offset + got_off);
				/* GLOBAL_OFFSET_TABLE[0] -> link_map (DYNAMIC segment)
 *  				  GLOBAL_OFFSET_TABLE[1] -> /lib/ld-2.6.1.so (Runtime linker)
 *  				  GLOBAL_OFFSET_TABLE[2] -> /lib/ld-2.6.1.so (Runtime linker)
 *  				  Lets increment the GOT to __gmon_start__ (Our base PLT entry) */
				GLOBAL_OFFSET_TABLE += 3;
				break;
			case DT_PLTRELSZ:
				plt_siz = dyn[i].d_un.d_val / sizeof(Elf32_Rel);
				break;
			case DT_STRTAB:		
				StringTable = (char *)dyn[i].d_un.d_ptr;
				break;
			case DT_SYMTAB:
				symtab = (Elf32_Sym *)dyn[i].d_un.d_ptr;
				break;	
			
		}
	}

	return 0;

out_detach:
	PTRACE_ERR_SET_EXTERNAL(p);
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (0)	
out:
	PTRACE_ERR_SET_EXTERNAL(p);
	return -1;
}

int ptrace_read(struct ptrace_context *p, void *dest, const void *src, size_t len)
{
	long w;
	size_t rem = len % sizeof(void *);
	size_t quot = len / sizeof(void *);
	unsigned char *s = (unsigned char *) src;
	unsigned char *d = (unsigned char *) dest;

	assert(sizeof(void *) == sizeof(long));

	while (quot-- != 0) {
		w = ptrace(PTRACE_PEEKDATA, p->tid, s, NULL);
		if (w == -1 && errno != 0)
			goto out_error;
		*((long *)d) = w;

		s += sizeof(long);
		d += sizeof(long);
	}

	/* The remainder of data to read will be handled in a manner
 * 	 * analogous to ptrace_write().
 * 	 	 */
	if (rem != 0) {
		long w;
		unsigned char *wp = (unsigned char *)&w;

		w = ptrace(PTRACE_PEEKDATA, p->tid, s, NULL);
		if (w == -1 && errno != 0) {
			s -= sizeof(long) - rem;

			w = ptrace(PTRACE_PEEKDATA, p->tid, s, NULL);
			if (w == -1 && errno != 0)
				goto out_error;

			wp += sizeof(void *) - rem;
		}

		while (rem-- != 0)
			d[rem] = wp[rem];
	}

	PTRACE_ERR_CLEAR(p);
	return 0;

out_error:
	PTRACE_ERR_SET_EXTERNAL(p);
	return -1;
}
