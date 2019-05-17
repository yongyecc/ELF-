#include "stdio.h"
#include <elf.h>
#include "rebuild.h"
#include <alloca.h>
#include <stdlib.h>
#include <assert.h>


char shstrtable[] =
"\0"
".interp\0"
".hash\0"
".note.ABI-tag\0"
".gnu.hash\0"
".dynsym\0"
".dynstr\0"
".gnu.version\0"
".gnu.version_r\0"
".rel.dyn\0"
".rel.plt\0"  
".init\0"
".plt\0"
".text\0"
".fini\0"
".rodata\0"
".eh_frame_hdr\0"
".eh_frame\0"
".ctors\0"
".dtors\0"
".jcr\0"
".dynamic\0"
".got\0"
".got.plt\0"
".data\0"
".bss\0"
".shstrtab\0"
".symtab\0"
".strtab\0";

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
	char *p1;
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
	uint8_t null = 0;

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
			printf("[+] bss segment size is : %d\n", bss_len);
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
				
				/* GOT表相对data段的偏移地址 */
				got_off = dyn[i].d_un.d_ptr - pt_load.data_vaddr;
				/*GOT[0]*/
				GLOBAL_OFFSET_TABLE = (Elf32_Addr *)(pmem + pt_load.data_offset + got_off);
				/* GLOBAL_OFFSET_TABLE[0] -> link_map (DYNAMIC segment)
 *  				  GLOBAL_OFFSET_TABLE[1] -> /lib/ld-2.6.1.so (Runtime linker)
 *  				  GLOBAL_OFFSET_TABLE[2] -> /lib/ld-2.6.1.so (Runtime linker)
 *  				  Lets increment the GOT to __gmon_start__ (Our base PLT entry) */
				/* 从GOT[3] 开始是共享函数的条目*/
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
	if (!dyn)
		goto no_dynamic;
	uint8_t *gp = &pmem[pt_load.data_offset + got_off + 4];
	for (i = 0; i < 8; i++)
		*(gp + i) = 0x0;
	Elf32_Addr PLT_VADDR = GLOBAL_OFFSET_TABLE[0];/* gmon_start */
	/*
 	  08048300 <__gmon_start__@plt>:
  	  8048300:       ff 25 00 a0 04 08       jmp    *0x804a000
  	  8048306:       68 00 00 00 00          push   $0x0  <- Here is where PLT_VADDR is  
 	  804830b:       e9 e0 ff ff ff          jmp    80482f0 <_init+0x18>
 	 */
	printf("[+] Resolved PLT: 0x%x\n", PLT_VADDR);
	printf("PLT Entries: %d\n", plt_siz);
	PLT_VADDR += 16;
	for (j = 1; j < plt_siz; j++)
	{
		printf("Patch #%d - [0x%x] changed to [0x%x]\n", j, GLOBAL_OFFSET_TABLE[j], PLT_VADDR);
		GLOBAL_OFFSET_TABLE[j] = PLT_VADDR;
		PLT_VADDR += 16;
	}	
	
	printf("[+] Patched GOT with PLT stubs\n");	
	no_dynamic:
	if ((fd = open(name, O_TRUNC|O_WRONLY|O_CREAT)) == -1)
	{
		printf("Unable to open file for writing: %s\n", strerror(errno));
		return -1;
	}
	
	if (fchmod(fd, 00777) < 0)
		printf("Warning: Unable to set permissions on output file\n");
	
	ep->e_shstrndx = !dyn ? 4 : 6;
	ep->e_shoff = totlen + bss_len + sizeof(shstrtable);
	ep->e_shnum = !dyn ? 5 : 7;
	Elf32_Off shsoff = totlen + bss_len;
	//将text段、data段写入文件
	if (write(fd, pmem, totlen) != totlen)
	{
		printf("Unable to write entire data: %s\n", strerror(errno));
		return -1;
	}
	//写入bss段
	int bw;
	if ((bw = write(fd, &null, bss_len)) == -1) //bss_len)
	{
		printf("Unable to create bss padding %d bytes (but only %d written): %s\n", bss_len, bw, strerror(errno));
		return -1;
	}

	totlen += bss_len;
	/* Write string table (final section) */
	if (write(fd, (char *)shstrtable, sizeof(shstrtable)) != sizeof(shstrtable))
	{
		printf("Unable to write string table %d bytes: %s\n", strerror(errno));
		return -1;
	}
	int slen = sizeof(Elf32_Shdr);
	/* Add NULL section */
	memset(&shdr, 0, slen);	
	shdr.sh_addr = BaseVaddr;
	
	if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }

        totlen += slen;
	
	if (!dyn)
		goto no_interp;
	/* Add .interp section */
	shdr.sh_type = SHT_PROGBITS;
	shdr.sh_offset = interp_off;
	shdr.sh_addr = interp_vaddr;
	shdr.sh_flags = SHF_ALLOC;
	shdr.sh_link = 0;
	shdr.sh_info = 0;
	shdr.sh_entsize = 0;
	shdr.sh_size = interp_size;
	shdr.sh_addralign = 0;
	
	for (i = 0, p1 = shstrtable ;; i++)
                if (p1[i] == '.' && p1[i + 1] == 'i' && p1[i + 2] == 'n' && p1[i + 3] == 't' && p1[i + 4] == 'e')
                {
                        shdr.sh_name = i;
                        break;
                }

	if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }
        totlen += slen;
	no_interp:
	/* Add .text section */
	shdr.sh_type = SHT_PROGBITS;
	shdr.sh_offset = phdr[TS].p_offset;
	shdr.sh_addr = phdr[TS].p_vaddr;
	shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
	shdr.sh_info = 0;
	shdr.sh_link = 0;
	shdr.sh_entsize = 0;
	shdr.sh_size = phdr[TS].p_filesz;
	shdr.sh_addralign = 0xf;

	for (i = 0, p1 = shstrtable ;; i++)
		if (p1[i] == '.' && p1[i + 1] == 't' && p1[i + 2] == 'e' && p1[i + 3] == 'x' && p1[i + 4] == 't')
		{
			shdr.sh_name = i;
			break;
		}
	if (write(fd, &shdr, slen) != slen)
	{
		printf("Error in writing section header: %s\n", strerror(errno));
		return -1;
	}
	
	totlen += slen;

	/* Add .data section */
	shdr.sh_type = SHT_PROGBITS;
        shdr.sh_offset = phdr[DS].p_offset;
        shdr.sh_addr = phdr[DS].p_vaddr;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_info = 0;
        shdr.sh_link = 0;
        shdr.sh_entsize = 0;
	shdr.sh_size = phdr[DS].p_filesz;
	shdr.sh_addralign = 4;

	for (i = 0, p1 = shstrtable ;; i++)
                if (p1[i] == '.' && p1[i + 1] == 'd' && p1[i + 2] == 'a' && p1[i + 3] == 't' && p1[i + 4] == 'a')
                {
		        shdr.sh_name = i;
			break;
		}
	
	if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }

	totlen += slen;
	if (!dyn)
		goto no_dynam_section;

	/* Add .dynamic section */
	shdr.sh_type = SHT_DYNAMIC;
        shdr.sh_offset = dynoffset;
        shdr.sh_addr = dynvaddr;
        shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
        shdr.sh_info = 0;
        shdr.sh_link = 0;
        shdr.sh_entsize = 8;
        shdr.sh_size = dynsize;
	shdr.sh_addralign = 4;

	for (i = 0, p1 = shstrtable ;; i++)
                if (p1[i] == '.' && p1[i + 1] == 'd' && p1[i + 2] == 'y' && p1[i + 3] == 'n' && p1[i + 4] == 'a' 
		 		&& p1[i + 5] == 'm' && p1[i + 6] == 'i' && p1[i + 7] == 'c')
                {
		        shdr.sh_name = i;
			break;
		}

	if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }
        totlen += slen;
	
	no_dynam_section:

	/* Add .bss section */
	shdr.sh_type = SHT_NOBITS;
        shdr.sh_offset = phdr[DS].p_offset + phdr[DS].p_filesz;
        shdr.sh_addr = phdr[DS].p_vaddr + phdr[DS].p_filesz;
        shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
        shdr.sh_info = 0;
        shdr.sh_link = 0;
        shdr.sh_entsize = 0;
        shdr.sh_size = bss_len;
	shdr.sh_addralign = 4;

        for (i = 0, p1 = shstrtable ;; i++)
                if (p1[i] == '.' && p1[i + 1] == 'b' && p1[i + 2] == 's' && p1[i + 3] == 's')
                {
                        shdr.sh_name = i;
                        break;
                }

        if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }
        totlen += slen;
	/* add .shstrtab */
	shdr.sh_type = SHT_STRTAB;
	shdr.sh_offset = shsoff;
	shdr.sh_addr = BaseVaddr + shsoff;
	shdr.sh_flags = 0;
	shdr.sh_info = 0;
	shdr.sh_link = 0;
	shdr.sh_entsize = 0;
	shdr.sh_size = sizeof(shstrtable);
	shdr.sh_addralign = 1;

	for (i = 0, p1 = shstrtable ;; i++)
                if (p1[i] == '.' && p1[i + 1] == 's' && p1[i + 2] == 'h' && p1[i + 3] == 's' && p1[i + 4] == 't')
                {
                        shdr.sh_name = i;
                        break;
                }

	if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }
        totlen += slen;
	ptrace_close(&ptc);
	close(fd);
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


int ptrace_close(struct ptrace_context *p)
{
	return ptrace_detach(p);
}

int ptrace_detach(struct ptrace_context *p)
{
	if ( ptrace(PTRACE_DETACH, p->tid, NULL, NULL) == -1 ) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	if (p->error.errmsg != NULL)
		free(p->error.errmsg);

	PTRACE_ERR_CLEAR(p);

	return 0;
}
