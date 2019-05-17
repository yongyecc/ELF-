# 32位进程镜像重建

### 编译
```
gcc -m32 rebuild.c -o rebuild
```

### 使用
```
rebuild -p <PID> <dump文件>
```
pid: 进程PID
dump文件：将进程进像dump下的ELF可执行文件

# 参考
> Linux二进制分析
> 工具quenya
