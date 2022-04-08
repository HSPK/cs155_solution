# CS155 Solution

## exploit1

根据foo函数构造payload，前256个字节初始化为1。ebp的位置内容不变。ebp+4位置修改为shellcode的地址（ebp+8）。

dbg查看ebp+8的值：

![image-20220408120601712](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\image-20220408120601712.png)

修改payload中的shellcode地址为0xbffffd44。编译运行exploit1：

![image-20220408150118265](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\image-20220408150118265.png)

## exploit2

漏洞类型：缓冲区溢出漏洞

​    漏洞代码：

```c
 for (i = 0; i <= len; i++)
  out[i] = in[i];
```

​    这段代码实际上复制了 len+1 个字节。因此，当len=200时，会修改bar函数的栈帧。

下面给出foo函数的栈帧结构示意图：

| ret to xxx         |
| ------------------ |
| xxx ebp            |
| pointer to argv[1] |
| ret to foo         |
| foo ebp            |
| buf[200]           |
| …                  |

​    通过buf溢出修改foo ebp的LSB使得foo ebp指向ret to foo的地址。那么当foo函数返回时，就会返回到argv[1]指定的地址中。将shellcode写入argv[1]指定的地址即可。

​    payload构造：

![image-20220408150204918](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\image-20220408150204918.png)

![image-20220408150214923](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\image-20220408150214923.png)

可以看到foo ebp=0xbffffe5c，而ret to foo的地址为0xbffffe54。

构造payload大小为201，初始化为0x90空指令。payload前面部分用shellcode填充，最后一个字节修改为0x54。

![image-20220408150231103](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\image-20220408150231103.png)

![image-20220408150237385](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\image-20220408150237385.png)

## expliot3

漏洞类型：整数溢出漏洞

​    漏洞代码：

```c
int foo(char *in, int count)
{
 struct widget_t buf[MAX_WIDGETS];
 if (count < MAX_WIDGETS) 
  memcpy(buf, in, count * sizeof(struct widget_t));
 return 0;
}
```



​    参数 count 为负数时，memcpy 第三个参数被转换为无符号整数，值可能超过MAX_WIDGETS * sizeof(struct widgets)。

当![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image002.png) 时，![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image004.png)，求解 ![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image006.png)，得 ![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image008.png) 时，溢出字节数目为 ![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image010.png)。

​    当 ![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image012.png) 时，溢出字节数目为 ![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image014.png)

漏洞利用：

以 ![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image002-164940150037010.png) 构造 payload，payload大小为 ![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image004-164940150037111.png)

shellcode 放在 payload的count后面。payload后16个字节修改foo函数的返回地址为shellcode。

payload构造：

定义 payload 大小：

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image006-164940150037112.jpg)

初始化 payload：

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image008-164940150037113.jpg)

第一部分为count：

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image010-164940150037114.jpg)

第二部分为shellcode：

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image012-164940150037118.jpg)

gdb查看shellcode地址

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image014-164940150037115.jpg)

​    构造payload：

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image016-164940150037117.jpg)

编译运行exploit3：

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image018-164940150037116.jpg)

## expliot4

漏洞利用：

查看tmalloc.c的实现，每一片分配的内存区域都有一个对应的chunk header。这个chunk header保存了内存区域的起始位置和结束位置以及是否可用。

*/**

 ** the chunk header*

 **/*

typedef double ALIGN;

 

typedef union CHUNK_TAG

{

 struct

  {

   union CHUNK_TAG *l;    */\* leftward chunk \*/*

   union CHUNK_TAG *r;    */\* rightward chunk + free bit (see below) \*/*

  } s;

 ALIGN x;

} CHUNK;

​    chunk结构一共8个字节，低四字节为前向指针，后四字节为后向指针。

初始化之后，内存布局为：

static void init(void)

{

 bot = &arena[0]; top = &arena[ARENA_CHUNKS-1];

 bot->s.l = NULL; bot->s.r = top;

 top->s.l = bot;  top->s.r = NULL;

 SET_FREEBIT(bot); CLR_FREEBIT(top);

}

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image002.png)

 char *p;

 char *q;

 

 if ( (p = tmalloc(500)) == NULL)

  {

   fprintf(stderr, "tmalloc failure\n");

   exit(EXIT_FAILURE);

  }

 if ( (q = tmalloc(300)) == NULL)

  {

   fprintf(stderr, "tmalloc failure\n");

   exit(EXIT_FAILURE);

  } 

  执行完之后，堆内存布局变为：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image004.png)

 tfree(p);

 tfree(q);

 

 if ( (p = tmalloc(1024)) == NULL)

  {

   fprintf(stderr, "tmalloc failure\n");

   exit(EXIT_FAILURE);

  }

​    执行完之后，堆内存布局变为：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image006.png)

tfree(q)之后，q仍然保存对内存地址的引用。

因此，这时再次执行tfree(q)：

void tfree(void *vp)

{

 CHUNK *p, *q;

 

 if (vp == NULL)

  return;

 

 p = TOCHUNK(vp);

 CLR_FREEBIT(p);

 q = p->s.l;

 if (q != NULL && GET_FREEBIT(q)) */\* try to consolidate leftward \*/*

  {

   CLR_FREEBIT(q);

   q->s.r    = p->s.r;

   p->s.r->s.l = q;

   SET_FREEBIT(q);

   p = q;

  }

 q = RIGHT(p);

 if (q != NULL && GET_FREEBIT(q)) */\* try to consolidate rightward \*/*

  {

   CLR_FREEBIT(q);

   p->s.r    = q->s.r;

   q->s.r->s.l = p;

   SET_FREEBIT(q);

  }

 SET_FREEBIT(p);

}

​    在指针q前面的chunk的位置伪造一个chunk，从而达到tfree后修改内存的目的。

伪造的chunk记为chunk_fake。

   chunk_fake.s.l存放修改的内存地址addr1。addr1被解析为一个chunk，记为chunk_addr1。

设计chunk_addr1的s.r最低位为1。利用gdb调试：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image008.jpg)

假设shellcode存放位置为0x804a068。

foo函数返回地址为0x804867c，这个值最低位为0，不满足条件。考虑修改foo函数的低2字节，将867c修改为a068。那么0xbffffa6c+2处的值为0x867cffbf，满足chunk空闲的条件。

那么，chunk_fake.s.l = 0xbffffa6c+2-4。chunk_fake.s.r=0xa068ffbf。

此时，chunk_addr1.s.r=0x867cffbf。但是，chunk_fake.s.r不是一个合法访问的地址。

那么，需要保证chunk_fake.s.r也是一个合法的地址，记为chunk_addr2。那么，从代码上面看，可以利用第二个赋值操作，即p->s.r->s.l = q;，将p->s.r指向的地址修改为栈中存放返回地址的地址。同样也可以达到修改内存的效果，同时保证了内存解析不会出现段错误。

那么chunk_addr1就可以手动设计，由于chunk_addr1.r会被修改，而chunk_addr1.l不会被修改，chunk_addr2.l会被赋值为chunk_addr1，即返回地址会被修改为chunk_addr1。因此，设计chunk_addr1.l为jmp指令，jmp到shellcode，从而越过chunk_addr1.r执行shellcode，而chunk_addr1.r只需要满足低位为1即可。

设计之后的内存布局如下：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image010.png)

payload编写：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image012.jpg)

chunk_addr1.l = 0xeb 0x06 0x90 0x90，jmp 0x06，即跳转到当前指令后6+2=8个字节位置

chunk_addr1.r = 0x01 0x90 0x90 0x90，保证free bit为1。

接下来是shellcode：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image014.jpg)

接下来是chunk_fake:

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image016.jpg)

chunk_fake的位置在原来q的chunk header的位置，即tmalloc(500)之后的位置，由于tmalloc中使用了8字节对齐，所以实际占用504字节。

chunk_fake.s.l = 0x68 0xa0 0x04 0x08，即chunk_addr1的地址

chunk_fake.s.r = 0x70 0xfa 0xff 0xbf，即 foo函数栈中 $ebp+4 的值。

编译运行payload：

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image018-164940154993519.jpg)

## expliot5

漏洞利用：

​    分析foo函数调用snprintf前的函数栈：

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image002-164940158088020.png)

​    通过snprintf修改foo函数的返回地址。

payload编写：

​    shellcode一共占用45个字节。设计payload布局：

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image004-164940158088021.png)

使用 %hn，通过两次写操作修改foo函数的返回地址。

addr1为其中两个字节的地址，addr2为另外两字节的地址。

写入shellcode：

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image006-164940158088022.jpg)

gdb查看返回地址以及shellcode的地址：

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image008-164940158088023.jpg)

​    shellcode地址为![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image010.png)，foo函数返回地址的地址为 ![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image012-164940158088024.png)

​    由于 ![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image014-164940158088025.png) 因此选择先写入高字节，再写入低字节。所以，

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image016.png)

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image018-164940158088026.jpg)

写入最后的format string：

![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image020.jpg)

format string计算：第一个![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image022.png)

第二个 ![img](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\clip_image024.png)

由于shellcode占用45字节，对齐后占用48字节。addr1实际上是第13个参数，addr2是第14个参数。所以format string两个%n为%13$hn和%14$hn。

编译运行：

![image-20220408150628142](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\image-20220408150628142.png)

## expliot6

漏洞利用：

利用多复制出的一个字节，可以修改bar函数保存的foo函数的ebp。返回到foo函数时，ebp已经被修改。

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image002.jpg)

从bar函数返回后，foo函数将ebp-8处的值赋值给了ebp-4位置处的指针指向的位置。这就给了修改内存的手段：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image004.jpg)

​    由于修改内存之后紧接着有一个call指令，所以可以修改call指令的参数。使得call指令转移到shellcode中运行。由于代码段不可写，所以不能直接修改call指令偏移量，又因为call _exit是动态链接函数，所以可以通过修改_exit在.got.plt表中的地址达到修改最终跳转地址的目的。

​    payload编写：

查看foo ebp的值：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image006.jpg)

​    可以修改的范围为0xbffffd00-0xbffffdff。

​    查看buf的范围：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image008.jpg)

buf的范围时0xbffffd84-0xbffffcc0。

因此，可以将foo ebp修改为0xbffffd88，即和bar ebp相同。shellcode存放在buf的起始位置。ebp-4位置存放指向call偏移量的指针，ebp-8存放跳转到shellcode的偏移量。

查看call指令的地址：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image010.jpg)

call指令偏移量地址=0x0804858b+1=0x0804858c。

shellcode地址为0xbffffcc0，新的call指令偏移量

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image012.png)

然而这样有一个问题，代码段是只读属性的。

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image014.jpg)

那么，重新开始看call _exit指令：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image016.jpg)

​    跳转到了.got.plt表，说明是动态链接函数。查看.got.plt节：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image018.jpg)

可以看到0x0804a00c地址下存放_exit函数的地址，重定位类型为R_386_JUMP_SLOT，直接填写目标函数的VMA。

因此，修改ebp-4为0x084a00c，ebp-8为shellcode的地址，即0xbffffcc0。这样，经过*p=a之后，_exit的地址就会被修改为shellcode的地址。

写入shellcode：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image020.jpg)

写入ebp-4和ebp-8的值：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image022.jpg)

写入溢出字节，0x88：

![img](file:///C:/Users/way/AppData/Local/Temp/msohtmlclip1/01/clip_image024.jpg)

编译运行：

![image-20220408150657675](C:\Users\way\Documents\collage\NetSecurity\project1\proj1\images\image-20220408150657675.png)

