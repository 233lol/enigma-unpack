	.text

/* ---------------------------------------------------------------------------
   unixTime.dll  —  重新实现（替代原 LTS 整合版中那个被壳虚拟化的同名 DLL）

   原 DLL 是 "ztj" 用 C++ 编译的小组件，只有 calcTimeDiffe1 被游戏脚本调用
   （脚本里 #uselib "unixTime.dll" + #func calcTimeDiffe1，用于自动备份存档
   的时间戳命名）。这里按原 DLL 的反汇编语义 1:1 重写：

     calcTimeDiffe1(year, month, day, hour, min, sec)
         = (int)( time(NULL) - mktime(local(year,month,day,hour,min,sec)) )
     calcTimeDiffe2(...) = 上面结果的相反数

   time()/mktime() 直接复用系统 msvcrt.dll 的 _time32 / _mktime32，
   保证与原实现（同样基于 msvcrt struct tm）完全一致。

   struct tm (msvcrt) 布局: sec,min,hour,mday,mon,year,wday,yday,isdst (9 x int)
   --------------------------------------------------------------------------- */

	.globl _GetNowUnixTime
_GetNowUnixTime:
	xorl	%eax, %eax
	ret

	.globl _fnunixTime
_fnunixTime:
	movl	$0x141, %eax			/* 原 DLL 就是返回常量 0x141 */
	ret

/* 公共体：填充 struct tm，target = mktime(tm)，now = time()
   栈帧: [esp+0x00..0x24)=struct tm, [esp+0x24]=target, [esp+0x28]=now */
.macro FILLTM
	movl	0x1c(%ebp), %eax
	movl	%eax, 0x00(%esp)		/* tm_sec  */
	movl	0x18(%ebp), %eax
	movl	%eax, 0x04(%esp)		/* tm_min  */
	movl	0x14(%ebp), %eax
	movl	%eax, 0x08(%esp)		/* tm_hour */
	movl	0x10(%ebp), %eax
	movl	%eax, 0x0c(%esp)		/* tm_mday */
	movl	0x0c(%ebp), %eax
	decl	%eax
	movl	%eax, 0x10(%esp)		/* tm_mon  */
	movl	0x08(%ebp), %eax
	subl	$1900, %eax
	movl	%eax, 0x14(%esp)		/* tm_year */
	movl	$0, 0x18(%esp)			/* tm_wday */
	movl	$0, 0x1c(%esp)			/* tm_yday */
	movl	$0, 0x20(%esp)			/* tm_isdst */
	leal	0x00(%esp), %eax
	pushl	%eax
	call	*__imp___mktime32
	addl	$4, %esp
	movl	%eax, 0x24(%esp)		/* target */
	leal	0x28(%esp), %eax
	pushl	%eax
	call	*__imp___time32
	addl	$4, %esp
.endm

	.globl _calcTimeDiffe1
_calcTimeDiffe1:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$0x30, %esp
	FILLTM
	movl	0x28(%esp), %eax		/* now    */
	subl	0x24(%esp), %eax		/* now - target */
	movl	%ebp, %esp
	popl	%ebp
	ret

	.globl _calcTimeDiffe2
_calcTimeDiffe2:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$0x30, %esp
	FILLTM
	movl	0x24(%esp), %eax		/* target - now */
	subl	0x28(%esp), %eax
	movl	%ebp, %esp
	popl	%ebp
	ret

/* DLL 入口：必须返回 TRUE，否则加载失败 (ERROR_DLL_INIT_FAILED) */
	.globl _DllMainCRTStartup
_DllMainCRTStartup:
	movl	$1, %eax
	ret
