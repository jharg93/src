/*	$OpenBSD: SYS.h,v 1.3 2020/07/14 16:48:13 kettenis Exp $	*/
/*-
 * Copyright (c) 1994
 *	Andrew Cagney.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Ralph Campbell.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)SYS.h	8.1 (Berkeley) 6/4/93
 */

#include "DEFS.h"
#include <sys/syscall.h>

/* r0 will be a non zero errno if there was an error, while r3/r4 will
   contain the return value */

#include "machine/asm.h"


/* offsetof(struct tib, tib_errno) - offsetof(struct tib, __tib_tcb) */
#define TCB_OFFSET_ERRNO	(-20)
/* from <powerpc64/tcb.h>: TCB address == %r13 - TCB_OFFSET */
#define TCB_OFFSET		0x7008

/* offset of errno from %r13 */
#define R13_OFFSET_ERRNO		(-TCB_OFFSET + TCB_OFFSET_ERRNO)

#define _CONCAT(x,y)	x##y
#define PSEUDO_PREFIX(p,x,y)	\
			ENTRY(p##x) \
				li %r0, SYS_##y ; \
				/* sc */
#define PSEUDO_SUFFIX		cmpwi %r0, 0 ; \
				beqlr ; \
				stw	%r0, R13_OFFSET_ERRNO(%r13); \
				li	%r3, -1; \
				blr

#define PSEUDO_NOERROR_SUFFIX	blr

#define __END_HIDDEN(p,x)	END(p##x);			\
				_HIDDEN_FALIAS(x,p##x);		\
				END(_HIDDEN(x))
#define __END(p,x)		__END_HIDDEN(p,x); END(x)


#define ALIAS(x,y)		WEAK_ALIAS(y,_CONCAT(x,y));
		
#define PREFIX_HIDDEN(x)	PSEUDO_PREFIX(_thread_sys_,x,x)
#define PREFIX(x)		ALIAS(_thread_sys_,x) \
				PREFIX_HIDDEN(x)
#define PSEUDO_NOERROR(x,y)	ALIAS(_thread_sys_,x) \
				PSEUDO_PREFIX(_thread_sys_,x,y) ; \
				sc ; \
				PSEUDO_NOERROR_SUFFIX; \
				__END(_thread_sys_,x)

#define PSEUDO_HIDDEN(x,y)	PSEUDO_PREFIX(_thread_sys_,x,y) ; \
				sc ; \
				PSEUDO_SUFFIX; \
				__END_HIDDEN(_thread_sys_,x)
#define PSEUDO(x,y)		ALIAS(_thread_sys_,x) \
				PSEUDO_HIDDEN(x,y); \
				END(x)

#define RSYSCALL(x)		PSEUDO(x,x)
#define RSYSCALL_HIDDEN(x)	PSEUDO_HIDDEN(x,x)
#define SYSCALL_END_HIDDEN(x)	__END_HIDDEN(_thread_sys_,x)
#define SYSCALL_END(x)		__END(_thread_sys_,x)

