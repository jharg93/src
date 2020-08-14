/*
 * Copyright (c) 2020 Jordan Hargrave <jordan_hargrave@hotmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef __x86emu_h__
#define __x86emu_h__

struct insn {
	uint8_t sig[3];
	int siglen;
	int dir;
	int size;
	int incr;
  	int reg;
};

#define mrr_mm(x)  (((x) >> 6) & 3)
#define mrr_ggg(x) (((x) >> 3) & 7)
#define mrr_rrr(x) (((x) >> 0) & 7)

#define sib_ss(x)  (((x) >> 6) & 3)
#define sib_iii(x) (((x) >> 3) & 7)
#define sib_bbb(x) (((x) >> 0) & 7)

/* Opcode argument types: register, immediate, memory, etc */
enum {
	TYPE_SHIFT = 24,
	SIZE_SHIFT = 16,

	VAL_MASK    = 0xFFFF,

	TYPE_MASK   = 0xFF << TYPE_SHIFT,
	TYPE_REG    = 'r' << TYPE_SHIFT,
	TYPE_EMBREG = 'g' << TYPE_SHIFT,
	TYPE_EA     = 'E' << TYPE_SHIFT,
	TYPE_EAMEM  = 'M' << TYPE_SHIFT,
	TYPE_EAREG  = 'G' << TYPE_SHIFT,
	TYPE_IMM    = 'I' << TYPE_SHIFT,
	TYPE_JMP    = 'J' << TYPE_SHIFT,
	TYPE_OFFSET = 'O' << TYPE_SHIFT,
	TYPE_INDEX  = '$' << TYPE_SHIFT,

	SIZE_MASK   = 0xFF << SIZE_SHIFT,
	SIZE_BYTE   = 'b' << SIZE_SHIFT,
	SIZE_WORD   = 'w' << SIZE_SHIFT,
	SIZE_DWORD  = 'd' << SIZE_SHIFT,
	SIZE_QWORD  = 'q' << SIZE_SHIFT,
	SIZE_VWORD  = 'v' << SIZE_SHIFT,  /* 16/32/64-bit opsize */
	SIZE_ZWORD  = 'z' << SIZE_SHIFT,  /* 16/32-bit opsize */
	SIZE_PTR    = 'p' << SIZE_SHIFT,
	SIZE_SREG   = 's' << SIZE_SHIFT,
	SIZE_CREG   = 'C' << SIZE_SHIFT,
	SIZE_DREG   = 'D' << SIZE_SHIFT,
	SIZE_TREG   = 'T' << SIZE_SHIFT,

	Ap      = TYPE_IMM+SIZE_PTR,
	Mp      = TYPE_EAMEM+SIZE_PTR,
	Sw      = TYPE_EAREG+SIZE_SREG,

	Ob      = TYPE_OFFSET+SIZE_BYTE,
	Ov      = TYPE_OFFSET+SIZE_VWORD,

	Eb      = TYPE_EA+SIZE_BYTE,
	Ew      = TYPE_EA+SIZE_WORD,
	Ev      = TYPE_EA+SIZE_VWORD,

	Gb      = TYPE_EAREG+SIZE_BYTE,
	Gv      = TYPE_EAREG+SIZE_VWORD,

	gb      = TYPE_EMBREG+SIZE_BYTE,
	gv      = TYPE_EMBREG+SIZE_VWORD,

	Ib      = TYPE_IMM+SIZE_BYTE,
	Iw      = TYPE_IMM+SIZE_WORD,
	Iv      = TYPE_IMM+SIZE_VWORD,
	Iz      = TYPE_IMM+SIZE_ZWORD,
	i1      = TYPE_IMM+0x01,
	i3      = TYPE_IMM+0x03,

	Jb      = TYPE_JMP+SIZE_BYTE,
	Jz      = TYPE_JMP+SIZE_ZWORD,

	Xb      = TYPE_INDEX+SIZE_BYTE,
	Xv      = TYPE_INDEX+SIZE_VWORD,
	Xz      = TYPE_INDEX+SIZE_ZWORD,
	Yb      = TYPE_INDEX+SIZE_BYTE+0x1,
	Yv      = TYPE_INDEX+SIZE_VWORD+0x1,
	Yz      = TYPE_INDEX+SIZE_ZWORD+0x1,
 
	/* Registers */
	rAL     = TYPE_REG+SIZE_BYTE,
	rCL,
	rDL,
	rBL,
	rAH,
	rCH,
	rDH,
	rBH,
	rSPL    = TYPE_REG+SIZE_BYTE+0x14,
	rBPL,
	rSIL,
	rDIL,

	rAX     = TYPE_REG+SIZE_WORD,
	rCX,
	rDX,
	rBX,
	rSP,
	rBP,
	rSI,
	rDI,

	rEAX    = TYPE_REG+SIZE_DWORD,
	rECX,
	rEDX,
	rEBX,
	rESP,
	rEBP,
	rESI,
	rEDI,

	rRAX    = TYPE_REG+SIZE_QWORD,
	rRCX,
	rRDX,
	rRBX,
	rRSP,
	rRBP,
	rRSI,
	rRDI,

	rvAX    = TYPE_REG+SIZE_VWORD,

	rES     = TYPE_REG+SIZE_SREG,
	rCS,
	rSS,
	rDS,
	rFS,
	rGS,
};

enum {
	REX_B    = 0x1,   /* mrr.rrr or sib.bbb or op.ggg */
	REX_X    = 0x2,   /* sib.iii */
	REX_R    = 0x4,   /* mrr.ggg */
	REX_W    = 0x8,   /* operand size=64-bit */

	/* Prefix flags */
	FLG_REX  = 0x0001,  /* REX byte */
	FLG_SEG  = 0x0002,  /* segment prefix */
	FLG_OSZ  = 0x0004,  /* operand size */
	FLG_ASZ  = 0x0008,  /* address size */
	FLG_LOCK = 0x0010,  /* lock */
	FLG_REP  = 0x0020,  /* repz/repnz/rep */

	/* Additional flags */
	FLG_MRR  = 0x0100,  /* has mod-reg-rm byte */
	FLG_GRP  = 0x0200,  /* opcode based on mrr.reg */
	FLG_D64  = 0x0400,  /* default size = 64-bit */
	FLG_NO64 = 0x0800,  /* invalid in 64-bit mode */
	FLG_MEM  = 0x1000,  /* non-mrr memory */
};

int dodis(uint8_t *, struct insn *ix, int mode);

#endif
