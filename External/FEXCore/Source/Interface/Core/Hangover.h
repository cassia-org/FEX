#pragma once

/*
 * Copyright 2021 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <cstdint>

#define BYTE uint8_t
#define WORD uint16_t
#define DWORD uint32_t
#define ULONG uint32_t
#define DWORD64 uint64_t
#define ULONGLONG uint64_t
#define LONGLONG int64_t

#define I386_SIZE_OF_80387_REGISTERS      80

#define CONTEXT_i386      0x00010000
#define CONTEXT_I386_CONTROL   (CONTEXT_i386 | 0x0001) /* SS:SP, CS:IP, FLAGS, BP */
#define CONTEXT_I386_INTEGER   (CONTEXT_i386 | 0x0002) /* AX, BX, CX, DX, SI, DI */
#define CONTEXT_I386_SEGMENTS  (CONTEXT_i386 | 0x0004) /* DS, ES, FS, GS */
#define CONTEXT_I386_FLOATING_POINT  (CONTEXT_i386 | 0x0008) /* 387 state */
#define CONTEXT_I386_DEBUG_REGISTERS (CONTEXT_i386 | 0x0010) /* DB 0-3,6,7 */
#define CONTEXT_I386_EXTENDED_REGISTERS (CONTEXT_i386 | 0x0020)
#define CONTEXT_I386_XSTATE             (CONTEXT_i386 | 0x0040)
#define CONTEXT_I386_FULL (CONTEXT_I386_CONTROL | CONTEXT_I386_INTEGER | CONTEXT_I386_SEGMENTS)
#define CONTEXT_I386_ALL (CONTEXT_I386_FULL | CONTEXT_I386_FLOATING_POINT | CONTEXT_I386_DEBUG_REGISTERS | CONTEXT_I386_EXTENDED_REGISTERS)

typedef struct _I386_FLOATING_SAVE_AREA
{
    DWORD   ControlWord;
    DWORD   StatusWord;
    DWORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    BYTE    RegisterArea[I386_SIZE_OF_80387_REGISTERS];
    DWORD   Cr0NpxState;
} I386_FLOATING_SAVE_AREA, WOW64_FLOATING_SAVE_AREA, *PWOW64_FLOATING_SAVE_AREA;
#define I386_MAXIMUM_SUPPORTED_EXTENSION     512

typedef union _ARM64_NT_NEON128
{
    struct
    {
        ULONGLONG Low;
        LONGLONG High;
    } DUMMYSTRUCTNAME;
    double D[2];
    float S[4];
    WORD  H[8];
    BYTE  B[16];
} ARM64_NT_NEON128, *PARM64_NT_NEON128;

#pragma pack(4)
typedef struct _I386_CONTEXT
{
    DWORD   ContextFlags;  /* 000 */

    /* These are selected by CONTEXT_DEBUG_REGISTERS */
    DWORD   Dr0;           /* 004 */
    DWORD   Dr1;           /* 008 */
    DWORD   Dr2;           /* 00c */
    DWORD   Dr3;           /* 010 */
    DWORD   Dr6;           /* 014 */
    DWORD   Dr7;           /* 018 */

    /* These are selected by CONTEXT_FLOATING_POINT */
    I386_FLOATING_SAVE_AREA FloatSave; /* 01c */

    /* These are selected by CONTEXT_SEGMENTS */
    DWORD   SegGs;         /* 08c */
    DWORD   SegFs;         /* 090 */
    DWORD   SegEs;         /* 094 */
    DWORD   SegDs;         /* 098 */

    /* These are selected by CONTEXT_INTEGER */
    DWORD   Edi;           /* 09c */
    DWORD   Esi;           /* 0a0 */
    DWORD   Ebx;           /* 0a4 */
    DWORD   Edx;           /* 0a8 */
    DWORD   Ecx;           /* 0ac */
    DWORD   Eax;           /* 0b0 */

    /* These are selected by CONTEXT_CONTROL */
    DWORD   Ebp;           /* 0b4 */
    DWORD   Eip;           /* 0b8 */
    DWORD   SegCs;         /* 0bc */
    DWORD   EFlags;        /* 0c0 */
    DWORD   Esp;           /* 0c4 */
    DWORD   SegSs;         /* 0c8 */

    BYTE    ExtendedRegisters[I386_MAXIMUM_SUPPORTED_EXTENSION];  /* 0xcc */
} I386_CONTEXT, WOW64_CONTEXT, *PWOW64_CONTEXT;

#define ARM64_MAX_BREAKPOINTS   8
#define ARM64_MAX_WATCHPOINTS   2
typedef struct _ARM64_NT_CONTEXT
{
    ULONG ContextFlags;                 /* 000 */
    /* CONTEXT_INTEGER */
    ULONG Cpsr;                         /* 004 */
    union
    {
        struct
        {
            DWORD64 X0;                 /* 008 */
            DWORD64 X1;                 /* 010 */
            DWORD64 X2;                 /* 018 */
            DWORD64 X3;                 /* 020 */
            DWORD64 X4;                 /* 028 */
            DWORD64 X5;                 /* 030 */
            DWORD64 X6;                 /* 038 */
            DWORD64 X7;                 /* 040 */
            DWORD64 X8;                 /* 048 */
            DWORD64 X9;                 /* 050 */
            DWORD64 X10;                /* 058 */
            DWORD64 X11;                /* 060 */
            DWORD64 X12;                /* 068 */
            DWORD64 X13;                /* 070 */
            DWORD64 X14;                /* 078 */
            DWORD64 X15;                /* 080 */
            DWORD64 X16;                /* 088 */
            DWORD64 X17;                /* 090 */
            DWORD64 X18;                /* 098 */
            DWORD64 X19;                /* 0a0 */
            DWORD64 X20;                /* 0a8 */
            DWORD64 X21;                /* 0b0 */
            DWORD64 X22;                /* 0b8 */
            DWORD64 X23;                /* 0c0 */
            DWORD64 X24;                /* 0c8 */
            DWORD64 X25;                /* 0d0 */
            DWORD64 X26;                /* 0d8 */
            DWORD64 X27;                /* 0e0 */
            DWORD64 X28;                /* 0e8 */
            DWORD64 Fp;                 /* 0f0 */
            DWORD64 Lr;                 /* 0f8 */
        };
        DWORD64 X[31];                  /* 008 */
    };
    /* CONTEXT_CONTROL */
    DWORD64 Sp;                         /* 100 */
    DWORD64 Pc;                         /* 108 */
    /* CONTEXT_FLOATING_POINT */
    ARM64_NT_NEON128 V[32];             /* 110 */
    DWORD Fpcr;                         /* 310 */
    DWORD Fpsr;                         /* 314 */
    /* CONTEXT_DEBUG_REGISTERS */
    DWORD Bcr[ARM64_MAX_BREAKPOINTS];   /* 318 */
    DWORD64 Bvr[ARM64_MAX_BREAKPOINTS]; /* 338 */
    DWORD Wcr[ARM64_MAX_WATCHPOINTS];   /* 378 */
    DWORD64 Wvr[ARM64_MAX_WATCHPOINTS]; /* 380 */
} ARM64_NT_CONTEXT, *PARM64_NT_CONTEXT;

typedef struct _M128A {
    ULONGLONG Low;
    LONGLONG High;
} M128A, *PM128A;

#pragma pack()
typedef struct _XSAVE_FORMAT {
    uint16_t ControlWord;        /* 000 */
    uint16_t StatusWord;         /* 002 */
    uint8_t TagWord;            /* 004 */
    uint8_t Reserved1;          /* 005 */
    uint16_t ErrorOpcode;        /* 006 */
    uint32_t ErrorOffset;       /* 008 */
    uint16_t ErrorSelector;      /* 00c */
    uint16_t Reserved2;          /* 00e */
    uint32_t DataOffset;        /* 010 */
    uint16_t DataSelector;       /* 014 */
    uint16_t Reserved3;          /* 016 */
    uint32_t MxCsr;             /* 018 */
    uint32_t MxCsr_Mask;        /* 01c */
    __uint128_t FloatRegisters[8]; /* 020 */
    __uint128_t XmmRegisters[16];  /* 0a0 */
    uint8_t Reserved4[96];      /* 1a0 */
} XSAVE_FORMAT, *PXSAVE_FORMAT;

static void fpux_to_fpu( I386_FLOATING_SAVE_AREA *fpu, const _XSAVE_FORMAT *fpux )
{
    unsigned int i, tag, stack_top;

    fpu->ControlWord   = fpux->ControlWord;
    fpu->StatusWord    = fpux->StatusWord;
    fpu->ErrorOffset   = fpux->ErrorOffset;
    fpu->ErrorSelector = fpux->ErrorSelector | (fpux->ErrorOpcode << 16);
    fpu->DataOffset    = fpux->DataOffset;
    fpu->DataSelector  = fpux->DataSelector;
    fpu->Cr0NpxState   = fpux->StatusWord | 0xffff0000;

    stack_top = (fpux->StatusWord >> 11) & 7;
    fpu->TagWord = 0xffff0000;
    for (i = 0; i < 8; i++)
    {
        memcpy( &fpu->RegisterArea[10 * i], &fpux->FloatRegisters[i], 10 );
        if (!(fpux->TagWord & (1 << i)))
            tag = 3;  /* empty */
        else
        {
            auto *reg = reinterpret_cast<const M128A *>(&fpux->FloatRegisters[(i - stack_top) & 7]);
            if ((reg->High & 0x7fff) == 0x7fff)  /* exponent all ones */
                tag = 2;  /* special */
            else if (!(reg->High & 0x7fff))  /* exponent all zeroes */
            {
                if (reg->Low) tag = 2;  /* special */
                else tag = 1;  /* zero */
            }
            else
            {
                if (reg->Low >> 63) tag = 0;  /* valid */
                else tag = 2;  /* special */
            }
        }
        fpu->TagWord |= tag << (2 * i);
    }
}
