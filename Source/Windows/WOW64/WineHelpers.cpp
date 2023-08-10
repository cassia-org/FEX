/*
 * Copyright 2023 Alexandre Julliard
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

#include <windef.h>

#include "WineHelpers.h"

namespace WineHelpers {

// From dlls/wow64cpu/cpu.c
void fpux_to_fpu( WOW64_FLOATING_SAVE_AREA *fpu, const _XSAVE_FORMAT *fpux )
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
        if (!(fpux->TagWord & (1 << i))) tag = 3;  /* empty */
        else
        {
            auto *reg = reinterpret_cast<const M128A *>(&fpux->FloatRegisters[(i - stack_top) & 7]);
            if ((reg->High & 0x7fff) == 0x7fff)  /* exponent all ones */
            {
                tag = 2;  /* special */
            }
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

// From dlls/ntdll/unix/system.c
#define AUTH	0x68747541	/* "Auth" */
#define ENTI	0x69746e65	/* "enti" */
#define CAMD	0x444d4163	/* "cAMD" */

#define GENU	0x756e6547	/* "Genu" */
#define INEI	0x49656e69	/* "ineI" */
#define NTEL	0x6c65746e	/* "ntel" */

void get_cpuinfo( do_cpuid_t do_cpuid, SYSTEM_CPU_INFORMATION *info )
{
    UINT32 regs[4], regs2[4], regs3[4];
    ULONGLONG features;

    info->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;

    /* We're at least a 386 */
    features = CPU_FEATURE_VME | CPU_FEATURE_X86 | CPU_FEATURE_PGE;
    info->ProcessorLevel = 3;

    do_cpuid( 0x00000000, 0, regs );  /* get standard cpuid level and vendor name */
    if (regs[0]>=0x00000001)   /* Check for supported cpuid version */
    {
        do_cpuid( 0x00000001, 0, regs2 ); /* get cpu features */
        if (regs2[3] & (1 << 3 )) features |= CPU_FEATURE_PSE;
        if (regs2[3] & (1 << 4 )) features |= CPU_FEATURE_TSC;
        if (regs2[3] & (1 << 6 )) features |= CPU_FEATURE_PAE;
        if (regs2[3] & (1 << 8 )) features |= CPU_FEATURE_CX8;
        if (regs2[3] & (1 << 11)) features |= CPU_FEATURE_SEP;
        if (regs2[3] & (1 << 12)) features |= CPU_FEATURE_MTRR;
        if (regs2[3] & (1 << 15)) features |= CPU_FEATURE_CMOV;
        if (regs2[3] & (1 << 16)) features |= CPU_FEATURE_PAT;
        if (regs2[3] & (1 << 23)) features |= CPU_FEATURE_MMX;
        if (regs2[3] & (1 << 24)) features |= CPU_FEATURE_FXSR;
        if (regs2[3] & (1 << 25)) features |= CPU_FEATURE_SSE;
        if (regs2[3] & (1 << 26)) features |= CPU_FEATURE_SSE2;
        if (regs2[2] & (1 << 0 )) features |= CPU_FEATURE_SSE3;
        if (regs2[2] & (1 << 9 )) features |= CPU_FEATURE_SSSE3;
        if (regs2[2] & (1 << 13)) features |= CPU_FEATURE_CX128;
        if (regs2[2] & (1 << 19)) features |= CPU_FEATURE_SSE41;
        if (regs2[2] & (1 << 20)) features |= CPU_FEATURE_SSE42;
        if (regs2[2] & (1 << 27)) features |= CPU_FEATURE_XSAVE;
        if (regs2[2] & (1 << 28)) features |= CPU_FEATURE_AVX;
        if ((regs2[3] & (1 << 26)) && (regs2[3] & (1 << 24))) /* has SSE2 and FXSAVE/FXRSTOR */
            features |= CPU_FEATURE_DAZ;

        if (regs[0] >= 0x00000007)
        {
            do_cpuid( 0x00000007, 0, regs3 ); /* get extended features */
            if (regs3[1] & (1 << 5)) features |= CPU_FEATURE_AVX2;
        }

        if (regs[1] == AUTH && regs[3] == ENTI && regs[2] == CAMD)
        {
            info->ProcessorLevel = (regs2[0] >> 8) & 0xf; /* family */
            if (info->ProcessorLevel == 0xf)  /* AMD says to add the extended family to the family if family is 0xf */
                info->ProcessorLevel += (regs2[0] >> 20) & 0xff;

            /* repack model and stepping to make a "revision" */
            info->ProcessorRevision  = ((regs2[0] >> 16) & 0xf) << 12; /* extended model */
            info->ProcessorRevision |= ((regs2[0] >> 4 ) & 0xf) << 8;  /* model          */
            info->ProcessorRevision |= regs2[0] & 0xf;                 /* stepping       */

            do_cpuid( 0x80000000, 0, regs );  /* get vendor cpuid level */
            if (regs[0] >= 0x80000001)
            {
                do_cpuid( 0x80000001, 0, regs2 );  /* get vendor features */
                if (regs2[2] & (1 << 2))   features |= CPU_FEATURE_VIRT;
                if (regs2[3] & (1 << 20))  features |= CPU_FEATURE_NX;
                if (regs2[3] & (1 << 27))  features |= CPU_FEATURE_TSC;
                if (regs2[3] & (1u << 31)) features |= CPU_FEATURE_3DNOW;
            }
        }
        else if (regs[1] == GENU && regs[3] == INEI && regs[2] == NTEL)
        {
            info->ProcessorLevel = ((regs2[0] >> 8) & 0xf) + ((regs2[0] >> 20) & 0xff); /* family + extended family */
            if(info->ProcessorLevel == 15) info->ProcessorLevel = 6;

            /* repack model and stepping to make a "revision" */
            info->ProcessorRevision  = ((regs2[0] >> 16) & 0xf) << 12; /* extended model */
            info->ProcessorRevision |= ((regs2[0] >> 4 ) & 0xf) << 8;  /* model          */
            info->ProcessorRevision |= regs2[0] & 0xf;                 /* stepping       */

            if(regs2[2] & (1 << 5))  features |= CPU_FEATURE_VIRT;
            if(regs2[3] & (1 << 21)) features |= CPU_FEATURE_DS;

            do_cpuid( 0x80000000, 0, regs );  /* get vendor cpuid level */
            if (regs[0] >= 0x80000001)
            {
                do_cpuid( 0x80000001, 0, regs2 );  /* get vendor features */
                if (regs2[3] & (1 << 20)) features |= CPU_FEATURE_NX;
                if (regs2[3] & (1 << 27)) features |= CPU_FEATURE_TSC;
            }
        }
        else
        {
            info->ProcessorLevel = (regs2[0] >> 8) & 0xf; /* family */

            /* repack model and stepping to make a "revision" */
            info->ProcessorRevision = ((regs2[0] >> 4 ) & 0xf) << 8;  /* model    */
            info->ProcessorRevision |= regs2[0] & 0xf;                /* stepping */
        }
    }
    info->ProcessorFeatureBits = features;
}

}
