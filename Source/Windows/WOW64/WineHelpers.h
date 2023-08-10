#pragma once

#include <cstdint>
#include <windef.h>
#include <winternl.h>

namespace WineHelpers {
using do_cpuid_t = void (*)( uint32_t, uint32_t, uint32_t * );

void fpux_to_fpu( WOW64_FLOATING_SAVE_AREA *fpu, const _XSAVE_FORMAT *fpux );
void get_cpuinfo( do_cpuid_t do_cpuid, SYSTEM_CPU_INFORMATION *info );
}
