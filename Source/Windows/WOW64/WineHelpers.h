#pragma once

#include <cstdint>
#include <windef.h>
#include <winternl.h>

namespace WineHelpers {
void fpux_to_fpu( WOW64_FLOATING_SAVE_AREA *fpu, const _XSAVE_FORMAT *fpux );
}
