/*
$info$
tags: Bin|FEXLoader
desc: Glues the ELF loader, FEXCore and LinuxSyscalls to launch an elf under fex
$end_info$
*/

#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Telemetry.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/Profiler.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <filesystem>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <sys/auxv.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include <fmt/format.h>
#include <sys/sysinfo.h>
#include <sys/signal.h>
#include <signal.h>

#define BYTE uint8_t
#define DWORD uint32_t
#define I386_SIZE_OF_80387_REGISTERS      80
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

class DummySyscallHandler: public FEXCore::HLE::SyscallHandler {
public:
  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame *Frame, FEXCore::HLE::SyscallArguments *Args) override {
    LOGMAN_MSG_A_FMT("Syscalls not implemented");
    return 0;
  }

  FEXCore::HLE::SyscallABI GetSyscallABI(uint64_t Syscall) override {
    LOGMAN_MSG_A_FMT("Syscalls not implemented");
    return {0, false, 0 };
  }

  FEXCore::HLE::AOTIRCacheEntryLookupResult LookupAOTIRCacheEntry(FEXCore::Core::InternalThreadState *Thread, uint64_t GuestAddr) override {
    return {0, 0};
  }
};

class DummySignalDelegator final : public FEXCore::SignalDelegator, public FEXCore::Allocator::FEXAllocOperators {
public:
  DummySignalDelegator() {}
  ~DummySignalDelegator() override {}

  void CheckXIDHandler() override {}

  void SignalThread(FEXCore::Core::InternalThreadState *Thread, FEXCore::Core::SignalEvent Event) override {}

protected:
  void HandleGuestSignal(FEXCore::Core::InternalThreadState *Thread, int Signal, void *Info, void *UContext) override {}

  void RegisterFrontendTLSState(FEXCore::Core::InternalThreadState *Thread) override {}
  void UninstallFrontendTLSState(FEXCore::Core::InternalThreadState *Thread) override {}

  void FrontendRegisterHostSignalHandler(int Signal, FEXCore::HostSignalDelegatorFunction Func, bool Required) override {}
  void FrontendRegisterFrontendHostSignalHandler(int Signal, FEXCore::HostSignalDelegatorFunction Func, bool Required) override {}
};

static fextl::unique_ptr<FEXCore::Context::Context> CTX;// = FEXCore::Context::Context::CreateNewContext();
extern "C" __attribute__((visibility ("default"))) void ho_A(void)
{
	FEXCore::Config::Initialize();
	FEXCore::Config::ReloadMetaLayer();

	FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_IS_INTERPRETER, "0");
	FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_INTERPRETER_INSTALLED, "0");
	FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_IS64BIT_MODE, "0");
    FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_TSOENABLED, "0");
    FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_MULTIBLOCK, "0");
    FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_X87REDUCEDPRECISION, "1");
    FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_BLOCKJITNAMING, "1");

	FEXCore::Context::InitializeStaticTables( FEXCore::Context::MODE_32BIT);

	CTX = FEXCore::Context::Context::CreateNewContext();
	CTX->InitializeContext();
	CTX->SetSignalDelegator(new DummySignalDelegator());
	CTX->SetSyscallHandler(new DummySyscallHandler());
}

static thread_local FEXCore::Core::InternalThreadState *Thread;
static FEXCore::Core::InternalThreadState *mainThread;

static thread_local int is_child_thread;
extern "C" __attribute__((visibility ("default"))) void ho_B(uint64_t wowteb, I386_CONTEXT* ctx)
{
    static int once;
    if (!once)
    {
        Thread = CTX->InitCore(ctx->Eip, ctx->Esp);
        mainThread = Thread;
        once = 1;
    }
    if (!Thread)
    {
        FEXCore::Core::CPUState NewThreadState{};
        memset(NewThreadState.gdt, 0, sizeof(FEXCore::Core::CPUState::gdt));
        NewThreadState.es_cached = NewThreadState.cs_cached = NewThreadState.ss_cached = NewThreadState.ds_cached = NewThreadState.gs_cached = NewThreadState.fs_cached = 0;
        Thread = CTX->CreateThread(&NewThreadState, mainThread->ThreadManager.GetTID());
        Thread->DestroyedByParent = 1;
        is_child_thread = 1;
    }

    if (ctx)
    {
        Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX] = ctx->Eax;
        Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RBX] = ctx->Ebx;
        Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RCX] = ctx->Ecx;
        Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RDX] = ctx->Edx;
        Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSI] = ctx->Esi;
        Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RDI] = ctx->Edi;
        Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RBP] = ctx->Ebp;
        Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP] = ctx->Esp;
    
        Thread->CurrentFrame->State.rip = ctx->Eip;

        /* flags? */
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_CF_LOC] = ctx->EFlags & 1;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_PF_LOC] = ctx->EFlags & 4;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_AF_LOC] = ctx->EFlags & 0x10;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_ZF_LOC] = ctx->EFlags & 0x40;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_SF_LOC] = ctx->EFlags & 0x80;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_TF_LOC] = ctx->EFlags & 0x100;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_IF_LOC] = ctx->EFlags & 0x200;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_DF_LOC] = ctx->EFlags & 0x400;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_OF_LOC] = ctx->EFlags & 0x800;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_NT_LOC] = ctx->EFlags & 0x4000;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_RF_LOC] = ctx->EFlags & 0x10000;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_VM_LOC] = ctx->EFlags & 0x20000;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_AC_LOC] = ctx->EFlags & 0x40000;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_VIF_LOC] = ctx->EFlags & 0x80000;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_VIP_LOC] = ctx->EFlags & 0x100000;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_ID_LOC] = ctx->EFlags & 0x200000;

        Thread->CurrentFrame->State.es_idx = ctx->SegEs & 0xFFFF;
        Thread->CurrentFrame->State.cs_idx = ctx->SegCs & 0xFFFF;
        Thread->CurrentFrame->State.ss_idx = ctx->SegSs & 0xFFFF;
        Thread->CurrentFrame->State.ds_idx = ctx->SegDs & 0xFFFF;
        Thread->CurrentFrame->State.fs_idx = ctx->SegFs & 0xFFFF;
        Thread->CurrentFrame->State.gs_idx = ctx->SegGs & 0xFFFF;

        // The TEB is the only populated GDT entry by default
        Thread->CurrentFrame->State.gdt[(ctx->SegFs & 0xFFFF) >> 3].base = wowteb;
        Thread->CurrentFrame->State.fs_cached = wowteb;
        Thread->CurrentFrame->State.es_cached = 0;
        Thread->CurrentFrame->State.cs_cached = 0;
        Thread->CurrentFrame->State.ss_cached = 0;
        Thread->CurrentFrame->State.ds_cached = 0;
        /*debug regs*/
        /*float*/
        memcpy(&Thread->CurrentFrame->State.mm[0], &ctx->FloatSave.RegisterArea[0],  10);
        memcpy(&Thread->CurrentFrame->State.mm[1], &ctx->FloatSave.RegisterArea[10], 10);
        memcpy(&Thread->CurrentFrame->State.mm[2], &ctx->FloatSave.RegisterArea[20], 10);
        memcpy(&Thread->CurrentFrame->State.mm[3], &ctx->FloatSave.RegisterArea[30], 10);
        memcpy(&Thread->CurrentFrame->State.mm[4], &ctx->FloatSave.RegisterArea[40], 10);
        memcpy(&Thread->CurrentFrame->State.mm[5], &ctx->FloatSave.RegisterArea[50], 10);
        memcpy(&Thread->CurrentFrame->State.mm[6], &ctx->FloatSave.RegisterArea[60], 10);
        memcpy(&Thread->CurrentFrame->State.mm[7], &ctx->FloatSave.RegisterArea[70], 10);

        Thread->CurrentFrame->State.FCW = ctx->FloatSave.ControlWord;
        Thread->CurrentFrame->State.FTW = ctx->FloatSave.TagWord;
        auto *win32_xstate = reinterpret_cast<XSAVE_FORMAT*>(ctx->ExtendedRegisters);
        memcpy(Thread->CurrentFrame->State.xmm.sse.data, win32_xstate->XmmRegisters, sizeof(Thread->CurrentFrame->State.xmm.sse.data));
        Thread->CurrentFrame->State.FCW = win32_xstate->ControlWord;
        Thread->CurrentFrame->State.FTW = win32_xstate->TagWord;

        Thread->CurrentFrame->State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (ctx->FloatSave.StatusWord >> 8) & 1;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (ctx->FloatSave.StatusWord >> 9) & 1;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (ctx->FloatSave.StatusWord >> 10) & 1;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (ctx->FloatSave.StatusWord >> 14) & 1;
        Thread->CurrentFrame->State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (ctx->FloatSave.StatusWord >> 11) & 0b111;
    } 

	CTX->ExecutionThread(Thread);

    if (ctx)
    {
        ctx->Eax = Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
        ctx->Ebx = Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RBX];
        ctx->Ecx = Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RCX];
        ctx->Edx = Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RDX];
        ctx->Esi = Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSI];
        ctx->Edi = Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RDI];
        ctx->Ebp = Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RBP];
        ctx->Esp = Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP];

        ctx->Eip = Thread->CurrentFrame->State.rip;

        /* flags? */
        ctx->EFlags = 0;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_CF_LOC]) << 0;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_PF_LOC]) << 2;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_AF_LOC]) << 4;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_ZF_LOC]) << 6;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_SF_LOC]) << 7;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_TF_LOC]) << 8;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_IF_LOC]) << 9;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_DF_LOC]) << 10;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_OF_LOC]) << 11;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_NT_LOC] ) << 14;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_RF_LOC] ) << 16;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_VM_LOC] ) << 17;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_AC_LOC] ) << 18;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_VIF_LOC]) << 19;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_VIP_LOC]) << 20;
        ctx->EFlags |= (!!Thread->CurrentFrame->State.flags[FEXCore::X86State::RFLAG_ID_LOC] ) << 21;

        ctx->SegEs = Thread->CurrentFrame->State.es_idx;
        ctx->SegCs = Thread->CurrentFrame->State.cs_idx;
        ctx->SegSs = Thread->CurrentFrame->State.ss_idx;
        ctx->SegDs = Thread->CurrentFrame->State.ds_idx;
        ctx->SegFs = Thread->CurrentFrame->State.fs_idx;
        ctx->SegGs = Thread->CurrentFrame->State.gs_idx;

        /*debug regs*/
        /*float*/
        memcpy(&ctx->FloatSave.RegisterArea[0],  &Thread->CurrentFrame->State.mm[0], 10);
        memcpy(&ctx->FloatSave.RegisterArea[10], &Thread->CurrentFrame->State.mm[1], 10);
        memcpy(&ctx->FloatSave.RegisterArea[20], &Thread->CurrentFrame->State.mm[2], 10);
        memcpy(&ctx->FloatSave.RegisterArea[30], &Thread->CurrentFrame->State.mm[3], 10);
        memcpy(&ctx->FloatSave.RegisterArea[40], &Thread->CurrentFrame->State.mm[4], 10);
        memcpy(&ctx->FloatSave.RegisterArea[50], &Thread->CurrentFrame->State.mm[5], 10);
        memcpy(&ctx->FloatSave.RegisterArea[60], &Thread->CurrentFrame->State.mm[6], 10);
        memcpy(&ctx->FloatSave.RegisterArea[70], &Thread->CurrentFrame->State.mm[7], 10);

        ctx->FloatSave.ControlWord = Thread->CurrentFrame->State.FCW;
        ctx->FloatSave.TagWord = Thread->CurrentFrame->State.FTW;
        auto *win32_xstate = reinterpret_cast<XSAVE_FORMAT*>(ctx->ExtendedRegisters);
        memcpy(win32_xstate->XmmRegisters, Thread->CurrentFrame->State.xmm.sse.data, sizeof(Thread->CurrentFrame->State.xmm.sse.data));
        win32_xstate->ControlWord = Thread->CurrentFrame->State.FCW;
        win32_xstate->TagWord = Thread->CurrentFrame->State.FTW;

        ctx->FloatSave.StatusWord =
        (Thread->CurrentFrame->State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] << 11) |
        (Thread->CurrentFrame->State.flags[FEXCore::X86State::X87FLAG_C0_LOC] << 8) |
        (Thread->CurrentFrame->State.flags[FEXCore::X86State::X87FLAG_C1_LOC] << 9) |
        (Thread->CurrentFrame->State.flags[FEXCore::X86State::X87FLAG_C2_LOC] << 10) |
        (Thread->CurrentFrame->State.flags[FEXCore::X86State::X87FLAG_C3_LOC] << 14);
    }
}

extern "C" __attribute__((visibility ("default"))) void ho_invalidate_code_range( uint64_t start, uint64_t length )
{
    if (!CTX)
        return;

    CTX->InvalidateGuestCodeRange(Thread, start, length);
}
