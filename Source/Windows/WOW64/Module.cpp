/*
$info$
tags: Bin|WOW64
desc: Implements the WOW64 BT module API using FEXCore
$end_info$
*/

// Thanks to André Zwing, whose ideas from https://github.com/AndreRH/hangover this code is based upon

#include <FEXCore/fextl/fmt.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/EnumOperators.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXHeaderUtils/TypeDefines.h>

#include "Common/Config.h"
#include "DummyHandlers.h"
#include "BTInterface.h"
#include "WineHelpers.h"

#include <cstdint>
#include <type_traits>
#include <atomic>
#include <mutex>
#include <utility>
#include <ntstatus.h>
#include <windef.h>
#include <winternl.h>
#include <wine/debug.h>
#include <wine/unixlib.h>

struct TLS {
  enum class Slot : size_t {
    ENTRY_CONTEXT = WOW64_TLS_MAX_NUMBER,
    THREAD_STATE = WOW64_TLS_MAX_NUMBER - 2,
  };

  _TEB *TEB;

  explicit TLS(_TEB *TEB) : TEB(TEB) {}

  CONTEXT *&EntryContext() const {
    return reinterpret_cast<CONTEXT *&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::ENTRY_CONTEXT)]);
  }

  FEXCore::Core::InternalThreadState *&ThreadState() const {
    return reinterpret_cast<FEXCore::Core::InternalThreadState *&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::THREAD_STATE)]);
  }
};

class WowSyscallHandler;

namespace {
  namespace BridgeInstrs {
    uint16_t Syscall{0x2ecd};
    uint16_t UnixCall{0x2ecd};
  }

  fextl::unique_ptr<FEXCore::Context::Context> CTX;
  fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> SignalDelegator;
  fextl::unique_ptr<WowSyscallHandler> SyscallHandler;

  SYSTEM_CPU_INFORMATION CpuInfo{};

  std::pair<NTSTATUS, TLS> GetThreadTLS(HANDLE Thread) {
    THREAD_BASIC_INFORMATION Info;
    const NTSTATUS Err = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), nullptr);
    return {Err, TLS{reinterpret_cast<_TEB *>(Info.TebBaseAddress)}};
  }

  TLS GetTLS() {
    return TLS{NtCurrentTeb()};
  }

  uint64_t GetWowTEB(void *TEB) {
    static constexpr size_t WowTEBOffsetMemberOffset{0x180c};
    return static_cast<uint64_t>(*reinterpret_cast<LONG *>(reinterpret_cast<uintptr_t>(TEB) + WowTEBOffsetMemberOffset)
                                 + reinterpret_cast<uint64_t>(TEB));
  }

  bool IsAddressInJit(uint64_t Address) {
    return GetTLS().ThreadState()->CPUBackend->IsAddressInCodeBuffer(Address);
  }
}

namespace Context {
  void LoadStateFromWowContext(FEXCore::Core::CPUState &State, uint64_t WowTEB, WOW64_CONTEXT *Context) {
    // General register state

    State.gregs[FEXCore::X86State::REG_RAX] = Context->Eax;
    State.gregs[FEXCore::X86State::REG_RBX] = Context->Ebx;
    State.gregs[FEXCore::X86State::REG_RCX] = Context->Ecx;
    State.gregs[FEXCore::X86State::REG_RDX] = Context->Edx;
    State.gregs[FEXCore::X86State::REG_RSI] = Context->Esi;
    State.gregs[FEXCore::X86State::REG_RDI] = Context->Edi;
    State.gregs[FEXCore::X86State::REG_RBP] = Context->Ebp;
    State.gregs[FEXCore::X86State::REG_RSP] = Context->Esp;

    State.rip = Context->Eip;

    for (size_t i = 0; i < FEXCore::Core::CPUState::NUM_EFLAG_BITS; ++i) {
      State.flags[i] = (Context->EFlags >> i) & 1;
    }

    State.es_idx = Context->SegEs & 0xffff;
    State.cs_idx = Context->SegCs & 0xffff;
    State.ss_idx = Context->SegSs & 0xffff;
    State.ds_idx = Context->SegDs & 0xffff;
    State.fs_idx = Context->SegFs & 0xffff;
    State.gs_idx = Context->SegGs & 0xffff;

    // The TEB is the only populated GDT entry by default
    State.gdt[(Context->SegFs & 0xffff) >> 3].base = WowTEB;
    State.fs_cached = WowTEB;
    State.es_cached = 0;
    State.cs_cached = 0;
    State.ss_cached = 0;
    State.ds_cached = 0;

    // Floating-point register state
    const auto *XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);

    memcpy(State.xmm.sse.data, XSave->XmmRegisters, sizeof(State.xmm.sse.data));
    memcpy(State.mm, XSave->FloatRegisters, sizeof(State.mm));

    State.FCW = XSave->ControlWord;
    State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (XSave->StatusWord >> 8) & 1;
    State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (XSave->StatusWord >> 9) & 1;
    State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (XSave->StatusWord >> 10) & 1;
    State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (XSave->StatusWord >> 14) & 1;
    State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (XSave->StatusWord >> 11) & 0b111;
    State.FTW = XSave->TagWord;
  }

  void StoreWowContextFromState(FEXCore::Core::CPUState &State, WOW64_CONTEXT *Context) {
    // General register state

    Context->Eax = State.gregs[FEXCore::X86State::REG_RAX];
    Context->Ebx = State.gregs[FEXCore::X86State::REG_RBX];
    Context->Ecx = State.gregs[FEXCore::X86State::REG_RCX];
    Context->Edx = State.gregs[FEXCore::X86State::REG_RDX];
    Context->Esi = State.gregs[FEXCore::X86State::REG_RSI];
    Context->Edi = State.gregs[FEXCore::X86State::REG_RDI];
    Context->Ebp = State.gregs[FEXCore::X86State::REG_RBP];
    Context->Esp = State.gregs[FEXCore::X86State::REG_RSP];

    Context->Eip = State.rip;

    Context->EFlags = 0;
    for (size_t i = 0; i < FEXCore::Core::CPUState::NUM_EFLAG_BITS; ++i) {
      Context->EFlags |= State.flags[i] << i;
    }

    Context->SegEs = State.es_idx;
    Context->SegCs = State.cs_idx;
    Context->SegSs = State.ss_idx;
    Context->SegDs = State.ds_idx;
    Context->SegFs = State.fs_idx;
    Context->SegGs = State.gs_idx;

    // Floating-point register state

    auto *XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);

    memcpy(XSave->XmmRegisters, State.xmm.sse.data, sizeof(State.xmm.sse.data));
    memcpy(XSave->FloatRegisters, State.mm, sizeof(State.mm));

    XSave->ControlWord = State.FCW;
    XSave->StatusWord =
      (State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] << 11) |
      (State.flags[FEXCore::X86State::X87FLAG_C0_LOC] << 8) |
      (State.flags[FEXCore::X86State::X87FLAG_C1_LOC] << 9) |
      (State.flags[FEXCore::X86State::X87FLAG_C2_LOC] << 10) |
      (State.flags[FEXCore::X86State::X87FLAG_C3_LOC] << 14);
    XSave->TagWord = State.FTW;

    WineHelpers::fpux_to_fpu(&Context->FloatSave, XSave);
  }

  NTSTATUS FlushThreadStateContext(HANDLE Thread) {
    const auto [Err, TLS] = GetThreadTLS(Thread);
    if (Err) {
      return Err;
    }

    WOW64_CONTEXT TmpWowContext{
      .ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_EXTENDED_REGISTERS
    };

    Context::StoreWowContextFromState(TLS.ThreadState()->CurrentFrame->State, &TmpWowContext);
    return RtlWow64SetThreadContext(Thread, &TmpWowContext);
  }

  bool HandleUnalignedAccess(CONTEXT *Context) {
    if (!GetTLS().ThreadState()->CPUBackend->IsAddressInCodeBuffer(Context->Pc)) {
      return false;
    }

    FEX_CONFIG_OPT(ParanoidTSO, PARANOIDTSO);
    const auto Result = FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(ParanoidTSO(), Context->Pc, &Context->X0);
    if (!Result.first) {
      return false;
    }

    Context->Pc += Result.second;
    return true;
  }
}

namespace Logging {
  void MsgHandler(LogMan::DebugLevels Level, char const *Message) {
    const auto Output = fextl::fmt::format("[{}][{:X}] {}\n", LogMan::DebugLevelStr(Level), GetCurrentThreadId(), Message);
    __wine_dbg_output(Output.c_str());
  }

  void AssertHandler(char const *Message) {
    const auto Output = fextl::fmt::format("[ASSERT] {}\n", Message);
    __wine_dbg_output(Output.c_str());
  }

  void Init() {
    LogMan::Throw::InstallHandler(AssertHandler);
    LogMan::Msg::InstallHandler(MsgHandler);
  }
}

class WowSyscallHandler : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
public:
  WowSyscallHandler() {
    OSABI = FEXCore::HLE::SyscallOSABI::OS_WIN32;
  }

  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame *Frame, FEXCore::HLE::SyscallArguments *Args) override {
    const uint64_t ReturnRIP = *(uint32_t *)(Frame->State.gregs[FEXCore::X86State::REG_RSP]); // Return address from the stack
    uint64_t ReturnRSP = Frame->State.gregs[FEXCore::X86State::REG_RSP] + 4; // Stack pointer after popping return address
    uint64_t ReturnRAX = 0;

    // APCs/User Callbacks end up calling into the JIT from Wow64SystemService, and since the FEX return stack pointer
    // is stored in TLS, the reentrant call ends up overwriting the callers stored return stack location. Stash it here
    // to avoid that breaking returns used in thread suspend
    const auto StashedStackLocation = Frame->ReturningStackLocation;
    if (Frame->State.rip == (uint64_t)&BridgeInstrs::UnixCall) {
      struct StackLayout {
        unixlib_handle_t Handle;
        UINT32 ID;
        ULONG32 Args;
      } *StackArgs = reinterpret_cast<StackLayout *>(ReturnRSP);

      ReturnRSP += sizeof(StackLayout);

      // Skip unlocking the JIT context here since the atomic accesses hurt unix call perfomance quite badly
      // NOTE: this will break suspension if there are any infinitely-blocking unix calls
      ReturnRAX = static_cast<uint64_t>(__wine_unix_call(StackArgs->Handle, StackArgs->ID, ULongToPtr(StackArgs->Args)));
    } else if (Frame->State.rip == (uint64_t)&BridgeInstrs::Syscall) {
      const uint64_t EntryRAX = Frame->State.gregs[FEXCore::X86State::REG_RAX];

      ReturnRAX = static_cast<uint64_t>(Wow64SystemServiceEx(static_cast<UINT>(EntryRAX),
                                                             reinterpret_cast<UINT *>(ReturnRSP + 4)));

    }
    // If a new context has been set, use it directly and don't return to the syscall caller
    if (Frame->State.rip == (uint64_t)&BridgeInstrs::Syscall ||
        Frame->State.rip == (uint64_t)&BridgeInstrs::UnixCall) {
      Frame->State.gregs[FEXCore::X86State::REG_RAX] = ReturnRAX;
      Frame->State.gregs[FEXCore::X86State::REG_RSP] = ReturnRSP;
      Frame->State.rip = ReturnRIP;
    }
    Frame->ReturningStackLocation = StashedStackLocation;

    // NORETURNEDRESULT causes this result to be ignored since we restore all registers back from memory after a syscall anyway
    return 0;
  }

  FEXCore::HLE::SyscallABI GetSyscallABI(uint64_t Syscall) override {
    return { .NumArgs = 0, .HasReturn = false, .HostSyscallNumber = -1 };
  }

  FEXCore::HLE::AOTIRCacheEntryLookupResult LookupAOTIRCacheEntry(FEXCore::Core::InternalThreadState *Thread, uint64_t GuestAddr) override {
    return {0, 0};
  }
};

void BTCpuProcessInit() {
  Logging::Init();
  FEX::Config::InitializeConfigs();
  FEXCore::Config::Initialize();
  FEXCore::Config::AddLayer(FEX::Config::CreateGlobalMainLayer());
  FEXCore::Config::AddLayer(FEX::Config::CreateMainLayer());
  FEXCore::Config::Load();
  FEXCore::Config::ReloadMetaLayer();

  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_IS_INTERPRETER, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_INTERPRETER_INSTALLED, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_IS64BIT_MODE, "0");

  // Not applicable to Windows
  FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_TSOAUTOMIGRATION, "0");

  FEXCore::Context::InitializeStaticTables(FEXCore::Context::MODE_32BIT);

  SignalDelegator = fextl::make_unique<FEX::DummyHandlers::DummySignalDelegator>();
  SyscallHandler = fextl::make_unique<WowSyscallHandler>();

  CTX = FEXCore::Context::Context::CreateNewContext();
  CTX->InitializeContext();
  CTX->SetSignalDelegator(SignalDelegator.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
  CTX->InitCore(0, 0);

  WineHelpers::get_cpuinfo([](uint32_t Function, uint32_t Leaf, uint32_t *Regs) {
    const auto Result = CTX->RunCPUIDFunction(Function, Leaf);
    Regs[0] = Result.eax;
    Regs[1] = Result.ebx;
    Regs[2] = Result.ecx;
    Regs[3] = Result.edx;
  }, &CpuInfo);
}

NTSTATUS BTCpuThreadInit() {
  GetTLS().ThreadState() = CTX->CreateThread(nullptr, 0);

  return STATUS_SUCCESS;
}

NTSTATUS BTCpuThreadTerm(HANDLE Thread) {
  const auto [Err, TLS] = GetThreadTLS(Thread);
  if (Err) {
    return Err;
  }

  CTX->DestroyThread(TLS.ThreadState());
  return STATUS_SUCCESS;
}

void *BTCpuGetBopCode() {
  return &BridgeInstrs::Syscall;
}

void *__wine_get_unix_opcode() {
  return &BridgeInstrs::UnixCall;
}

NTSTATUS BTCpuGetContext(HANDLE Thread, HANDLE Process, void *Unknown, WOW64_CONTEXT *Context) {
  auto [Err, TLS] = GetThreadTLS(Thread);
  if (Err) {
    return Err;
  }

  if (Err = Context::FlushThreadStateContext(Thread); Err) {
    return Err;
  }

  return RtlWow64GetThreadContext(Thread, Context);
}

NTSTATUS BTCpuSetContext(HANDLE Thread, HANDLE Process, void *Unknown, WOW64_CONTEXT *Context) {
  auto [Err, TLS] = GetThreadTLS(Thread);
  if (Err) {
    return Err;
  }


  // Back-up the input context incase we've been passed the CPU area (the flush below would wipe it out otherwise)
  WOW64_CONTEXT TmpContext = *Context;

  if (Err = Context::FlushThreadStateContext(Thread); Err) {
    return Err;
  }

  // Merge the input context into the CPU area then pass the full context into the JIT
  if (Err = RtlWow64SetThreadContext(Thread, &TmpContext); Err) {
    return Err;
  }

  TmpContext.ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_EXTENDED_REGISTERS;

  if (Err = RtlWow64GetThreadContext(Thread, &TmpContext); Err) {
    return Err;
  }

  Context::LoadStateFromWowContext(TLS.ThreadState()->CurrentFrame->State, GetWowTEB(TLS.TEB), &TmpContext);
  return STATUS_SUCCESS;
}

void BTCpuSimulate() {
  CONTEXT entry_context;
  RtlCaptureContext(&entry_context);

  // APC handling calls BTCpuSimulate from syscalls and then use NtContinue to return to the previous context,
  // to avoid the saved context being clobbered in this case only save the entry context highest in the stack
  if (!GetTLS().EntryContext() ||  GetTLS().EntryContext()->Sp <= entry_context.Sp) {
    GetTLS().EntryContext() = &entry_context;
  }

  while (1) {
    Context::LockJITContext();
    CTX->ExecuteThread(GetTLS().ThreadState());
    Context::UnlockJITContext();
  }
}

NTSTATUS BTCpuResetToConsistentState(EXCEPTION_POINTERS *Ptrs) {
  auto *Context = Ptrs->ContextRecord;
  const auto *Exception = Ptrs->ExceptionRecord;

  if (Exception->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT && Context::HandleUnalignedAccess(Context)) {
    LogMan::Msg::DFmt("Handled unaligned atomic: new pc: {:X}", Context->Pc);
    NtContinue(Context, FALSE);
  }

  return STATUS_SUCCESS;
}

BOOLEAN WINAPI BTCpuIsProcessorFeaturePresent(UINT Feature) {
  switch (Feature) {
    case PF_FLOATING_POINT_PRECISION_ERRATA:
      return FALSE;
    case PF_FLOATING_POINT_EMULATED:
      return FALSE;
    case PF_COMPARE_EXCHANGE_DOUBLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_CX8);
    case PF_MMX_INSTRUCTIONS_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_MMX);
     case PF_XMMI_INSTRUCTIONS_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE);
    case PF_3DNOW_INSTRUCTIONS_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_3DNOW);
    case PF_RDTSC_INSTRUCTION_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_TSC);
    case PF_PAE_ENABLED:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_PAE);
    case PF_XMMI64_INSTRUCTIONS_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE2);
    case PF_SSE3_INSTRUCTIONS_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE3);
    case PF_SSSE3_INSTRUCTIONS_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSSE3);
    case PF_XSAVE_ENABLED:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_XSAVE);
    case PF_COMPARE_EXCHANGE128:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_CX128);
    case PF_SSE_DAZ_MODE_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_DAZ);
    case PF_NX_ENABLED:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_NX);
    case PF_SECOND_LEVEL_ADDRESS_TRANSLATION:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_2NDLEV);
    case PF_VIRT_FIRMWARE_ENABLED:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_VIRT);
    case PF_RDWRFSGSBASE_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_RDFS);
    case PF_FASTFAIL_AVAILABLE:
      return TRUE;
    case PF_SSE4_1_INSTRUCTIONS_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE41);
    case PF_SSE4_2_INSTRUCTIONS_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_SSE42);
    case PF_AVX_INSTRUCTIONS_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_AVX);
    case PF_AVX2_INSTRUCTIONS_AVAILABLE:
      return !!(CpuInfo.ProcessorFeatureBits & CPU_FEATURE_AVX2);
    default:
      LogMan::Msg::DFmt( "Unknown CPU feature: {:X}", Feature);
      return FALSE;
  }
}

BOOLEAN BTCpuUpdateProcessorInformation(SYSTEM_CPU_INFORMATION *Info) {
  Info->ProcessorArchitecture = CpuInfo.ProcessorArchitecture;
  Info->ProcessorLevel = CpuInfo.ProcessorLevel;
  Info->ProcessorRevision = CpuInfo.ProcessorRevision;
  Info->ProcessorFeatureBits = CpuInfo.ProcessorFeatureBits;
  return TRUE;
}
