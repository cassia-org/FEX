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
#include <FEXCore/Utils/Threads.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "Context.h"


class DummySyscallHandler : public FEXCore::HLE::SyscallHandler {
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

static fextl::unique_ptr<FEXCore::Context::Context> CTX;
DummySignalDelegator SignalDelegator;
DummySyscallHandler SyscallHandler;

extern "C" __attribute__((visibility ("default"))) void ho_A() {
  FEXCore::Config::Initialize();
  FEXCore::Config::ReloadMetaLayer();

  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_IS_INTERPRETER, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_INTERPRETER_INSTALLED, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_IS64BIT_MODE, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_TSOENABLED, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_MULTIBLOCK, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_X87REDUCEDPRECISION, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_BLOCKJITNAMING, "1");

  FEXCore::Context::InitializeStaticTables( FEXCore::Context::MODE_32BIT);

  CTX = FEXCore::Context::Context::CreateNewContext();
  CTX->InitializeContext();
  CTX->SetSignalDelegator(&SignalDelegator);
  CTX->SetSyscallHandler(&SyscallHandler);
}

static thread_local FEXCore::Core::InternalThreadState *Thread;
static FEXCore::Core::InternalThreadState *MainThread;

static void LoadStateFromWinContext(FEXCore::Core::CPUState& State, uint64_t WowTeb, WOW64_CONTEXT* Context) {
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

  State.es_idx = Context->SegEs & 0xFFFF;
  State.cs_idx = Context->SegCs & 0xFFFF;
  State.ss_idx = Context->SegSs & 0xFFFF;
  State.ds_idx = Context->SegDs & 0xFFFF;
  State.fs_idx = Context->SegFs & 0xFFFF;
  State.gs_idx = Context->SegGs & 0xFFFF;

  // The TEB is the only populated GDT entry by default
  State.gdt[(Context->SegFs & 0xFFFF) >> 3].base = WowTeb;
  State.fs_cached = WowTeb;
  State.es_cached = 0;
  State.cs_cached = 0;
  State.ss_cached = 0;
  State.ds_cached = 0;

  // Floating-point register state

  auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);

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

static void StoreWinContextFromState(FEXCore::Core::CPUState& State, WOW64_CONTEXT* Context) {
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

  auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);

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

  fpux_to_fpu(&Context->FloatSave, XSave);
}

extern "C" __attribute__((visibility ("default"))) void ho_B(uint64_t WowTeb, WOW64_CONTEXT* Context) {
  if (!MainThread) {
    Thread = CTX->InitCore(Context->Eip, Context->Esp);
    MainThread = Thread;
  }

  if (!Thread) {
    FEXCore::Core::CPUState NewThreadState{};
    memset(NewThreadState.gdt, 0, sizeof(FEXCore::Core::CPUState::gdt));
    NewThreadState.es_cached = NewThreadState.cs_cached = NewThreadState.ss_cached = NewThreadState.ds_cached = NewThreadState.gs_cached = NewThreadState.fs_cached = 0;
    Thread = CTX->CreateThread(&NewThreadState, MainThread->ThreadManager.GetTID());
    Thread->DestroyedByParent = 1;
  }

  static constexpr uint32_t RequiredContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_EXTENDED_REGISTERS;

  if ((Context->ContextFlags & RequiredContextFlags) != RequiredContextFlags) {
    fprintf(stderr, "Incomplete context!\n");
  }

  LoadStateFromWinContext(Thread->CurrentFrame->State, WowTeb, Context);

  CTX->ExecutionThread(Thread);

  StoreWinContextFromState(Thread->CurrentFrame->State, WowTeb, Context);
}

extern "C" __attribute__((visibility ("default"))) void ho_invalidate_code_range(uint64_t Start, uint64_t Length) {
  if (!CTX) {
    return;
  }

  CTX->InvalidateGuestCodeRange(Thread, Start, Length);
}