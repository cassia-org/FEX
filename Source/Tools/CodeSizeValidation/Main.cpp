#include "DummyHandlers.h"
#include "FEXCore/Core/Context.h"
#include "FEXCore/Debug/InternalThreadState.h"
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/File.h>
#include <FEXCore/Utils/FileLoading.h>
#include <FEXCore/Utils/LogManager.h>

namespace CodeSize {
  class CodeSizeValidation final {
    public:
      struct InstructionStats {
        uint64_t GuestCodeInstructions{};
        uint64_t HostCodeInstructions{};

        uint64_t HeaderSize{};
        uint64_t TailSize{};
      };

      using CodeLines = fextl::vector<fextl::string>;
      using InstructionData = std::pair<InstructionStats, CodeLines>;

      bool ParseMessage(char const *Message);

      InstructionData *GetDataForRIP(uint64_t RIP) {
        return &RIPToStats[RIP];
      }

      bool InfoPrintingDisabled() const {
        return SetupInfoDisabled;
      }

      void CalculateBaseStats(FEXCore::Context::Context *CTX, FEXCore::Core::InternalThreadState *Thread);
    private:
      void ClearStats() {
        RIPToStats.clear();
      }

      void SetBaseStats(InstructionStats const &NewBase) {
        BaseStats = NewBase;
      }

      void CalculateDifferenceBetweenStats(InstructionData *Nop, InstructionData *Fence);

      uint64_t CurrentRIPParse{};
      bool ConsumingDisassembly{};
      InstructionData *CurrentStats{};
      InstructionStats BaseStats{};

      fextl::unordered_map<uint64_t, InstructionData> RIPToStats;
      bool SetupInfoDisabled{};
  };

  constexpr std::string_view RIPMessage = "RIP: 0x";
  constexpr std::string_view GuestCodeMessage = "Guest Code instructions: ";
  constexpr std::string_view HostCodeMessage = "Host Code instructions: ";
  constexpr std::string_view DisassembleBeginMessage = "Disassemble Begin";
  constexpr std::string_view DisassembleEndMessage = "Disassemble End";
  constexpr std::string_view BlowUpMsg = "Blow-up Amt: ";

  bool CodeSizeValidation::ParseMessage(char const *Message) {
    // std::string_view doesn't have contains until c++23.
    std::string_view MessageView {Message};
    if (MessageView.find(RIPMessage) != MessageView.npos) {
      // New RIP found
      std::string_view RIPView = std::string_view{Message + RIPMessage.size()};
      std::from_chars(RIPView.data(), RIPView.end(), CurrentRIPParse, 16);
      CurrentStats = &RIPToStats[CurrentRIPParse];
      return false;
    }

    if (MessageView.find(GuestCodeMessage) != MessageView.npos) {
      std::string_view CodeSizeView = std::string_view{Message + GuestCodeMessage.size()};
      std::from_chars(CodeSizeView.data(), CodeSizeView.end(), CurrentStats->first.GuestCodeInstructions);
      return false;
    }
    if (MessageView.find(HostCodeMessage) != MessageView.npos) {
      std::string_view CodeSizeView = std::string_view{Message + HostCodeMessage.size()};
      std::from_chars(CodeSizeView.data(), CodeSizeView.end(), CurrentStats->first.HostCodeInstructions);

      CurrentStats->first.HostCodeInstructions -= BaseStats.HostCodeInstructions;
      return false;
    }
    if (MessageView.find(DisassembleBeginMessage) != MessageView.npos) {
      ConsumingDisassembly = true;
      // Just so the output isn't a mess.
      return false;
    }
    if (MessageView.find(DisassembleEndMessage) != MessageView.npos) {
      ConsumingDisassembly = false;
      // Just so the output isn't a mess.

      // Remove the header and tails.
      if (BaseStats.HeaderSize) {
        CurrentStats->second.erase(CurrentStats->second.begin(), CurrentStats->second.begin() + BaseStats.HeaderSize);
      }
      if (BaseStats.TailSize) {
        CurrentStats->second.erase(CurrentStats->second.end() - BaseStats.TailSize, CurrentStats->second.end());
      }
      return false;
    }

    if (MessageView.find(BlowUpMsg) != MessageView.npos) {
      return false;
    }

    if (ConsumingDisassembly) {
      // Currently consuming disassembly. Each line will be a single line of disassembly.
      CurrentStats->second.push_back(Message);
      return false;
    }

    return true;
  }

  void CodeSizeValidation::CalculateDifferenceBetweenStats(InstructionData *Nop, InstructionData *Fence) {
    // Expected format.
    // adr x0, #-0x4 (addr 0x7fffe9880054)
    // str x0, [x28, #184]
    // dmb sy
    // ldr x0, pc+8 (addr 0x7fffe988006c)
    // blr x0
    // unallocated (Unallocated)
    // udf #0x7fff
    // unallocated (Unallocated)
    // udf #0x0
    //
    // First two lines are the header.
    // Next comes the implementation (0 instruction size for nop, 1 instruction for fence)
    // After that is the tail.

    const auto &NOPCode = Nop->second;
    const auto &FENCECode = Fence->second;

    LOGMAN_THROW_A_FMT(NOPCode.size() < FENCECode.size(), "NOP code must be smaller than fence!");
    for (size_t i = 0; i < NOPCode.size(); ++i) {
      const auto &NOPLine = NOPCode.at(i);
      const auto &FENCELine = FENCECode.at(i);

      const auto NOPmnemonic = std::string_view(NOPLine.data(), NOPLine.find(' '));
      const auto FENCEmnemonic = std::string_view(FENCELine.data(), FENCELine.find(' '));

      if (NOPmnemonic != FENCEmnemonic) {
        // Headersize of a block is now `i` number of instructions.
        Nop->first.HeaderSize = i;

        // Tail size is going to be the remaining size
        Nop->first.TailSize = NOPCode.size() - i;
        break;
      }
    }

    SetBaseStats(Nop->first);
  }

  void CodeSizeValidation::CalculateBaseStats(FEXCore::Context::Context *CTX, FEXCore::Core::InternalThreadState *Thread) {
    SetupInfoDisabled = true;

    // Known hardcoded instructions that will generate blocks of particular sizes.
    // NOP will never generate any instructions.
    constexpr static uint8_t NOP[] = {
      0x90,
    };

    // MFENCE will always generate a block with one instruction.
    constexpr static uint8_t MFENCE[] = {
      0x0f, 0xae, 0xf0,
    };

    // Compile the NOP.
    CTX->CompileRIP(Thread, (uint64_t)NOP);
    // Gather the stats for the NOP.
    auto NOPStats = GetDataForRIP((uint64_t)NOP);

    // Compile MFence
    CTX->CompileRIP(Thread, (uint64_t)MFENCE);

    // Get MFence stats.
    auto MFENCEStats = GetDataForRIP((uint64_t)MFENCE);

    // Now scan the difference in disasembly between NOP and MFENCE to remove the header and tail.
    // Just searching for first instruction change.

    CalculateDifferenceBetweenStats(NOPStats, MFENCEStats);
    // Now that the stats have been cleared. Clear our currentStats.
    ClearStats();

    // Invalidate the code ranges to be safe.
    CTX->InvalidateGuestCodeRange(Thread, (uint64_t)NOP, sizeof(NOP));
    CTX->InvalidateGuestCodeRange(Thread, (uint64_t)MFENCE, sizeof(MFENCE));
    SetupInfoDisabled = false;
  }

  static CodeSizeValidation Validation{};
}

void MsgHandler(LogMan::DebugLevels Level, char const *Message) {
  const char *CharLevel{nullptr};

  switch (Level) {
  case LogMan::NONE:
    CharLevel = "NONE";
    break;
  case LogMan::ASSERT:
    CharLevel = "ASSERT";
    break;
  case LogMan::ERROR:
    CharLevel = "ERROR";
    break;
  case LogMan::DEBUG:
    CharLevel = "DEBUG";
    break;
  case LogMan::INFO:
    CharLevel = "Info";
    // Disassemble information is sent through the Info log level.
    if (!CodeSize::Validation.ParseMessage(Message)) {
      return;
    }
    if (CodeSize::Validation.InfoPrintingDisabled()) {
      return;
    }
    break;
  default:
    CharLevel = "???";
    break;
  }
  fextl::fmt::print("[{}] {}\n", CharLevel, Message);
}

void AssertHandler(char const *Message) {
  fextl::fmt::print("[ASSERT] {}\n", Message);

  // make sure buffers are flushed
  fflush(nullptr);
}

struct TestInfo {
  char TestInst[128];
  uint64_t Optimal;
  int64_t ExpectedInstructionCount;
  uint64_t CodeSize;
  uint32_t Cookie;
  uint8_t Code[];
};

struct TestHeader {
  uint64_t Bitness;
  uint64_t NumTests{};
  uint64_t EnabledHostFeatures;
  uint64_t DisabledHostFeatures;
  TestInfo Tests[];
};

static fextl::vector<char> TestData;
static TestHeader const *TestHeaderData{};

static bool TestInstructions(FEXCore::Context::Context *CTX, FEXCore::Core::InternalThreadState *Thread, const char *UpdatedInstructionCountsPath) {
  LogMan::Msg::IFmt("Compiling code");

  // Tell FEXCore to compile all the instructions upfront.
  TestInfo const *CurrentTest = &TestHeaderData->Tests[0];
  for (size_t i = 0; i < TestHeaderData->NumTests; ++i) {
    uint64_t CodeRIP = (uint64_t)&CurrentTest->Code[0];
    // Compile the INST.
    CTX->CompileRIP(Thread, CodeRIP);

    // Go to the next test.
    CurrentTest = reinterpret_cast<TestInfo const*>(&CurrentTest->Code[CurrentTest->CodeSize]);
  }

  bool TestsPassed {true};
  bool InstructionCountChanged {};

  // Get all the data for the instructions compiled.
  CurrentTest = &TestHeaderData->Tests[0];
  for (size_t i = 0; i < TestHeaderData->NumTests; ++i) {
    uint64_t CodeRIP = (uint64_t)CurrentTest->Code;
    // Get the instruction stats.
    auto INSTStats = CodeSize::Validation.GetDataForRIP(CodeRIP);

    LogMan::Msg::IFmt("Testing instruction '{}': {} host instructions", CurrentTest->TestInst, INSTStats->first.HostCodeInstructions);

    // Show the code if we know the implementation isn't optimal or if the count of instructions changed to something we didn't expect.
    bool ShouldShowCode = CurrentTest->Optimal == 0 ||
      INSTStats->first.HostCodeInstructions != CurrentTest->ExpectedInstructionCount;

    if (ShouldShowCode) {
      for (auto Line : INSTStats->second) {
        LogMan::Msg::EFmt("\t{}", Line);
      }
    }

    if (INSTStats->first.HostCodeInstructions != CurrentTest->ExpectedInstructionCount) {
      LogMan::Msg::EFmt("Fail: '{}': {} host instructions", CurrentTest->TestInst, INSTStats->first.HostCodeInstructions);
      LogMan::Msg::EFmt("Fail: Test took {} instructions but we expected {} instructions!", INSTStats->first.HostCodeInstructions, CurrentTest->ExpectedInstructionCount);
      InstructionCountChanged = true;

      if (CurrentTest->Optimal) {
        // Don't count the test as a failure if it's known non-optimal.
        TestsPassed = false;
      }
    }

    // Go to the next test.
    CurrentTest = reinterpret_cast<TestInfo const*>(&CurrentTest->Code[CurrentTest->CodeSize]);
  }

  if (UpdatedInstructionCountsPath) {
    // Unlink the file.
    unlink(UpdatedInstructionCountsPath);

    if (!InstructionCountChanged) {
      // If no instruction count changed then just return the results.
      return TestsPassed;
    }

    FEXCore::File::File FD(UpdatedInstructionCountsPath, FEXCore::File::FileModes::WRITE | FEXCore::File::FileModes::CREATE | FEXCore::File::FileModes::TRUNCATE);

    if (!FD.IsValid()) {
      // If we couldn't open the file then early exit this.
      LogMan::Msg::EFmt("Couldn't open {} for updating instruction counts", UpdatedInstructionCountsPath);
      return TestsPassed;
    }

    FD.Write("{\n", 2);

    CurrentTest = &TestHeaderData->Tests[0];
    for (size_t i = 0; i < TestHeaderData->NumTests; ++i) {
      uint64_t CodeRIP = (uint64_t)CurrentTest->Code;
      // Get the instruction stats.
      auto INSTStats = CodeSize::Validation.GetDataForRIP(CodeRIP);

      if (INSTStats->first.HostCodeInstructions != CurrentTest->ExpectedInstructionCount) {
        FD.Write(fextl::fmt::format("\t\"{}\": {},\n", CurrentTest->TestInst, INSTStats->first.HostCodeInstructions));
      }

      // Go to the next test.
      CurrentTest = reinterpret_cast<TestInfo const*>(&CurrentTest->Code[CurrentTest->CodeSize]);
    }

    // Print a null member
    FD.Write(fextl::fmt::format("\t\"\": \"\""));

    FD.Write("}\n", 2);
  }
  return TestsPassed;
}

bool LoadTests(const char *Path) {
  if (!FEXCore::FileLoading::LoadFile(TestData, Path)) {
    return false;
  }

  TestHeaderData = reinterpret_cast<TestHeader const*>(TestData.data());
  return true;
}

int main(int argc, char **argv, char **const envp) {
  FEXCore::Allocator::GLIBCScopedFault GLIBFaultScope;
  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(MsgHandler);
  FEXCore::Config::Initialize();
  FEXCore::Config::Load();
  FEXCore::Config::ReloadMetaLayer();

  if (argc < 2) {
    LogMan::Msg::EFmt("Usage: {} <Test binary> [Changed instruction count.json]", argv[0]);
    return 1;
  }

  if (!LoadTests(argv[1])) {
    LogMan::Msg::EFmt("Couldn't load tests from {}", argv[1]);
    return 1;
  }

  // Setup configurations that this tool needs
  // Maximum one instruction.
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_MAXINST, "1");
  // IRJIT. Only works on JITs.
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_CORE, fextl::fmt::format("{}", static_cast<uint64_t>(FEXCore::Config::CONFIG_IRJIT)));
  // Enable block disassembly.
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_DISASSEMBLE, fextl::fmt::format("{}", static_cast<uint64_t>(FEXCore::Config::Disassemble::BLOCKS | FEXCore::Config::Disassemble::STATS)));
  // Choose bitness.
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_IS64BIT_MODE, TestHeaderData->Bitness == 64 ? "1" : 0);

  // Host feature override. Only supports overriding SVE width.
  enum HostFeatures {
    FEATURE_SVE128 = (1U << 0),
    FEATURE_SVE256 = (1U << 1),
    FEATURE_CLZERO = (1U << 2),
  };

  uint64_t SVEWidth = 0;
  uint64_t HostFeatureControl{};
  if (TestHeaderData->EnabledHostFeatures & FEATURE_SVE128) {
    HostFeatureControl |= static_cast<uint64_t>(FEXCore::Config::HostFeatures::ENABLESVE);
    SVEWidth = 128;
  }
  if (TestHeaderData->EnabledHostFeatures & FEATURE_SVE256) {
    HostFeatureControl |= static_cast<uint64_t>(FEXCore::Config::HostFeatures::ENABLEAVX);
    SVEWidth = 256;
  }
  if (TestHeaderData->EnabledHostFeatures & FEATURE_CLZERO) {
    HostFeatureControl |= static_cast<uint64_t>(FEXCore::Config::HostFeatures::ENABLECLZERO);
  }

  if (TestHeaderData->DisabledHostFeatures & FEATURE_SVE128) {
    HostFeatureControl |= static_cast<uint64_t>(FEXCore::Config::HostFeatures::DISABLESVE);
  }
  if (TestHeaderData->DisabledHostFeatures & FEATURE_SVE256) {
    HostFeatureControl |= static_cast<uint64_t>(FEXCore::Config::HostFeatures::DISABLEAVX);
  }
  if (TestHeaderData->DisabledHostFeatures & FEATURE_CLZERO) {
    HostFeatureControl |= static_cast<uint64_t>(FEXCore::Config::HostFeatures::DISABLECLZERO);
  }
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_HOSTFEATURES, fextl::fmt::format("{}", HostFeatureControl));
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_FORCESVEWIDTH, fextl::fmt::format("{}", SVEWidth));

  // Initialize static tables.
  FEXCore::Context::InitializeStaticTables(TestHeaderData->Bitness == 64 ? FEXCore::Context::MODE_64BIT : FEXCore::Context::MODE_32BIT);

  // Create FEXCore context.
  auto CTX = FEXCore::Context::Context::CreateNewContext();

  CTX->InitializeContext();
  auto SignalDelegation = FEX::DummyHandlers::CreateSignalDelegator();
  auto SyscallHandler = FEX::DummyHandlers::CreateSyscallHandler();

  CTX->SetSignalDelegator(SignalDelegation.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
  auto ParentThread = CTX->InitCore(0, 0);

  // Calculate the base stats for instruction testing.
  CodeSize::Validation.CalculateBaseStats(CTX.get(), ParentThread);

  // Test all the instructions.
  return TestInstructions(CTX.get(), ParentThread, argc >= 2 ? argv[2] : nullptr) ? 0 : 1;
}
