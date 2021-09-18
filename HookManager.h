#pragma once
#include <string>
#include <vector>
#include <Windows.h>

//
// Breakpoint hook definition
//
struct Breakpoint
{
  enum RegType
  {
    NA = 0,
    EAX = 1,
    RAX = EAX,
    ECX = EAX * 2,
    RCX = ECX,
    EDX = ECX * 2,
    RDX = EDX,
    EBX = EDX * 2,
    RBX = EBX,
    EBP = EBX * 2,
    RBP = EBP,
    ESP = EBP * 2,
    RSP = ESP,
    ESI = ESP * 2,
    RSI = ESI,
    EDI = ESI * 2,
    RDI = EDI,
    EIP = EDI * 2,
    RIP = EIP,
    CF  = EIP * 2,
    PF  = CF * 2,
    AF  = PF * 2,
    ZF  = AF * 2,
    SF  = ZF * 2,
    TF  = SF * 2, 
    IF  = TF * 2,
    DF  = IF * 2,
    OF  = DF * 2
  };

  enum ModType
  {
    NONE    = 0,
    SET     = 1,
    UNSET   = 2,
    XOR     = 4,
    GET     = 8,
    MASK    = 15,
    INVOKE  = 16,
    VERBOSE = 32
  };

  enum BPType
  {
    MEM_PAGE,
    DEBUG_REG
  };

  uint64_t address;
  BPType type;
  unsigned char data[12];
  unsigned int length;
  CONTEXT context;
  RegType RegisterTypes;
  ModType Modification;
  uint64_t* RegisterValue;
  void* InvokeFunc;
  bool Enabled;

  Breakpoint() :
    address(0),
    type(BPType::MEM_PAGE),
    RegisterTypes(RegType::NA), 
    Modification(ModType::NONE), 
    RegisterValue(0), 
    InvokeFunc(0), 
    Enabled(false)
  {
  }

  void inline AppendReg(RegType reg)
  {
    this->RegisterTypes =  
      static_cast<RegType>(static_cast<unsigned int>(this->RegisterTypes) |
                           static_cast<unsigned int>(reg));
  }

  void inline AppendMod(ModType mod)
  {
    this->Modification =
      static_cast<ModType>(static_cast<unsigned int>(this->Modification) |
                           static_cast<unsigned int>(mod));
  }

  // Debugging constants
  static const unsigned int CF_MASK = 0x00000001;
  static const unsigned int PF_MASK = 0x00000004;
  static const unsigned int AF_MASK = 0x00000010;
  static const unsigned int ZF_MASK = 0x00000040;
  static const unsigned int SF_MASK = 0x00000080;
  static const unsigned int TF_MASK = 0x00000100;
  static const unsigned int IF_MASK = 0x00000200;
  static const unsigned int DF_MASK = 0x00000400;
  static const unsigned int OF_MASK = 0x00000800;
  static const unsigned int ON_EXECUTE_MASK = 0x00000001;
  static const unsigned int ON_WRITE_MASK = 0x00030000;      // C + 1
  static const unsigned int ON_READ_WRITE_MASK = 0x00030000; // C + 3 
};

//
// Trampoline hook definition
//
struct TrampolineHook
{
  uint64_t address;
  uint64_t codecave;
  uint32_t hook_length;
  uint8_t* originalMem;
};

class HookManager
{
public:
  static void Initialize(bool addHandler);
  static void RegisterBP(Breakpoint& hook);
  static bool UnRegisterBP(uint64_t address);
  static void RegisterTrampoline(TrampolineHook& hook);
  static void ToggleTrampoline32(uint64_t address, bool enable);
  static void ToggleTrampoline64(uint64_t address, bool enable);
  static void Trampoline32(TrampolineHook* hook, bool enable);
  static void Trampoline64(TrampolineHook* hook, bool enable);
  static bool ToggleHook(uint64_t address, bool enable);
  static std::vector<uint64_t> SignatureScan(unsigned char* src,
                                             uint64_t len,
                                             std::string target,
                                             bool useMask = true,
                                             unsigned int count = 1);

private:
  static bool VEHHook(uint64_t address);
  static void Trampoline(uint64_t address, uint64_t destination, unsigned int len);
  static LONG __stdcall ExceptionFilter(PEXCEPTION_POINTERS exception);
  static void ProcessInterrupt(PEXCEPTION_POINTERS exception);
  static void StrReplace(const char* delim, const char* rep,
                         std::string& str, unsigned int count);

  // Members
  static std::vector<Breakpoint> Breakpoints;
  static std::vector<TrampolineHook> Trampolines;
};

