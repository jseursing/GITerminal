#include "HookManager.h"
#include <inttypes.h>
#include <TlHelp32.h>

// Static definitions
std::vector<Breakpoint> HookManager::Breakpoints;
std::vector<TrampolineHook> HookManager::Trampolines;

/****************************************************************************************
/ Function: Initialize
/ Notes: Applies page guard attribute to the memory page.
/***************************************************************************************/
void HookManager::Initialize(bool addHandler)
{
  AddVectoredExceptionHandler(1, ExceptionFilter);
}

/****************************************************************************************
/ Function: RegisterBP
/ Notes: Add hook
/***************************************************************************************/
void HookManager::RegisterBP(Breakpoint& hook)
{
  printf("[notice] RegisterHook 0x%llX 0x%llX 0x%llX\n", 
         hook.address, hook.RegisterTypes, hook.Modification);

  // If this address already exists, modify the REG and Modify options
  bool addHook = true;
  for (unsigned int i = 0; i < Breakpoints.size(); ++i)
  {
    if (hook.address == Breakpoints[i].address)
    {
      Breakpoints[i].RegisterTypes = hook.RegisterTypes;
      Breakpoints[i].Modification = hook.Modification;
      addHook = false;
      break;
    }
  }

  // If the hook was not found, add it
  if (true == addHook)
  {
    Breakpoints.push_back(hook);

    switch (hook.type)
    {
    case Breakpoint::MEM_PAGE:
      if (false == VEHHook(hook.address))
      {
        printf("[error] Failed hooking 0x%llX %llX\n", hook.address, GetLastError());
      }
      break;
    }
  }
}

/****************************************************************************************
/ Function: UnRegisterBP
/ Notes: Add hook
/***************************************************************************************/
bool HookManager::UnRegisterBP(uint64_t address)
{
  bool success = false;
  for (unsigned int i = 0; i < Breakpoints.size(); ++i)
  {
    if (address == Breakpoints[i].address)
    {
      Breakpoints.erase(Breakpoints.begin() + i);
      success = true;
      break;
    }
  }

  return success;
}

/****************************************************************************************
/ Function: RegisterTrampoline
/ Notes: Add hook
/***************************************************************************************/
void HookManager::RegisterTrampoline(TrampolineHook& hook)
{
  bool addHook = true;
  for (unsigned int i = 0; i < Trampolines.size(); ++i)
  {
    if (hook.address == Trampolines[i].address)
    {
      addHook = false;
      break;
    }
  }

  if (true == addHook)
  {
    Trampolines.push_back(hook);
  }
}

/****************************************************************************************
/ Function: ToggleTrampoline32
/ Notes: Add hook
/***************************************************************************************/
void HookManager::ToggleTrampoline32(uint64_t address, bool enable)
{
  for (unsigned int i = 0; i < Trampolines.size(); ++i)
  {
    if (address == Trampolines[i].address)
    {
      Trampoline32(&Trampolines[i], enable);
      break;
    }
  }
}

/****************************************************************************************
/ Function: ToggleTrampoline64
/ Notes: Add hook
/***************************************************************************************/
void HookManager::ToggleTrampoline64(uint64_t address, bool enable)
{
  for (unsigned int i = 0; i < Trampolines.size(); ++i)
  {
    if (address == Trampolines[i].address)
    {
      Trampoline64(&Trampolines[i], enable);
      break;
    }
  }
}

/****************************************************************************************
/ Function: Trampoline32
/ Notes: Add hook
/***************************************************************************************/
void HookManager::Trampoline32(TrampolineHook* hook, bool enable)
{
  printf("[notice] Trampoline32 0x%llX 0x%llX \n", hook->address, hook->codecave);

  unsigned char x32Jump[5] =
  {
    0xE9, 0x00, 0x00, 0x00, 0x00
  };
  *reinterpret_cast<uint32_t*>(&x32Jump[1]) = 
    static_cast<uint32_t>(hook->codecave) - hook->address - 5;

  unsigned long oldP;
  if (TRUE == VirtualProtect(reinterpret_cast<void*>(hook->address),
                             hook->hook_length,
                             PAGE_EXECUTE_READWRITE,
                             &oldP))
  {
    if (true == enable)
    {
      // Store old memory
      if (0 != hook->originalMem)
      {
        delete[] hook->originalMem;
      }
      hook->originalMem = new uint8_t[hook->hook_length];
      memcpy(hook->originalMem, reinterpret_cast<void*>(hook->address), hook->hook_length);

      // Write hook
      int nopCount = hook->hook_length - sizeof(x32Jump);
      if (0 < nopCount)
      {
        memset(reinterpret_cast<void*>(hook->address + sizeof(x32Jump)), 0x90, nopCount);
      }
      memcpy(reinterpret_cast<void*>(hook->address), x32Jump, sizeof(x32Jump));
    }
    else
    {
      memcpy(reinterpret_cast<void*>(hook->address), hook->originalMem, hook->hook_length);
    }

    VirtualProtect(reinterpret_cast<void*>(hook->address), hook->hook_length, oldP, &oldP);
    return;
  }

  printf("[error] Trampoline32 Failed: %08X \n", GetLastError());
}

/****************************************************************************************
/ Function: Trampoline64
/ Notes: Add hook
/***************************************************************************************/
void HookManager::Trampoline64(TrampolineHook* hook, bool enable)
{
  printf("[notice] Trampoline64 0x%llX 0x%llX \n", hook->address, hook->codecave);

  unsigned char x64Jump[14] =
  {
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  *reinterpret_cast<uint64_t*>(&x64Jump[6]) = hook->codecave;

  unsigned long oldP;
  if (TRUE == VirtualProtect(reinterpret_cast<void*>(hook->address), 
                             hook->hook_length,
                             PAGE_EXECUTE_READWRITE, 
                             &oldP))
  {
    if (true == enable)
    {
      // Store old memory
      if (0 != hook->originalMem)
      {
        delete[] hook->originalMem;
      }
      hook->originalMem = new uint8_t[hook->hook_length];
      memcpy(hook->originalMem, reinterpret_cast<void*>(hook->address), hook->hook_length);

      // Write hook
      int nopCount = hook->hook_length - sizeof(x64Jump);
      if (0 < nopCount)
      {
        memset(reinterpret_cast<void*>(hook->address + sizeof(x64Jump)), 0x90, nopCount);
      }
      memcpy(reinterpret_cast<void*>(hook->address), x64Jump, sizeof(x64Jump));
    }
    else
    {
      memcpy(reinterpret_cast<void*>(hook->address), hook->originalMem, hook->hook_length);
    }

    VirtualProtect(reinterpret_cast<void*>(hook->address), hook->hook_length, oldP, &oldP);
    return;
  }
  
  printf("[error] Trampoline64 Failed: %08X \n", GetLastError());
}

/****************************************************************************************
/ Function: ToggleHook
/ Notes: Add/Remove hook
/***************************************************************************************/
bool HookManager::ToggleHook(uint64_t address, bool enable)
{
  bool success = false;
  for (unsigned int i = 0; i < Breakpoints.size(); ++i)
  {
    if (address == Breakpoints[i].address)
    {
      Breakpoints[i].Enabled = enable;
      success = true;
      break;
    }
  }

  return success;
}

/****************************************************************************************
/ Function: VEHHook
/ Notes: Applies page guard attribute to the memory page.
/***************************************************************************************/
std::vector<uint64_t> HookManager::SignatureScan(unsigned char* src,
                                                 uint64_t len,
                                                 std::string target,
                                                 bool useMask,
                                                 unsigned int count)
{
  std::vector<unsigned char> arr;
  std::vector<bool> mask;

  // Remove all spaces
  std::string strRep = target;
  StrReplace(" ", "", strRep, 0);

  // Build our array and mask container
  if (0 == (strRep.length() % 2))
  {
    for (uint64_t i = 0; i < strRep.length() - 1; i += 2)
    {
      bool wildCard = (true == useMask) && ('?' == strRep[i]);
      mask.push_back(wildCard);
      if (true == wildCard)
      {
        arr.push_back(0);

        // Support 1 '?' ...
        if (((i + 1) < strRep.length()) && ('?' != strRep[i + 1]))
        {
          --i; // Step back one so we don't skip a nibble!
        }
      }
      else
      {
        arr.push_back(strtoul(strRep.substr(i, 2).c_str(), 0, 16) & 0xFF);
      }
    }
  }

  // Begin scan
  std::vector<uint64_t> offsets;
  if (0 < arr.size())
  {
    for (unsigned int i = 0; i < (len - arr.size()); ++i)
    {
      for (unsigned int j = 0; j < arr.size(); ++j)
      {
        if (((src[i + j] != arr[j]) && (false == mask[j])))
        {
          break;
        }
        else if (j == (arr.size() - 1))
        {
          offsets.push_back(i);
        }
      }

      // Exit if we exceed the count.
      if ((0 < count) && (offsets.size() >= count))
      {
        break;
      }
    }
  }

  return offsets;
}

/****************************************************************************************
/ Function: VEHHook
/ Notes: Applies page guard attribute to the memory page.
/***************************************************************************************/
bool HookManager::VEHHook(uint64_t address)
{
  unsigned long oldP = 0;
  unsigned long newP = PAGE_EXECUTE_READ | PAGE_GUARD;
  return (FALSE != VirtualProtect(reinterpret_cast<void*>(address), 1, newP, &oldP));
}

/****************************************************************************************
/ Function: Trampoline
/ Notes: Applies detour/trampoline.
/***************************************************************************************/
void HookManager::Trampoline(uint64_t address, uint64_t destination, unsigned int len)
{
  *reinterpret_cast<unsigned char*>(address) = 0xE9;
  *reinterpret_cast<unsigned int*>(address+1) = (destination - address) - 5;
  for (unsigned int i = 5; i < len; ++i)
  {
    *reinterpret_cast<unsigned char*>(address + i) = 0x90;
  }
}

/****************************************************************************************
/ Function: ExceptionFilter
/ Notes: Filters all exceptions
/***************************************************************************************/
LONG __stdcall HookManager::ExceptionFilter(PEXCEPTION_POINTERS exception)
{
  // For memory read/write
  if (STATUS_ACCESS_VIOLATION == exception->ExceptionRecord->ExceptionCode)
  {
    return EXCEPTION_CONTINUE_EXECUTION;
  }

  if (STATUS_GUARD_PAGE_VIOLATION == exception->ExceptionRecord->ExceptionCode)
  {
    ProcessInterrupt(exception);
    exception->ContextRecord->EFlags |= 0x100; // Single-step
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  
  if (STATUS_SINGLE_STEP == exception->ExceptionRecord->ExceptionCode)
  {
    for (unsigned int i = 0; i < Breakpoints.size(); ++i)
    {
      VEHHook(Breakpoints[i].address);
    }

    return EXCEPTION_CONTINUE_EXECUTION;
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

/****************************************************************************************
/ Function: ProcessInterrupt
/ Notes: Handles hooked addresses.
/***************************************************************************************/
void HookManager::ProcessInterrupt(PEXCEPTION_POINTERS exception)
{
  uint64_t address = reinterpret_cast<uint64_t>
                     (exception->ExceptionRecord->ExceptionAddress);

  for (unsigned int i = 0; i < Breakpoints.size(); ++i)
  {
    if (true == Breakpoints[i].Enabled) // Skip disabled hooks
    {
      if (address == Breakpoints[i].address)
      {
        // If the Modification specifies Verbose, output context record..
        if (Breakpoint::VERBOSE & Breakpoints[i].Modification)
        {
          printf("//// CONTEXT RECORD VERBOSE OUTPUT ////\n"
                 "// RIP: 0x%llX\n"
                 "// RAX: 0x%llX \tRCX: 0x%llX \tRDX: 0x%llX \tRBX: 0x%llX\n"
                 "// RBP: 0x%llX \tRSP: 0x%llX \tRSI: 0x%llX \tRDI: 0x%llX\n"
                 "// CF[%s] \tPF[%s] \tAF[%s] \tZF[%s] \tSF[%s] \tIF[%s] \tOF[%s] \tDF[%s]\n\n",
                 exception->ContextRecord->Rip,
                 exception->ContextRecord->Rax,
                 exception->ContextRecord->Rcx,
                 exception->ContextRecord->Rdx,
                 exception->ContextRecord->Rbx,
                 exception->ContextRecord->Rbp,
                 exception->ContextRecord->Rsp,
                 exception->ContextRecord->Rsi,
                 exception->ContextRecord->Rdi,
                 (exception->ContextRecord->EFlags & Breakpoint::CF_MASK ? "X" : " "),
                 (exception->ContextRecord->EFlags & Breakpoint::PF_MASK ? "X" : " "),
                 (exception->ContextRecord->EFlags & Breakpoint::AF_MASK ? "X" : " "),
                 (exception->ContextRecord->EFlags & Breakpoint::ZF_MASK ? "X" : " "),
                 (exception->ContextRecord->EFlags & Breakpoint::SF_MASK ? "X" : " "),
                 (exception->ContextRecord->EFlags & Breakpoint::IF_MASK ? "X" : " "),
                 (exception->ContextRecord->EFlags & Breakpoint::OF_MASK ? "X" : " "),
                 (exception->ContextRecord->EFlags & Breakpoint::DF_MASK ? "X" : " "));
        }

        // If the modification specifies invoke, call the function
        if (Breakpoint::INVOKE & Breakpoints[i].Modification)
        {
          if (0 != Breakpoints[i].InvokeFunc)
          {
            reinterpret_cast<void (*)(PEXCEPTION_POINTERS)>(Breakpoints[i].InvokeFunc)(exception);
          }
        }

        //
        // Begin modifying Registers and Flags
        //
        if (Breakpoints[i].RegisterTypes & Breakpoint::EAX)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
            case Breakpoint::SET:
              exception->ContextRecord->Rax = Breakpoints[i].EAX;
              break;
            case Breakpoint::UNSET:
              exception->ContextRecord->Rax = 0;
              break;
            case Breakpoint::GET:
              *(Breakpoints[i].RegisterValue) = exception->ContextRecord->Rax;
              break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::ECX)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->Rcx = Breakpoints[i].ECX;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->Rcx = 0;
            break;
          case Breakpoint::GET:
            printf("[notice] %llX ECX[%llX] stored\n", address, exception->ContextRecord->Rcx);
            *(Breakpoints[i].RegisterValue) = exception->ContextRecord->Rcx;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::EDX)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->Rdx = Breakpoints[i].EDX;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->Rdx = 0;
            break;
          case Breakpoint::GET:
            *(Breakpoints[i].RegisterValue) = exception->ContextRecord->Rdx;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::EBX)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->Rbx = Breakpoints[i].EBX;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->Rbx = 0;
            break;
          case Breakpoint::GET:
            *(Breakpoints[i].RegisterValue) = exception->ContextRecord->Rbx;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::EBP)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->Rbp = Breakpoints[i].EBP;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->Rbp = 0;
            break;
          case Breakpoint::GET:
            *(Breakpoints[i].RegisterValue) = exception->ContextRecord->Rbp;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::ESP)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->Rsp = Breakpoints[i].ESP;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->Rsp = 0;
            break;
          case Breakpoint::GET:
            *(Breakpoints[i].RegisterValue) = exception->ContextRecord->Rsp;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::ESI)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->Rsi = Breakpoints[i].ESI;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->Rsi = 0;
            break;
          case Breakpoint::GET:
            *(Breakpoints[i].RegisterValue) = exception->ContextRecord->Rsi;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::EDI)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->Rdi = Breakpoints[i].EDI;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->Rdi = 0;
            break;
          case Breakpoint::GET:
            *(Breakpoints[i].RegisterValue) = exception->ContextRecord->Rdi;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::EIP)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            printf("[notice] Updating %llX EIP->%llX\n", address, Breakpoints[i].RIP);
            exception->ContextRecord->Rip = Breakpoints[i].EIP;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->Rip = 0;
            break;
          case Breakpoint::GET:
            *(Breakpoints[i].RegisterValue) = exception->ContextRecord->Rip;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::CF)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->EFlags |= Breakpoint::CF_MASK;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->EFlags &= ~(Breakpoint::CF_MASK);
            break;
          case Breakpoint::XOR:
            exception->ContextRecord->EFlags ^= Breakpoint::CF_MASK;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::PF)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->EFlags |= Breakpoint::PF_MASK;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->EFlags &= ~(Breakpoint::PF_MASK);
            break;
          case Breakpoint::XOR:
            exception->ContextRecord->EFlags ^= Breakpoint::PF_MASK;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::AF)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->EFlags |= Breakpoint::AF_MASK;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->EFlags &= ~(Breakpoint::AF_MASK);
            break;
          case Breakpoint::XOR:
            exception->ContextRecord->EFlags ^= Breakpoint::AF_MASK;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::ZF)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->EFlags |= Breakpoint::ZF_MASK;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->EFlags &= ~Breakpoint::ZF_MASK;
            break;
          case Breakpoint::XOR:
            exception->ContextRecord->EFlags ^= Breakpoint::ZF_MASK;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::SF)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->EFlags |= Breakpoint::SF_MASK;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->EFlags &= ~(Breakpoint::SF_MASK);
            break;
          case Breakpoint::XOR:
            exception->ContextRecord->EFlags ^= Breakpoint::SF_MASK;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::TF)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->EFlags |= Breakpoint::TF_MASK;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->EFlags &= ~(Breakpoint::TF_MASK);
            break;
          case Breakpoint::XOR:
            exception->ContextRecord->EFlags ^= Breakpoint::TF_MASK;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::IF)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->EFlags |= Breakpoint::IF_MASK;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->EFlags &= ~(Breakpoint::IF_MASK);
            break;
          case Breakpoint::XOR:
            exception->ContextRecord->EFlags ^= Breakpoint::IF_MASK;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::DF)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->EFlags |= Breakpoint::DF_MASK;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->EFlags &= ~(Breakpoint::DF_MASK);
            break;
          case Breakpoint::XOR:
            exception->ContextRecord->EFlags ^= Breakpoint::DF_MASK;
            break;
          }
        }
        if (Breakpoints[i].RegisterTypes & Breakpoint::OF)
        {
          switch (Breakpoints[i].Modification & Breakpoint::MASK)
          {
          case Breakpoint::SET:
            exception->ContextRecord->EFlags |= Breakpoint::OF_MASK;
            break;
          case Breakpoint::UNSET:
            exception->ContextRecord->EFlags &= ~(Breakpoint::OF_MASK);
            break;
          case Breakpoint::XOR:
            exception->ContextRecord->EFlags ^= Breakpoint::OF_MASK;
            break;
          }
        }

        break;
      }
    }
  }
}

/****************************************************************************************
/ Function: StrReplace
/ Notes: None.
/***************************************************************************************/
void HookManager::StrReplace(const char* delim, 
                             const char* rep,
                             std::string& str, 
                             unsigned int count)
{
  unsigned int counter = 0;
  size_t next = str.find(delim);
  while ((std::string::npos != next) && (next <= str.length()))
  {
    std::string temp;
    if (0 == memcmp(delim, str.substr(next).c_str(), strlen(delim)))
    {
      temp = str.substr(0, next) + str.substr(next + strlen(delim));
    }
    else
    {
      temp = str.substr(0, next) + str.substr(next + 1);
    }

    str = temp;
    next = str.find(delim);

    // Exit if we exceed count
    if ((0 < count) && (counter >= count))
    {
      break;
    }
  }
}