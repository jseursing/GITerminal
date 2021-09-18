#include "GITerminal.h"
#include "redactedDB.h"
#include "HookManager.h"
#include <inttypes.h>
#include <iostream>
#include <stdio.h>
#include <thread>
#include <Psapi.h>
#include <Windows.h>

/****************************************************************************************
/ Function: Instance
/ Notes: None.
/***************************************************************************************/
GITerminal& GITerminal::Instance()
{
  static GITerminal instance;
  return instance;
}

/****************************************************************************************
/ Function: Launch
/ Notes: None.
/***************************************************************************************/
void GITerminal::Launch()
{
  InitializeTerminal();

  InjectionHandle = std::async(std::launch::async, &GITerminal::InjectionThread);
  HotkeyHandle = std::async(std::launch::async, &GITerminal::HotkeyThread);
}

/****************************************************************************************
/ Function: Destroy
/ Notes: Undo everything...
/***************************************************************************************/
void GITerminal::Destroy()
{
  FreeConsole();
  ThreadExit = true;
}

/****************************************************************************************
/ Function: HotkeyThread
/ Notes: Hotkey Processing
/***************************************************************************************/
void GITerminal::HotkeyThread()
{
  bool chestToggle = false;
  bool freezeToggle = false;

  while (true)
  {
    if (0 != GetAsyncKeyState(VK_F11))
    {
      chestToggle = !chestToggle;
      redactedDB::ToggleChestESP(chestToggle);
      printf("[Chest ESP] %s\n", true == chestToggle ? "Enabled" : "Disabled");
    }

    if (0 != GetAsyncKeyState(VK_F12))
    {
      freezeToggle = !freezeToggle;
      redactedDB::ToggleFreeze(freezeToggle);
      printf("[Freeze] %s\n", true == freezeToggle ? "Enabled" : "Disabled");
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
}

/****************************************************************************************
/ Function: InjectionThread
/ Notes: Main processing.
/***************************************************************************************/
void GITerminal::InjectionThread()
{
  GITerminal* Terminal = &(GITerminal::Instance());

  // Initialize redacted Impact Database
  if (false == redactedDB::Initialize())
  {
    printf("[error] Failed initializing database.. aborting.\n");
    return;
  }
  
  // Status
  printf("[notice] Done\n\n");

  // Accept inputs from the user
  while (false == Terminal->ThreadExit)
  {
    std::cout << "~>";

    char input[256] = { 0 };
    std::cin.getline(input, sizeof(input));
    if (0 != strlen(input))
    {
      Terminal->ProcessCommand(input);
    }

    // Sleep to avoid excessive CPU usage
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

/****************************************************************************************
/ Function: ProcessCommand
/ Notes: None.
/***************************************************************************************/
void GITerminal::ProcessCommand(char* inputStr)
{
  // Help command
  if (0 == _strcmpi(HELP_STR, inputStr))
  {
    PrintHelp();
    return;
  }

  std::vector<std::string> tokens = Tokenize(inputStr, " ");
  if (1 < tokens.size())
  {
    //
    // Enable Commands
    //
    if (0 == _strcmpi(ENABLE_STR, tokens[0].c_str()))
    {
      if (0 == _strcmpi(CHEST_STR, tokens[1].c_str()))
      {
        redactedDB::ToggleChestESP(true);
        printf("[Chest ESP] Enabled\n");
      }
      else if (0 == _strcmpi(FREEZE_STR, tokens[1].c_str()))
      {
        redactedDB::ToggleFreeze(true);
        printf("[Freeze] Enabled\n");
      }
      return;
    }

    // 
    // Disable Commands
    //
    if (0 == _strcmpi(DISABLE_STR, tokens[0].c_str()))
    {
      if (0 == _strcmpi(CHEST_STR, tokens[1].c_str()))
      {
        redactedDB::ToggleChestESP(false);
        printf("[Chest ESP] Disabled\n");
      }
      else if (0 == _strcmpi(FREEZE_STR, tokens[1].c_str()))
      {
        redactedDB::ToggleFreeze(false);
        printf("[Freeze] Disabled\n");
      }
    }

    //
    // Signature Scan command
    //
    if (0 == _strcmpi(SCAN_STR, tokens[0].c_str()))
    {
      if (3 > tokens.size())
      {
        return; // Error
      }

      uint64_t scanBase = reinterpret_cast<uint64_t>(GetModuleHandleA(tokens[1].c_str()));
      uint64_t scanLength = 0;
      if (0 == scanBase)
      {
        printf("[error] Module %s not found.\n", tokens[1].c_str());
        return; // Error
      }

      // Retrieve Module length
      MODULEINFO moduleInfo;
      unsigned long miSize = sizeof(MODULEINFO);
      GetModuleInformation(GetCurrentProcess(),
                           reinterpret_cast<HMODULE>(scanBase),
                           &moduleInfo,
                           miSize);
      scanBase = reinterpret_cast<uint64_t>(moduleInfo.lpBaseOfDll);
      scanLength = moduleInfo.SizeOfImage;

      // Build signature and scan..
      std::string signature = "";
      for (unsigned int i = 2; i < tokens.size(); ++i)
      {
        signature += tokens[i];
      }
  
      printf("[Signature Scan] Scanning Base:0x%llX Length:0x%llX Signature:%s...\n",
             scanBase, scanLength, signature.data());

      unsigned char* ptr = reinterpret_cast<unsigned char*>(scanBase);
      std::vector<uint64_t> offsets = 
        HookManager::SignatureScan(ptr, scanLength, signature, true, 10);

      printf("Results: %d\n"
             "-----------\n",
             offsets.size());

      for (uint64_t offset : offsets)
      {
        printf("0x%llX \n", scanBase + offset);
      }
    }

    //
    // Hook command
    //
    if (0 == _strcmpi(HOOK_STR, tokens[0].c_str()))
    {
      if (3 > tokens.size())
      {
        return; // Error
      }

      Breakpoint hook;
      hook.Enabled = true;

      // If the address doesn't have ULL, add it
      std::string addrToken = tokens[1];
      if (std::string::npos == addrToken.find("ULL"))
      {
        addrToken += "ULL";
      }
      hook.address = strtoull(addrToken.c_str(), 0, 16);

      // Begin adding parameters for every token specified
      for (unsigned int i = 2; i < tokens.size(); ++i)
      {
        if (0 == _strcmpi(RAX_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::EAX);
          continue;
        }
        if (0 == _strcmpi(RCX_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::ECX);
          continue;
        }
        if (0 == _strcmpi(RDX_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::EDX);
          continue;
        }
        if (0 == _strcmpi(RBX_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::EBX);
          continue;
        }
        if (0 == _strcmpi(RBP_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::EBP);
          continue;
        }
        if (0 == _strcmpi(RSP_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::ESP);
          continue;
        }
        if (0 == _strcmpi(RSI_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::ESI);
          continue;
        }
        if (0 == _strcmpi(RDI_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::EDI);
          continue;
        }
        if (0 == _strcmpi(RIP_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::EIP);
          continue;
        }
        if (0 == _strcmpi(CF_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::CF);
          continue;
        }
        if (0 == _strcmpi(PF_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::PF);
          continue;
        }
        if (0 == _strcmpi(AF_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::AF);
          continue;
        }
        if (0 == _strcmpi(ZF_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::ZF);
          continue;
        }
        if (0 == _strcmpi(SF_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::SF);
          continue;
        }
        if (0 == _strcmpi(IF_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::IF);
          continue;
        }
        if (0 == _strcmpi(DF_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::DF);
          continue;
        }
        if (0 == _strcmpi(OF_STR, tokens[i].c_str()))
        {
          hook.AppendReg(Breakpoint::OF);
          continue;
        }
        if (0 == _strcmpi(SET_STR, tokens[i].c_str()))
        {
          hook.Modification = Breakpoint::SET;
          continue;
        }
        if (0 == _strcmpi(UNSET_STR, tokens[i].c_str()))
        {
          hook.Modification = Breakpoint::UNSET;
          continue;
        }
        if (0 == _strcmpi(XOR_STR, tokens[i].c_str()))
        {
          hook.Modification = Breakpoint::XOR;
          continue;
        }
        if (0 == _strcmpi(VERBOSE_STR, tokens[i].c_str()))
        {
          hook.AppendMod(Breakpoint::VERBOSE);
          continue;
        }
    
        // If we make it this far, we assume the value should be applied
        // to an already specified register...
        uint64_t regVal = strtoul(tokens[i].c_str(), 0, 16);
      
        if (Breakpoint::EAX & hook.RegisterTypes)
        {
          hook.context.Rax = regVal;
        }
        if (Breakpoint::ECX & hook.RegisterTypes)
        {
          hook.context.Rcx = regVal;
        }
        if (Breakpoint::EDX & hook.RegisterTypes)
        {
          hook.context.Rdx = regVal;
        }
        if (Breakpoint::EBX & hook.RegisterTypes)
        {
          hook.context.Rbx = regVal;
        }
        if (Breakpoint::EBP & hook.RegisterTypes)
        {
          hook.context.Rbp = regVal;
        }
        if (Breakpoint::ESP & hook.RegisterTypes)
        {
          hook.context.Rsp = regVal;
        }
        if (Breakpoint::ESI & hook.RegisterTypes)
        {
          hook.context.Rsi = regVal;
        }
        if (Breakpoint::EDI & hook.RegisterTypes)
        {
          hook.context.Rdi = regVal;
        }
        if (Breakpoint::EIP & hook.RegisterTypes)
        {
          hook.context.Rip = regVal;
        }
      }

      HookManager::RegisterBP(hook);
      printf("[notice] Hook registered\n");
    }

    //
    // Unhook command
    //
    if (0 == _strcmpi(UNHOOK_STR, tokens[0].c_str()))
    {
      if (2 > tokens.size())
      {
        return; // Error
      }

      std::string addrToken = tokens[1];
      if (std::string::npos == addrToken.find("ULL"))
      {
        addrToken += "ULL";
      }

      uint64_t address = strtoull(addrToken.c_str(), 0, 16);
      bool removed = HookManager::UnRegisterBP(address);
      printf("[notice] Hook removal %s\n", (true == removed ? "success" : "failed"));
    }

    //
    // Module command
    //
    if (0 == _strcmpi(MODULE_STR, tokens[0].c_str()))
    {
      if (2 > tokens.size())
      {
        return; // Error
      }
    
      MODULEINFO moduleInfo;
      unsigned long miSize = sizeof(MODULEINFO);
      GetModuleInformation(GetCurrentProcess(),
                           GetModuleHandleA(tokens[1].c_str()),
                           &moduleInfo,
                           miSize);
      uint64_t address = reinterpret_cast<uint64_t>(moduleInfo.lpBaseOfDll);
      uint64_t entrypoint = reinterpret_cast<uint64_t>(moduleInfo.EntryPoint);

      printf("[Module] %s BaseAddress: 0x%llX Entrypoint: 0x%llX\n",  
             tokens[1].c_str(), address, entrypoint);
    }

    //
    // Getval command
    //
    if (0 == _strcmpi(GETVAL_STR, tokens[0].c_str()))
    {
      if (3 > tokens.size())
      {
        return; // Error
      }

      union
      {
        uint8_t  b;
        uint16_t s;
        uint32_t w;
        uint64_t l;
        double   d;
        float    f;
      } val;

      // Retrieve address
      uint64_t address = reinterpret_cast<uint64_t>(GetModuleHandleA(tokens[1].c_str()));
      if (0 == address)
      {
        return; // Abort if address is invalid
      }
      
      // Retrieve value depending on type
      if (0 == _strcmpi(BYTE_STR, tokens[2].c_str()))
      {
        memcpy(&val, reinterpret_cast<void*>(address), sizeof(val.b));
        printf("[notice] 0x%llX[%d] = %d(%02X)\n", 
               address, sizeof(val.b), val.b, val.b);
      }
      else if (0 == _strcmpi(SHORT_STR, tokens[2].c_str()))
      {
        memcpy(&val, reinterpret_cast<void*>(address), sizeof(val.s));
        printf("[notice] 0x%llX[%d] = %d(%04X)\n",
          address, sizeof(val.s), val.s, val.s);
      }
      else if (0 == _strcmpi(WORD_STR, tokens[2].c_str()))
      {
        memcpy(&val, reinterpret_cast<void*>(address), sizeof(val.w));
        printf("[notice] 0x%llX[%d] = %d(%llX)\n",
          address, sizeof(val.w), val.w, val.w);
      }
      else if (0 == _strcmpi(LONG_STR, tokens[2].c_str()))
      {
        memcpy(&val, reinterpret_cast<void*>(address), sizeof(val.l));
        printf("[notice] 0x%llX[%d] = %llu(%llX)\n",
          address, sizeof(val.l), val.l, val.l);
      }
      else if (0 == _strcmpi(DOUBLE_STR, tokens[2].c_str()))
      {
        memcpy(&val, reinterpret_cast<void*>(address), sizeof(val.d));
        printf("[notice] 0x%llX[%d] = %f)\n",
               address, sizeof(val.d), val.d);
      }
      else if (0 == _strcmpi(FLOAT_STR, tokens[2].c_str()))
      {
        memcpy(&val, reinterpret_cast<void*>(address), sizeof(val.f));
        printf("[notice] 0x%llX[%d] = %f\n",
               address, sizeof(val.f), val.f);
      }
    }

    //
    // Setval command
    //
    if (0 == _strcmpi(GETVAL_STR, tokens[0].c_str()))
    {
      if (4 > tokens.size())
      {
        return; // Error
      }

      union
      {
        uint8_t  b;
        uint16_t s;
        uint32_t w;
        uint64_t l;
        double   d;
        float    f;
      } val;

      // Retrieve address
      uint64_t address = reinterpret_cast<uint64_t>(GetModuleHandleA(tokens[1].c_str()));
      if (0 == address)
      {
        return; // Abort if address is invalid
      }

      // Retrieve value depending on type
      if (0 == _strcmpi(BYTE_STR, tokens[2].c_str()))
      {
        val.b = strtoul(tokens[3].c_str(), 0, 16);
        memcpy(reinterpret_cast<void*>(address), &val, sizeof(val.b));
        printf("[notice] Set 0x%llX[%d] = %d(%02X)\n",
               address, sizeof(val.b), val.b, val.b);
      }
      else if (0 == _strcmpi(SHORT_STR, tokens[2].c_str()))
      {
        val.s = strtoul(tokens[3].c_str(), 0, 16);
        memcpy(reinterpret_cast<void*>(address), &val, sizeof(val.s));
        printf("[notice] Set 0x%llX[%d] = %d(%04X)\n",
               address, sizeof(val.s), val.s, val.s);
      }
      else if (0 == _strcmpi(WORD_STR, tokens[2].c_str()))
      {
        val.w = strtoul(tokens[3].c_str(), 0, 16);
        memcpy(reinterpret_cast<void*>(address), &val, sizeof(val.w));
        printf("[notice] Set 0x%llX[%d] = %d(%llX)\n",
               address, sizeof(val.w), val.w, val.w);
      }
      else if (0 == _strcmpi(LONG_STR, tokens[2].c_str()))
      {
        val.l = strtoul(tokens[3].c_str(), 0, 16);
        memcpy(reinterpret_cast<void*>(address), &val, sizeof(val.l));
        printf("[notice] Set 0x%llX[%d] = %llu(%llX)\n",
               address, sizeof(val.l), val.l, val.l);
      }
      else if (0 == _strcmpi(DOUBLE_STR, tokens[2].c_str()))
      {
        val.d = std::stod(tokens[3].c_str());
        memcpy(reinterpret_cast<void*>(address), &val, sizeof(val.d));
        printf("[notice] Set 0x%llX[%d] = %f)\n",
               address, sizeof(val.d), val.d);
      }
      else if (0 == _strcmpi(FLOAT_STR, tokens[2].c_str()))
      {
        val.f = std::stof(tokens[3].c_str());
        memcpy(reinterpret_cast<void*>(address), &val, sizeof(val.f));
        printf("[notice] Set 0x%llX[%d] = %f\n",
               address, sizeof(val.f), val.f);
      }
    }
  }
}

/****************************************************************************************
/ Function: InitializeTerminal
/ Notes: Allocates a console and initializes IO.
/***************************************************************************************/
void GITerminal::InitializeTerminal()
{
  // Allocate terminal and output welcome message..
  AllocConsole();
  freopen_s(&InHandle, "CONIN$", "r", stdin);
  freopen_s(&OutHandle, "CONOUT$", "w", stdout);

  printf("====================================\n"
         " redacted Impact Terminal Controller \n"
         "====================================\n");
}

/****************************************************************************************
/ Function: PrintHelp
/ Notes: None.
/***************************************************************************************/
void GITerminal::PrintHelp()
{
  printf("\n"
         "Functions:       Parameters:\n"
         "----------       -----------\n"
         "help\n"
         "enable           <type>\n"
         "disable          <type>\n"
         "sigscan          <module> <signature>\n"
         "hook             <address> <registers/flags> <options>\n"
         "unhook           <address>\n"
         "module           <module>\n"
         "getval           <address> <primitive_type>\n"
         "setval           <address> <primitive_type> <value>\n\n"
         "Types: \n"
         "------\n"
         "showchests\n"
         "freeze\n\n");
}

/****************************************************************************************
/ Function: Tokenize
/ Notes: None.
/***************************************************************************************/
std::vector<std::string> GITerminal::Tokenize(std::string str, const char* delim)
{
  std::vector<std::string> tokens;

  size_t base = 0;
  size_t next = str.find_first_of(delim, base);
  while (std::string::npos != next)
  {
    if (base != next)
    {
      tokens.push_back(str.substr(base, next - base));
    }

    base = next + 1;
    next = str.find_first_of(delim, base);
  }

  // Add remainder of string if base is not at the end..
  if (base < str.length())
  {
    tokens.push_back(str.substr(base));
  }

  return tokens;
}

/****************************************************************************************
/ Function: Constructor
/ Notes: None.
/***************************************************************************************/
GITerminal::GITerminal() :
  ThreadExit(false)
{

}