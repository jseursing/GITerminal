#pragma once
#include <future>
#include <vector>

class GITerminal
{
public:
  static GITerminal& Instance();
  void Launch();
  void Destroy();

private:
  static void HotkeyThread();
  static void InjectionThread();
  void ProcessCommand(char* inputStr);
  void InitializeTerminal();
  void PrintHelp();
  std::vector<std::string> Tokenize(std::string str, const char* delim);
  GITerminal();
  
  // IO and Thread members
  FILE* InHandle;
  FILE* OutHandle;
  bool ThreadExit;
  std::future<void> HotkeyHandle;
  std::future<void> InjectionHandle;

  // Terminal constants
  const char* HELP_STR = "help\0";
  const char* ENABLE_STR = "enable\0";
  const char* DISABLE_STR = "disable\0";
  const char* SCAN_STR = "sigscan\0";
  const char* HOOK_STR = "hook\0";
  const char* UNHOOK_STR = "unhook\0";
  const char* MODULE_STR = "module\0";
  const char* GETVAL_STR = "getval\0";
  const char* SETVAL_STR = "setval\0";

  // Enable/Disable Types
  const char* CHEST_STR = "showchests\0";
  const char* FREEZE_STR = "freeze\0";

  // Hook Types
  const char* RAX_STR = "rax\0";
  const char* RCX_STR = "rcx\0";
  const char* RDX_STR = "rdx\0";
  const char* RBX_STR = "rbx\0";
  const char* RBP_STR = "rbp\0";
  const char* RSP_STR = "rsp\0";
  const char* RSI_STR = "rsi\0";
  const char* RDI_STR = "rdi\0";
  const char* RIP_STR = "rip\0";
  const char* CF_STR = "cf\0";
  const char* PF_STR = "pf\0";
  const char* AF_STR = "af\0";
  const char* ZF_STR = "zf\0";
  const char* SF_STR = "sf\0";
  const char* IF_STR = "if\0";
  const char* DF_STR = "df\0";
  const char* OF_STR = "of\0";
  const char* SET_STR = "set\0";
  const char* UNSET_STR = "unset\0";
  const char* XOR_STR = "xor\0";
  const char* VERBOSE_STR = "-v\0";

  // Get/Set Value Types
  const char* BYTE_STR = "byte\0";
  const char* SHORT_STR = "short\0";
  const char* WORD_STR = "word\0";
  const char* LONG_STR = "long\0";
  const char* DOUBLE_STR = "double\0";
  const char* FLOAT_STR = "float\0";
};