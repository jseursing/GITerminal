#pragma once
#include <stdint.h>
#include <string>
#include <Windows.h>

extern "C" void ContextHook();
extern "C" void SetContextHookReturn(uint64_t addr);

extern "C" void SpeedHook();
extern "C" void SpeedSwitchHook();
extern "C" void SetSpeedHookReturn(uint64_t addr);
extern "C" void SetSpeedSwitchHookReturn(uint64_t addr);
extern "C" void ToggleSpeedHook(uint64_t enable);

class redactedDB
{
public:
  static bool Initialize();
  static void ToggleChestESP(bool enable);
  static void ToggleFreeze(bool enable);
  static void NotifyChest(PEXCEPTION_POINTERS exception);

  static uint64_t ChestESPAddress[2];
  static uint64_t SpeedContextAddress;
  static uint64_t SpeedHookAddress;
  static uint64_t SpeedSwitchAddress;

private:
  // Module members
  static std::string _UserAssemblyDll;
  static uint64_t _UserAssemblyBase;
  static uint64_t _UserAssemblySize;
  static std::string _UnityPlayerDll;
  static uint64_t _UnityPlayerBase;
  static uint64_t _UnityPlayerSize;

  // Exploit members
  static std::string ChestESPSignature[2];
  static std::string SpeedSignature[3];
};

