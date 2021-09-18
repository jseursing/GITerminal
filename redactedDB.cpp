#include "redactedDB.h"
#include "HookManager.h"
#include <psapi.h>
#include <thread>

/****************************************************************************************
/ Function: Initialize
/ Notes: None.
/***************************************************************************************/
bool redactedDB::Initialize()
{
  std::vector<uint64_t> scanResults;

  // Status
  printf("[notice] Initializing interfaces...\n");

  // Initialize Hook Manager after a delay
  std::this_thread::sleep_for(std::chrono::seconds(1));
  HookManager::Initialize(true);

  /***********************************************************************
    Wait for UserAssembly.dll and UnityPlayer.dll to be found
  ***********************************************************************/
  while (0 == _UserAssemblyBase)
  {
    _UserAssemblyBase = reinterpret_cast<uint64_t>
                       (GetModuleHandleA(_UserAssemblyDll.c_str()));

    // Sleep to avoid excessive CPU usage
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  MODULEINFO moduleInfo;
  unsigned long miSize = sizeof(MODULEINFO);
  GetModuleInformation(GetCurrentProcess(),
                       reinterpret_cast<HMODULE>(_UserAssemblyBase),
                       &moduleInfo,
                       miSize);
  _UserAssemblyBase = reinterpret_cast<uint64_t>(moduleInfo.lpBaseOfDll);
  _UserAssemblySize = moduleInfo.SizeOfImage;

  while (0 == _UnityPlayerBase)
  {
    _UnityPlayerBase = reinterpret_cast<uint64_t>
                       (GetModuleHandleA(_UnityPlayerDll.c_str()));

    // Sleep to avoid excessive CPU usage
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  GetModuleInformation(GetCurrentProcess(),
                       reinterpret_cast<HMODULE>(_UnityPlayerBase),
                       &moduleInfo,
                       miSize);
  _UnityPlayerBase = reinterpret_cast<uint64_t>(moduleInfo.lpBaseOfDll);
  _UnityPlayerSize = moduleInfo.SizeOfImage;

  /***********************************************************************
    Scan for Chest ESP Addresses
  ***********************************************************************/
  unsigned char* ptr = reinterpret_cast<unsigned char*>(_UserAssemblyBase);

  scanResults = HookManager::SignatureScan(ptr,
                                           _UserAssemblySize, 
                                           ChestESPSignature[0], 
                                           true);
  if (0 == scanResults.size())
  {
    printf("[error] Signature scan failed: %s\n", ChestESPSignature[0].c_str());
    return false;
  }

  ChestESPAddress[0] = _UserAssemblyBase + scanResults[0];

  scanResults = HookManager::SignatureScan(ptr, 
                                           _UserAssemblySize, 
                                           ChestESPSignature[1], 
                                           true);
  if (0 == scanResults.size())
  {
    printf("[error] Signature scan failed: %s\n", ChestESPSignature[1].c_str());
    return false;
  }

  ChestESPAddress[1] = _UserAssemblyBase + scanResults[0];

  // Register breakpoint hooks for ChestESP
  Breakpoint bp;
  bp.Enabled = true;
  bp.type = Breakpoint::MEM_PAGE;
  bp.RegisterTypes = Breakpoint::ZF;
  bp.Modification = Breakpoint::SET;
  bp.AppendMod(Breakpoint::INVOKE);
  bp.InvokeFunc = NotifyChest;

  bp.address = ChestESPAddress[0];
  HookManager::RegisterBP(bp);

  bp.address = ChestESPAddress[1];
  HookManager::RegisterBP(bp);

  /***********************************************************************
    Freeze 
  ***********************************************************************/

  ptr = reinterpret_cast<unsigned char*>(_UnityPlayerBase);

  scanResults = HookManager::SignatureScan(ptr,
                                           _UnityPlayerSize,
                                           SpeedSignature[0],
                                           true);
  if (0 == scanResults.size())
  {
    printf("[error] Signature scan failed: %s\n", SpeedSignature[0].c_str());
    return false;
  }

  SpeedContextAddress = _UnityPlayerBase + scanResults[0];
  SetContextHookReturn(SpeedContextAddress + 8);

  scanResults = HookManager::SignatureScan(ptr,
                                           _UnityPlayerSize,
                                           SpeedSignature[1],
                                           true);
  if (0 == scanResults.size())
  {
    printf("[error] Signature scan failed: %s\n", SpeedSignature[1].c_str());
    return false;
  }

  SpeedHookAddress = _UnityPlayerBase + scanResults[0];
  SetSpeedHookReturn(SpeedHookAddress + 6);

  scanResults = HookManager::SignatureScan(ptr,
                                           _UnityPlayerSize,
                                           SpeedSignature[2],
                                           true);
  if (0 == scanResults.size())
  {
    printf("[error] Signature scan failed: %s\n", SpeedSignature[2].c_str());
    return false;
  }

  SpeedSwitchAddress = _UnityPlayerBase + scanResults[0];
  SetSpeedSwitchHookReturn(SpeedSwitchAddress + 5);
  
  TrampolineHook th;
  th.address = SpeedContextAddress;
  th.codecave = reinterpret_cast<uint64_t>(ContextHook);
  th.hook_length = 8;
  th.originalMem = 0;
  HookManager::RegisterTrampoline(th);
  HookManager::ToggleTrampoline32(th.address, true);

  th.address = SpeedHookAddress;
  th.codecave = reinterpret_cast<uint64_t>(SpeedHook);
  th.hook_length = 6;
  th.originalMem = 0;
  HookManager::RegisterTrampoline(th);
  HookManager::ToggleTrampoline32(th.address, true);

  th.address = SpeedSwitchAddress;
  th.codecave = reinterpret_cast<uint64_t>(SpeedSwitchHook);
  th.hook_length = 5;
  th.originalMem = 0;
  HookManager::RegisterTrampoline(th);
  HookManager::ToggleTrampoline32(th.address, true);

  return true;
}

/****************************************************************************************
/ Function: ToggleChestESP
/ Notes: None.
/***************************************************************************************/
void redactedDB::ToggleChestESP(bool enable)
{
  HookManager::ToggleHook(ChestESPAddress[0], enable);
  HookManager::ToggleHook(ChestESPAddress[1], enable);
}

/****************************************************************************************
/ Function: ToggleFreeze
/ Notes: None.
/***************************************************************************************/
void redactedDB::ToggleFreeze(bool enable)
{
  ToggleSpeedHook(true == enable ? 1 : 0);
}

/****************************************************************************************
/ Function: NotifyChest
/ Notes: None.
/***************************************************************************************/
void redactedDB::NotifyChest(PEXCEPTION_POINTERS exception)
{
  static unsigned int counter = 0;
  if (0 == (++counter % 50))
  {
    printf("[notice] Chest nearby!\n");
  }
}

/****************************************************************************************
/ Modules
/***************************************************************************************/
std::string redactedDB::_UserAssemblyDll = "UserAssembly.dll";
uint64_t redactedDB::_UserAssemblyBase = 0;
uint64_t redactedDB::_UserAssemblySize = 0;
std::string redactedDB::_UnityPlayerDll = "UnityPlayer.dll";;
uint64_t redactedDB::_UnityPlayerBase = 0;
uint64_t redactedDB::_UnityPlayerSize = 0;

/****************************************************************************************
/ CHEST ESP
/***************************************************************************************/
uint64_t redactedDB::ChestESPAddress[2] = {0};
std::string redactedDB::ChestESPSignature[2] =
{
  "74 ?? 48 85 F6 0F 84 ?? ?? ?? ?? 45 33 C0 8B D0",
  "74 ?? 33 D2 48 8B CF E8 ?? ?? 00 00 C6 87 ?? ?? 00 00 00 EB"
};

/* 
UserAssembly.dll -  74 ?? 48 85 F6 0F 84 ?? ?? ?? ?? 45 33 C0 8b D0 (+0x14804C4 v1.1) - JE->JNE
{
014804AA - 48 63 CB              - movsxd  rcx,ebx
014804AD - 48 8B 4C C8 20        - mov rcx,[rax+rcx*8+20]
014804B2 - 48 85 C9              - test rcx,rcx
014804B5 - 0F84 E7000000         - je 014805A2
014804BB - 33 D2                 - xor edx,edx
014804BD - E8 8EEA9700           - call 01DFEF50
014804C2 - 85 DB                 - test ebx,ebx
<-->
014804C4 - 74 1C                 - je 014804E2
<-->
014804C6 - 48 85 F6              - test rsi,rsi
014804C9 - 0F84 D3000000         - je 014805A2
014804CF - 45 33 C0              - xor r8d,r8d
014804D2 - 8B D0                 - mov edx,eax
014804D4 - 48 8B CE              - mov rcx,rsi
014804D7 - E8 C41AFFFF           - call 01471FA0
014804DC - 44 0FB6 F0            - movzx r14d,al
}

UserAssembly.dll -  74 ?? 33 D2 48 8B CF E8 ?? ?? 00 00 C6 87 ?? ?? 00 00 00 EB (+0x148054B v1.1) - JE->JNE
{
0148051E - E8 8DF6FFFF           - call 0147FBB0
01480523 - C6 87 90000000 01     - mov byte ptr [rdi+00000090],01
0148052A - 48 8B 74 24 40        - mov rsi,[rsp+40]
0148052F - 48 8B 6C 24 38        - mov rbp,[rsp+38]
01480534 - 48 8B 5C 24 30        - mov rbx,[rsp+30]
01480539 - 4C 8B 74 24 48        - mov r14,[rsp+48]
0148053E - 48 83 C4 20           - add rsp,20 { (00000000) }
01480542 - 5F                    - pop rdi
01480543 - C3                    - ret
01480544 - 80 BF 90000000 00     - cmp byte ptr [rdi+00000090],00
<-->
0148054B - 74 DD                 - je 0148052A
<-->
0148054D - 33 D2                 - xor edx,edx
0148054F - 48 8B CF              - mov rcx,rdi
01480552 - E8 490C0000           - call 014811A0
01480557 - C6 87 90000000 00     - mov byte ptr [rdi+00000090],00
0148055E - EB CA                 - jmp 0148052A

}
*/

/****************************************************************************************
/ SPEED/FREEZE
/***************************************************************************************/
uint64_t redactedDB::SpeedContextAddress = 0;
uint64_t redactedDB::SpeedHookAddress = 0;
uint64_t redactedDB::SpeedSwitchAddress = 0;
std::string redactedDB::SpeedSignature[3] =
{
  "F3 0F 10 81 0C 03 00 00 C3",
  "8B 87 ?? ?? 00 00 89 01 80 BF",
  "8B 11 45 22 D4 45 02 D3"
};

/*
UnityPlayer.dll - F3 0F 10 81 0C 03 00 00 C3 (+xB73970) -> Capture RCX (SpeedContextValue)
{
00B72F6F - CC                    - int 3
<-->
00B72F70 - F3 0F10 81 0C030000   - movss xmm0,[rcx+0000030C]
<-->
00B72F78 - C3                    - ret
00B72F79 - CC                    - int 3
00B72F7A - CC                    - int 3
00B72F7B - CC                    - int 3
00B72F7C - CC                    - int 3
00B72F7D - CC                    - int 3
00B72F7E - CC                    - int 3
00B72F7F - CC                    - int 3
00B72F80 - 80 B9 3D010000 00     - cmp byte ptr [rcx+0000013D],00 { (9460301) }
00B72F87 - 75 03                 - jne 00B72F8C
00B72F89 - 32 C0                 - xor al,al
00B72F8B - C3                    - ret
}

UnityPlayer.dll - 8B 87 0C 03 00 00 89 01 80 (+B6ADC8) -> Codecave hook
{
00B6A39F - 48 8B CF              - mov rcx,rdi
00B6A3A2 - E8 69330000           - call 00B6D710
00B6A3A7 - 83 BF EC000000 00     - cmp dword ptr [rdi+000000EC],00 
00B6A3AE - 74 20                 - je 00B6A3D0
00B6A3B0 - 48 8B 87 98040000     - mov rax,[rdi+00000498]
00B6A3B7 - 48 85 C0              - test rax,rax
00B6A3BA - 74 14                 - je 00B6A3D0
00B6A3BC - 48 8B 88 F0000000     - mov rcx,[rax+000000F0]
00B6A3C3 - 48 85 C9              - test rcx,rcx
00B6A3C6 - 74 08                 - je 00B6A3D0
<-->
00B6A3C8 - 8B 87 0C030000        - mov eax,[rdi+0000030C]
<-->
00B6A3CE - 89 01                 - mov [rcx],eax
00B6A3D0 - 80 BF D0000000 00     - cmp byte ptr [rdi+000000D0],00 
00B6A3D7 - 0F84 B5020000         - je 00B6A692
00B6A3DD - 45 84 FF              - test r15l,r15l
00B6A3E0 - 74 22                 - je 00B6A404
00B6A3E2 - 48 8B 87 20010000     - mov rax,[rdi+00000120]
00B6A3E9 - 80 B8 A4000000 00     - cmp byte ptr [rax+000000A4],00
00B6A3F0 - 75 1F                 - jne 00B6A411
00B6A3F2 - 80 BF D1000000 00     - cmp byte ptr [rdi+000000D1],00
00B6A3F9 - 75 16                 - jne 00B6A411

}

UnityPlayer.dll - 8B 11 45 22 D4 45 02 D3 (+1D71FC3) -> xor edx, edx
1D71FB4 - C3                    - ret
1D71FB5 - E9 8BE4FAFF           - jmp UnityPlayer.dll+1D20445
1D71FBA - 48 8B 0B              - mov rcx,[rbx]
1D71FBD - 32 D5                 - xor dl,ch
1D71FBF - 44 0F4E D4            - cmovle r10d,esp
<-->
1D71FC3 - 8B 11                 - mov edx,[rcx]
<-->
1D71FC5 - 45 22 D4              - and r10l,r12l
1D71FC8 - 45 02 D3              - add r10l,r11l
1D71FCB - 48 81 C3 04000000     - add rbx,00000004 { 4 }
1D71FD2 - 4D 13 D6              - adc r10,r14
1D71FD5 - 41 80 C2 F2           - add r10l,-0E { 242 }
1D71FD9 - 89 13                 - mov [rbx],edx
1D71FDB - 49 81 E8 04000000     - sub r8,00000004 { 4 }

*/