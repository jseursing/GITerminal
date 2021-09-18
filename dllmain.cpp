#include "GITerminal.h"
#include <Windows.h>

BOOL __stdcall DllMain(HINSTANCE instance, unsigned long  reason, void* reserved)
{
  switch (reason)
  {
  case DLL_PROCESS_ATTACH:
    DisableThreadLibraryCalls(instance);
    GITerminal::Instance().Launch();
    break;
  case DLL_PROCESS_DETACH:
    FreeLibrary(instance);
    break;
  }
  return TRUE;
}

