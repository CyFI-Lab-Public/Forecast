#include <windows.h>
#include <stdio.h>
typedef DWORD(WINAPI *GetTickCount_t)(void);
int main() {
  HMODULE hModule = LoadLibrary(TEXT("kernel32.dll"));
  printf("LoadLibrary Completed");
  GetTickCount_t getTick =
      (GetTickCount_t)GetProcAddress(hModule, "GetTickCount");
  printf("GetProcAddress Completed");
  DWORD tick = getTick();
  printf("Finished Call to getTick(), value is %lu", tick);
  
  FreeLibrary(hModule);
}
