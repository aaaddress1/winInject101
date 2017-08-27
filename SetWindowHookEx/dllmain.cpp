/**
 *	@file: wndHookDll.cpp
 *	@author: aaaddress1@chroot.org
 *	@date:	2017/8/11
**/
#include <Windows.h>

bool disp = false;
HMODULE hMod = NULL;
HHOOK hHook = NULL;

LRESULT WINAPI msgProg(int code, WPARAM wParam, LPARAM lParam)
{
	if (!disp) MessageBoxA(0, "Hello World", "HITCON 2017", 0);
	disp = true;
	return CallNextHookEx(NULL, code, wParam, lParam);
}


extern "C" {
	__declspec(dllexport) int hookStart() {
		hHook = SetWindowsHookEx(WH_GETMESSAGE, msgProg, hMod, 0);
		return !!hHook;
	}
	__declspec(dllexport) int hookStop() {
		return hHook && UnhookWindowsHookEx(hHook);
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	hMod = hModule;
	return TRUE;
}

