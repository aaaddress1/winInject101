/**
 *	@file: wndHookLoader.cpp
 *	@author: aaaddress1@chroot.org
 *	@date:	2017/8/11
**/
#include <Windows.h>

int main() {
	if (auto mod = LoadLibraryA("inject.dll")) {
		(int(*)())GetProcAddress(LoadLibraryA("inject.dll"), "hookStart")();
		getchar();
	}
    return 0;
}

