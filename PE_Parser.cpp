/**
 *	@file: PE_Parser.cpp
 *	@author: aaaddress1@chroot.org
 *	@date:	2017/8/11
**/

#include <stdio.h>
#include <Windows.h>

void PE_Parser(char *pe_file)
{
	HANDLE hFile; 

	if (!(hFile = CreateFileA
	(
		pe_file,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	))) {
		puts("fail to read pe data.");
		return;
	}

	DWORD dwFileSize = GetFileSize(hFile, NULL);
	HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	PBYTE pBuffer = (PBYTE)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_NT_HEADERS     NTHeader;
	PIMAGE_DOS_HEADER     DOSHeader;
	PIMAGE_SECTION_HEADER Sections;

	/* start reading PE headers */
	DOSHeader = (PIMAGE_DOS_HEADER)pBuffer;
	NTHeader = (PIMAGE_NT_HEADERS)(pBuffer + DOSHeader->e_lfanew);
	DWORD dwBaseAddress = NTHeader->OptionalHeader.ImageBase;
	printf("image base: %p\n", dwBaseAddress);

	/* get the first section (should be .text) */
	Sections = (PIMAGE_SECTION_HEADER)
	(
		pBuffer +
		DOSHeader->e_lfanew +
		sizeof(IMAGE_NT_HEADERS)
	);

	printf
	(	
		"image entry: %s, %p\n",
		Sections->Name,
		NTHeader->OptionalHeader.ImageBase + NTHeader->OptionalHeader.AddressOfEntryPoint
	);
	
	puts("section information");
	for (int i = 0; i < NTHeader->FileHeader.NumberOfSections; i++)
	{
		printf
		(
			"\t%s\t%p\n",
			Sections->Name,
			NTHeader->OptionalHeader.ImageBase + Sections->VirtualAddress
		);
		Sections++;
	}
}

int main()
{
	/* get current executable file path */
	char CurrentFilePath[MAX_PATH];
	GetModuleFileNameA(0, CurrentFilePath, MAX_PATH);

	/* try parse self */
	PE_Parser(CurrentFilePath);
	getchar();
	return 0;
}