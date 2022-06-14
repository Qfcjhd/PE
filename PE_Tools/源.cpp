#include <stdio.h>
#include <Windows.h>

#include "Pehlp.h"

#define _RDATA_SECTION 1
#define _RSRC_SECTION 2

#define PATH "C:\\Users\\Administrator\\Desktop\\PE_TEST 2.exe"

int main(void)
{
	/*DWORD localImage = GetLocalImage();
	_RVAToFOA(localImage, 0x1010);

	DWORD rva = _rDDEntry(localImage, _RDATA_SECTION, IMAGE_FLAG_IMAGE, IR_FOA);
	rva = _rSection(localImage, _RDATA_SECTION, IMAGE_FLAG_IMAGE, IR_FOA_FileBase);

	rva = _getRVASectionName(localImage, 0x4010);

	int flag = 0x1;
	DWORD status = READ_FLAG(PE_FLAG_3, flag);
	status = WRITE_FLAG(PE_FLAG_3, flag);*/

	//printf("localImage: %x\r\n", status);


	/*LPVOID mem;
	DWORD len = _FileToFileBuffer((LPSTR*)PATH, &mem);

	PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)mem;
	PIMAGE_NT_HEADERS imageNtHeader = (PIMAGE_NT_HEADERS)((DWORD)imageDosHeader + imageDosHeader->e_lfanew);
	DWORD off = _RVAToOffset((DWORD)mem, imageNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress);
	printf("import: %x\r\n", off);
	off = _RVAToOffset((DWORD)mem, (0x44060 - imageNtHeader->OptionalHeader.ImageBase));
	printf("IAT: %x\r\n", off);

	_getImportInfo((DWORD)mem);


	BOOL status = VirtualFree(mem, 0, MEM_RELEASE);*/

	char funcName[] = "GetLocalImage";
	_getApi(GetLocalImage(), funcName);

}

