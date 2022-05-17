#include "Pehlp.h"

DWORD GetLocalImage()
{
	HMODULE handle = GetModuleHandle(NULL);
	return (DWORD)handle;
}

DWORD _RVAToFOA(DWORD _lpFileHead, DWORD _dwRVA)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)_lpFileHead;
	PIMAGE_NT_HEADERS imageNtHeader = (PIMAGE_NT_HEADERS)(_lpFileHead + (DWORD)dosHeader->e_lfanew);
	DWORD off = 0;

	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)imageNtHeader + sizeof(IMAGE_NT_HEADERS));
	DWORD sectionNumber = (DWORD)imageNtHeader->FileHeader.NumberOfSections;

	for (DWORD i = 0; i < sectionNumber; i++)
	{
		DWORD sectionEnd = sectionHeader[i].VirtualAddress + sectionHeader[i].SizeOfRawData;
		if (_dwRVA >= sectionHeader[i].VirtualAddress && _dwRVA < sectionEnd)
		{
			off = sectionEnd - _dwRVA + sectionHeader[i].PointerToRawData;
		}
	}
	return off;
}

DWORD _rDDEntry(DWORD _lpHeader, DWORD _index, IMAGE_FLAG _imageFlag, IMAGE_RESULT _imageResult)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)_lpHeader;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(_lpHeader + (DWORD)dosHeader->e_lfanew);
	DWORD _ImageBase = ntHeader->OptionalHeader.ImageBase;

	//取数据项
	PIMAGE_DATA_DIRECTORY dataDirectory = (PIMAGE_DATA_DIRECTORY)&(ntHeader->OptionalHeader.DataDirectory[_index]);
	
	DWORD off = 0;

	if (_imageFlag == IMAGE_FLAG_FILE)
	{
		if (_imageResult == IR_RVA_ImageBase)
		{
			off = _lpHeader + (DWORD)dataDirectory->VirtualAddress;
		}
		else if (_imageResult == IR_FOA_FileBase) //无意义返回foa
		{
			off = _RVAToFOA(_lpHeader, (DWORD)dataDirectory->VirtualAddress);
		}
		else if (_imageResult == IR_RVA)
		{
			off = (DWORD)dataDirectory->VirtualAddress;
		}
		else if (_imageResult == IR_FOA)
		{
			off = _RVAToFOA(_lpHeader, (DWORD)dataDirectory->VirtualAddress);
		}
	}
	else //内存映射
	{
		if (_imageResult == IR_RVA_ImageBase) //RVA
		{
			off = _ImageBase + (DWORD)dataDirectory->VirtualAddress;
		}
		else if (_imageResult == IR_FOA_FileBase) //FOA
		{
			off = _RVAToFOA(_lpHeader, (DWORD)dataDirectory->VirtualAddress);
		}
		else if (_imageResult == IR_RVA)
		{
			off = (DWORD)dataDirectory->VirtualAddress;
		}
		else if (_imageResult == IR_FOA)
		{
			off = _RVAToFOA(_lpHeader, (DWORD)dataDirectory->VirtualAddress);
		}
	}

	return off;
}
