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
			break;
		}
	}
	return off;
}

DWORD _rPE(DWORD _lpHeader, IMAGE_FLAG _imageFlag, IMAGE_RESULT _imageResult)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)_lpHeader;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(_lpHeader + (DWORD)dosHeader->e_lfanew);
	DWORD _ImageBase = ntHeader->OptionalHeader.ImageBase;

	DWORD off = 0;

	if (_imageFlag == IMAGE_FLAG_FILE)
	{
		if (_imageResult == IR_RVA_ImageBase)
		{
			off = _lpHeader + (DWORD)ntHeader;
		}
		else if (_imageResult == IR_FOA_FileBase) //无意义返回foa
		{
			off = ((DWORD)ntHeader - _lpHeader);
		}
		else 
		{
			off = ((DWORD)ntHeader - _lpHeader);
		}
	}
	else //内存映射
	{
		if (_imageResult == IR_RVA_ImageBase) //RVA
		{
			off = _ImageBase + ((DWORD)ntHeader - _lpHeader);
		}
		else if (_imageResult == IR_FOA_FileBase) //FOA
		{
			off = (DWORD)ntHeader;
		}
		else
		{
			off = ((DWORD)ntHeader - _lpHeader);
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

DWORD _rSection(DWORD _lpHeader, DWORD _index, IMAGE_FLAG _imageFlag, IMAGE_RESULT _imageResult)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)_lpHeader;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(_lpHeader + (DWORD)dosHeader->e_lfanew);
	DWORD _ImageBase = ntHeader->OptionalHeader.ImageBase;

	DWORD _NumberOfRvaAndSizes = ntHeader->OptionalHeader.NumberOfRvaAndSizes;
	DWORD off = 0;
	if (_NumberOfRvaAndSizes <= _index)
		return off;

	PIMAGE_DATA_DIRECTORY dataDirectory = (PIMAGE_DATA_DIRECTORY) & (ntHeader->OptionalHeader.DataDirectory[_index]);


	if (_imageFlag == IMAGE_FLAG_FILE)
	{
		if (_imageResult == IR_RVA_ImageBase)
		{
			off = (DWORD)dataDirectory;
		}
		else
		{
			off = (DWORD)dataDirectory - _lpHeader;
		}
	}
	else //内存映射
	{
		if (_imageResult == IR_RVA_ImageBase) //RVA
		{
			off = _ImageBase + (DWORD)dataDirectory - _lpHeader;
		}
		else if (_imageResult == IR_FOA_FileBase) //FOA
		{
			off = (DWORD)dataDirectory;
		}
		else if (_imageResult == IR_RVA)
		{
			off = (DWORD)dataDirectory - _lpHeader;
		}
	}

	return off;
}

DWORD _getRVASectionName(DWORD _lpFileHeader, DWORD _dwRVA)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)_lpFileHeader;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(_lpFileHeader + (DWORD)dosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER sectionHeader = PIMAGE_SECTION_HEADER((DWORD)ntHeader + sizeof IMAGE_NT_HEADERS);
	DWORD _NumberOfSections = ntHeader->FileHeader.NumberOfSections;
	DWORD off = 0;

	for (DWORD i = 0; i < _NumberOfSections; i++)
	{
		DWORD _EndSectonAdderss = sectionHeader[i].VirtualAddress + sectionHeader[i].SizeOfRawData; //节点结束地址

		if (_dwRVA >= sectionHeader[i].VirtualAddress && _dwRVA < _EndSectonAdderss)
		{
			off = (DWORD)&sectionHeader[i];
			break;
		}
	}

	return off;
}

//BOOLEAN IsFlag(PE_FLAG_15 peFlag, DWORD flag)
//{
//	return flag & peFlag ? TRUE : FALSE;
//}

DWORD _FileToFileBuffer(IN LPSTR* filePath, OUT LPVOID* mem)
{
	FILE* _Post_ _Notnull_ pF;
	errno_t err = fopen_s(&pF, (char*)filePath, "rb+");
	if (err) {
		printf("加载文件失败 %s\r\n", __FUNCTION__);
		return -1;
	}

	fseek(pF, 0, SEEK_END);
	ULONG len = ftell(pF);
	fseek(pF, 0, SEEK_SET);

	if (!len) {
		printf("文件大小获取失败 %s\r\n", __FUNCTION__);
		return -1;
	}

	LPVOID adderss = VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!adderss) {
		printf("申请内存失败 %s\r\n", __FUNCTION__);
		return -1;
	}

	size_t count = fread_s(adderss, len, 1, len, pF);

	*mem = adderss;
	fclose(pF);

	return len;
}

BOOL IsDosSignature(LPVOID mem)
{
	if (*((PWORD)mem) != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	return TRUE;
}

DWORD _RVAToOffset(DWORD _lpFileHead, DWORD _dwRVA)
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
			off = _dwRVA - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
			break;
		}
	}
	return off;
}

VOID _getImportInfo(DWORD _lpFileHeader)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)_lpFileHeader;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(_lpFileHeader + (DWORD)dosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY _Import = ntHeader->OptionalHeader.DataDirectory[1];
	if (!_Import.VirtualAddress) {
		printf("%s\r\n",__FUNCTION__);
		return;
	}

	DWORD FOA = _RVAToOffset(_lpFileHeader, _Import.VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR imageImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(_lpFileHeader + FOA);


	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)_getRVASectionName(_lpFileHeader, imageImportDesc->OriginalFirstThunk);
	printf("%s\r\n", sectionHeader->Name);
}