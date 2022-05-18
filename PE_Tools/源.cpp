#include <stdio.h>
#include <Windows.h>

#include "Pehlp.h"

#define _RDATA_SECTION 1
#define _RSRC_SECTION 2

int main(void) 
{
	DWORD localImage = GetLocalImage();
	_RVAToFOA(localImage, 0x1010);

	DWORD rva = _rDDEntry(localImage, _RDATA_SECTION, IMAGE_FLAG_IMAGE, IR_FOA);
	rva = _rSection(localImage, _RDATA_SECTION, IMAGE_FLAG_IMAGE, IR_FOA_FileBase);

	rva = _getRVASectionName(localImage, 0x4010);

	int flag = 0x1;
	DWORD status = READ_FLAG(PE_FLAG_3, flag);
	status = WRITE_FLAG(PE_FLAG_3, flag);

	printf("localImage: %x\r\n", status);
}