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

	printf("localImage: %x\r\n", rva);
}