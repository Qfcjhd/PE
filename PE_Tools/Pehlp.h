#pragma once
#include <stdio.h>
#include <Windows.h>

enum IMAGE_RESULT
{
	IR_RVA_ImageBase = 0,
	IR_FOA_FileBase,
	IR_RVA,
	IR_FOA,
};

enum IMAGE_FLAG
{
	IMAGE_FLAG_IMAGE = 0,
	IMAGE_FLAG_FILE,
};

/*
	��ȡ����Image
*/
DWORD GetLocalImage();

/*
	RVA ת FOA
	@_lpFileHead: �ļ�ͷ��ַ
	@_dwRVA: ����RVA��ַ
*/
DWORD _RVAToFOA(DWORD _lpFileHead, DWORD _dwRVA);


/*
	����Ŀ¼��λ
	@_lpHeader: ͷ����ַ
	@_index:����Ŀ¼����
	@_dwFlag1:
		0ΪPEӳ��ͷ�ļ�
		1Ϊ�ڴ�ӳ��ͷ�ļ�
	@_dwFlag2:
		0ΪRVA + ģ���ַ
		1ΪFOA + ģ���ַ
		2Ϊ���� RVA
		3Ϊ���� FOA
*/
DWORD _rDDEntry(DWORD _lpHeader, DWORD _index, IMAGE_FLAG _imageFlag, IMAGE_RESULT _imageResult);