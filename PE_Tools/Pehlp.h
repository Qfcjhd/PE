#pragma once
#include <stdio.h>
#include <Windows.h>

#define EXPORT_API extern "C" __declspec(dllexport)

/*
	���ر�־λֵ
	@PE_FLAG: PE_FLAG_15
	@flag: ��ֵ
*/
#define READ_FLAG(PE_FLAG,flag)(PE_FLAG & flag ? 1 : 0)

/*
	���ñ�־λֵ
	@PE_FLAG: PE_FLAG_15
	@flag: ��ֵ
*/
#define WRITE_FLAG(PE_FLAG,flag)(PE_FLAG | flag)

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

enum PE_FLAG_15
{
	PE_FLAG_0 = 0x0,
	PE_FLAG_1 = 0x2,
	PE_FLAG_2 = 0x4,
	PE_FLAG_3 = 0x8,
	PE_FLAG_4 = 0x10,
	PE_FLAG_5 = 0x20,
	PE_FLAG_6 = 0x40,
	PE_FLAG_7 = 0x80,
	PE_FLAG_8 = 0x100,
	PE_FLAG_9 = 0x200,
	PE_FLAG_A = 0x400,
	PE_FLAG_B = 0x800,
	PE_FLAG_C = 0x1000,
	PE_FLAG_D = 0x2000,
	PE_FLAG_E = 0x4000,
	PE_FLAG_F = 0x8000,
};

/*
	��ȡ����Image
*/
EXPORT_API DWORD GetLocalImage();

/*
	RVA ת FOA
	@_lpFileHead: �ļ�ͷ��ַ
	@_dwRVA: ����RVA��ַ
*/
EXPORT_API DWORD _RVAToFOA(DWORD _lpFileHead, DWORD _dwRVA);

/*
	����Ŀ¼��λ
	@_lpHeader: ͷ����ַ
	@_dwFlag1:
		0ΪPEӳ��ͷ�ļ�
		1Ϊ�ڴ�ӳ��ͷ�ļ�
	@_dwFlag2:
		0ΪRVA + ģ���ַ
		1ΪFOA + ģ���ַ
		2Ϊ���� RVA
		3Ϊ���� FOA
*/
DWORD _rPE(DWORD _lpHeader, IMAGE_FLAG _imageFlag, IMAGE_RESULT _imageResult);

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
DWORD _rSection(DWORD _lpHeader, DWORD _index, IMAGE_FLAG _imageFlag, IMAGE_RESULT _imageResult);

/*
	����RVA���ڵĽ�����
*/
DWORD _getRVASectionName(DWORD _lpFileHeader, DWORD _dwRVA);

/*
	���ڴ�ƫ����RVAת��Ϊ�ļ�ƫ��
	@_lpFileHead:Ϊ�ļ�ͷ����ʼ��ַ
	@_dwRVA:Ϊ������RVA��ַ
*/
DWORD _RVAToOffset(DWORD _lpFileHead, DWORD _dwRVA);

/*
	�жϱ�־λ�Ƿ�Ϊ 1
*/
//BOOLEAN IsFlag(PE_FLAG_15 peFlag,DWORD flag);

/*
	�����ļ����ڴ�
	@filePath: �ļ�·��
	@mem: �ɹ����ط��ص�ַ
	@return: �����ļ���С, ���󷵻�-1
	@ps: ʹ����֮��һ��ʹ�� VirtualFree(mem, 0, MEM_RELEASE) �ͷ��ڴ�
*/
DWORD _FileToFileBuffer(IN LPSTR* filePath, OUT LPVOID* mem);

/*
	��֤DosSignature �Ƿ���ȷ
	@mem: �ڴ�
*/
BOOL IsDosSignature(LPVOID mem);


/*
	��ȡ�����
	@_lpFileHeader: ӳ�䵽�ڴ���ļ���ַ
	ps:
		0004106F      | FF15 60400400       | call dword ptr ds:[<&MessageBoxA>]  |
		1.��ǰ������ImageBase: 0x40000, �ڴ��жϵ�MessageBoxA��,�鿴Ӳ����Ϊ: 60400400 -> 0x44060
		2.��ǰ�ļ�����Ϊ200 , �ڴ����Ϊ1000
		3.����RvaToOff����, ���� 0x44060 - 0x40000 = RVA, ����ó�0x3460 (�ļ�ƫ��)
		4.�ļ���ʼ��ַ + 0x3460 ȡ����ֵ = 502C
		5.��ӡIAT��ַ,�ҵ�MessageBoxA RVA ��ַ����502c, �˺�����ʽ��user32.dll �����ֵ����

*/
VOID _getImportInfo(DWORD _lpFileHeader);

/*
	��ȡָ��Api�������õĵ�ַ
	@_hMoudle:��̬���ӿ��ַ
	@funName: ��������
	@ret: ������ַ + ģ���ַ
*/
DWORD _getApi(DWORD _hMoudle, char* funName);
