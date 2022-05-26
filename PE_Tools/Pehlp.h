#pragma once
#include <stdio.h>
#include <Windows.h>

/*
	返回标志位值
	@PE_FLAG: PE_FLAG_15
	@flag: 数值
*/
#define READ_FLAG(PE_FLAG,flag)(PE_FLAG & flag ? 1 : 0)

/*
	设置标志位值
	@PE_FLAG: PE_FLAG_15
	@flag: 数值
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
	获取自身Image
*/
DWORD GetLocalImage();

/*
	RVA 转 FOA
	@_lpFileHead: 文件头基址
	@_dwRVA: 给定RVA地址
*/
DWORD _RVAToFOA(DWORD _lpFileHead, DWORD _dwRVA);

/*
	数据目录定位
	@_lpHeader: 头部基址
	@_dwFlag1:
		0为PE映射头文件
		1为内存映射头文件
	@_dwFlag2:
		0为RVA + 模块基址
		1为FOA + 模块基址
		2为返回 RVA
		3为返回 FOA
*/
DWORD _rPE(DWORD _lpHeader, IMAGE_FLAG _imageFlag, IMAGE_RESULT _imageResult);

/*
	数据目录定位
	@_lpHeader: 头部基址
	@_index:数据目录索引
	@_dwFlag1:
		0为PE映射头文件
		1为内存映射头文件
	@_dwFlag2:
		0为RVA + 模块基址
		1为FOA + 模块基址
		2为返回 RVA
		3为返回 FOA
*/
DWORD _rDDEntry(DWORD _lpHeader, DWORD _index, IMAGE_FLAG _imageFlag, IMAGE_RESULT _imageResult);

/*
	数据目录定位
	@_lpHeader: 头部基址
	@_index:数据目录索引
	@_dwFlag1:
		0为PE映射头文件
		1为内存映射头文件
	@_dwFlag2:
		0为RVA + 模块基址
		1为FOA + 模块基址
		2为返回 RVA
		3为返回 FOA
*/
DWORD _rSection(DWORD _lpHeader, DWORD _index, IMAGE_FLAG _imageFlag, IMAGE_RESULT _imageResult);

/*
	返回RVA所在的节名称
*/
DWORD _getRVASectionName(DWORD _lpFileHeader, DWORD _dwRVA);

/*
	将内存偏移量RVA转换为文件偏移
	@_lpFileHead:为文件头的起始地址
	@_dwRVA:为给定的RVA地址
*/
DWORD _RVAToOffset(DWORD _lpFileHead, DWORD _dwRVA);

/*
	判断标志位是否为 1
*/
//BOOLEAN IsFlag(PE_FLAG_15 peFlag,DWORD flag);

/*
	加载文件到内存
	@filePath: 文件路径
	@mem: 成功加载返回地址
	@return: 返回文件大小, 错误返回-1
	@ps: 使用完之后一定使用 VirtualFree(mem, 0, MEM_RELEASE) 释放内存
*/
DWORD _FileToFileBuffer(IN LPSTR* filePath, OUT LPVOID* mem);

/*
	验证DosSignature 是否正确
	@mem: 内存
*/
BOOL IsDosSignature(LPVOID mem);


/*
	获取导入表
	@_lpFileHeader: 映射到内存的文件地址
*/
VOID _getImportInfo(DWORD _lpFileHeader);