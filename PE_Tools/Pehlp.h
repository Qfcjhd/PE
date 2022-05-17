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