#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>

#include "SplitRecv.h"

#define CryptoBufferVFun 0x21DC868
#define WriteBuffRva 0x1278950
#define ReadBuffRva 0x1278820
#define ReadBuffHookRva ReadBuffRva + 0x102

#define g_公共发包CALLRVA 0x148ED10
#define g_公共收包RVA 0x187D5C0 + 0x46 //(-0x80)48 8B 0F 48 8B 01 4C 8B C3 0F B7 D6                             $+46             00007FF76BDC2AA6           | 48:8D9424 80010000       | lea rdx,qword ptr ss:[rsp+180]                                      |
#define g_收包包内容偏移 0x1c0
#define g_收包总已读取长度偏移 0x190
#define g_收包当前读取长度偏移 0x1a0

std::vector<CPackageField> g_PackageFieldArray;

bool g_Send开关 = false;
bool g_Recv开关 = false;
bool g_自动解析收包字段 = false;

DWORD64 PathOfExile = (DWORD64)GetModuleHandle(NULL);
auto CryptoBuffer = (bool(__thiscall *)(PVOID _this, char *inBuff, char *outBuff, size_t size)) * ((DWORD64 *)(PathOfExile + CryptoBufferVFun));
auto DecryptBuffer = (bool(__thiscall *)(PVOID _this, char *inBuff, char *outBuff, size_t size)) * ((DWORD64 *)(PathOfExile + CryptoBufferVFun + 8));
auto WriteBuff = (bool(__thiscall *)(PVOID _this, char *buff, size_t size))(PathOfExile + WriteBuffRva);
auto ReadBuff = (bool(__thiscall *)(PVOID _this, char *buff, size_t size))(PathOfExile + ReadBuffRva);

void PrintSend(void *mem, unsigned int len, WORD colour);
void PrintRecv(void *mem, unsigned int len, WORD colour);

bool MyCryptoBuffer(PVOID _this, char *inBuff, char *outBuff, size_t size)
{

	return CryptoBuffer(_this, inBuff, outBuff, size);
}

bool MyDecryptBuffer(PVOID _this, char *inBuff, char *outBuff, size_t size)
{
	bool bRet = DecryptBuffer(_this, inBuff, outBuff, size);
	WORD PacketID = ntohs(*(WORD *)inBuff);

	return bRet;
}

PVOID OldExceptionHandler = NULL;
LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS *ExceptionInfo)
{

	if (ExceptionInfo->ContextRecord->Rip == (DWORD64)WriteBuff)
	{
		*(DWORD64 *)(ExceptionInfo->ContextRecord->Rsp + 8) = ExceptionInfo->ContextRecord->Rbx;
		ExceptionInfo->ContextRecord->Rip += 5;

		CPackageField pf;
		pf.m_Size = (DWORD)(ExceptionInfo->ContextRecord->R8);
		memcpy_s(pf.m_Buffer, PACKAGEFIELDSIZE, (void *)(ExceptionInfo->ContextRecord->Rdx), pf.m_Size);
		g_PackageFieldArray.push_back(pf);
		//hexdump((void *)pf.m_Buffer, pf.m_Size);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (ExceptionInfo->ContextRecord->Rip == PathOfExile + ReadBuffHookRva)
	{
		static int i = 0;
		*(DWORD64 *)(ExceptionInfo->ContextRecord->Rbx + 0x1A0) += ExceptionInfo->ContextRecord->Rdi;
		ExceptionInfo->ContextRecord->Rip += 7;
		if (g_自动解析收包字段 && g_收集解密字段)
		{
			
			CPackageField *pf = new CPackageField;
			pf->m_Size = ExceptionInfo->ContextRecord->Rdi;
			if (g_解密字段循环次数 >= 0)
			{
				// memcpy_s(pf->m_Buffer, PACKAGEFIELDSIZE, (void *)ExceptionInfo->ContextRecord->Rax, pf->m_Size);
				// g_收包字段数组.push_back(pf);
				hexdump((void *)ExceptionInfo->ContextRecord->Rax, ExceptionInfo->ContextRecord->Rdi, 0xf);
				g_解密字段循环次数--;
			}
			else
			{
				g_收集解密字段 = false;
			}
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (ExceptionInfo->ContextRecord->Rip == PathOfExile + g_公共发包CALLRVA)
	{
		*(DWORD64 *)(ExceptionInfo->ContextRecord->Rsp + 0x10) = ExceptionInfo->ContextRecord->Rbx;
		ExceptionInfo->ContextRecord->Rip += 5;

		char *buffer = (char *)(*((DWORD64 *)(ExceptionInfo->ContextRecord->Rcx + 0x1a8)));
		DWORD size = *((DWORD *)(ExceptionInfo->ContextRecord->Rcx + 0x180));
		WORD PacketID = ntohs(*(WORD *)buffer);
		if (g_Send开关 && size > 1 && PacketID != 0x0e && PacketID != 0 && PacketID != 1)
		{

			PrintSend(buffer, (DWORD)size, 6);
		}
		g_PackageFieldArray.clear();
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (ExceptionInfo->ContextRecord->Rip == PathOfExile + g_公共收包RVA)
	{
		ExceptionInfo->ContextRecord->Rdx = ExceptionInfo->ContextRecord->Rsp + 0x180;
		ExceptionInfo->ContextRecord->Rip += 8;
		DWORD64 总已读取长度 = *((DWORD64 *)(ExceptionInfo->ContextRecord->Rcx + g_收包总已读取长度偏移));
		DWORD64 当前读取长度 = *((DWORD64 *)(ExceptionInfo->ContextRecord->Rcx + g_收包当前读取长度偏移));
		DWORD64 是否有效 = *((DWORD64 *)(ExceptionInfo->ContextRecord->Rcx + g_收包总已读取长度偏移 + 8));
		CBuffer buffer((char *)(*((DWORD64 *)(ExceptionInfo->ContextRecord->Rcx + g_收包包内容偏移)) + 总已读取长度 + 当前读取长度) , *((DWORD64*)(ExceptionInfo->ContextRecord->Rcx)));
		if (g_Recv开关 && 是否有效 > 0)
		{
			buffer.解析收包();
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

void Hook()
{
	// 保存原始页属性
	DWORD OldProtect = 0;
	// 修改页保护属性
	// VirtualProtect((LPVOID)(PathOfExile + CryptoBufferVFun), 0x10, PAGE_READWRITE, &OldProtect);
	// *((DWORD64 *)(PathOfExile + CryptoBufferVFun)) = (DWORD64)MyCryptoBuffer;
	// *((DWORD64 *)(PathOfExile + CryptoBufferVFun + 8)) = (DWORD64)MyDecryptBuffer;
	// // 还原页保护属性
	// VirtualProtect((LPVOID)(PathOfExile + CryptoBufferVFun), 0x10, OldProtect, &OldProtect);

	OldExceptionHandler = AddVectoredExceptionHandler(1, ExceptionHandler);
	// Hook WriteBuff
	VirtualProtect(WriteBuff, 1, PAGE_EXECUTE_READWRITE, &OldProtect);
	*(byte *)(WriteBuff) = 0xCC;

	// Hook ReadBuff
	VirtualProtect((LPVOID)(PathOfExile + ReadBuffHookRva), 1, PAGE_EXECUTE_READWRITE, &OldProtect);
	*(byte *)(PathOfExile + ReadBuffHookRva) = 0xCC;

	// Hook 公共发包call
	VirtualProtect((LPVOID)(PathOfExile + g_公共发包CALLRVA), 1, PAGE_EXECUTE_READWRITE, &OldProtect);
	*(byte *)(PathOfExile + g_公共发包CALLRVA) = 0xCC;

	// Hook 公共收包
	VirtualProtect((LPVOID)(PathOfExile + g_公共收包RVA), 1, PAGE_EXECUTE_READWRITE, &OldProtect);
	*(byte *)(PathOfExile + g_公共收包RVA) = 0xCC;
}

void UnHook()
{
	// 保存原始页属性
	DWORD OldProtect = 0;
	// 修改页保护属性
	VirtualProtect((LPVOID)(PathOfExile + CryptoBufferVFun), 0x10, PAGE_READWRITE, &OldProtect);
	*((DWORD64 *)(PathOfExile + CryptoBufferVFun)) = (DWORD64)CryptoBuffer;
	*((DWORD64 *)(PathOfExile + CryptoBufferVFun + 8)) = (DWORD64)DecryptBuffer;
	// 还原页保护属性
	VirtualProtect((LPVOID)(PathOfExile + CryptoBufferVFun), 1, OldProtect, &OldProtect);

	// UnHook WriteBuff
	*(byte *)(WriteBuff) = 0x48;

	// UnHook ReadBuff
	*(byte *)(PathOfExile + ReadBuffHookRva) = 0x48;

	// UnHook 公共发包
	*(byte *)(PathOfExile + g_公共发包CALLRVA) = 0x48;
	RemoveVectoredContinueHandler(OldExceptionHandler);

	// UnHook 公共取包id
	*(byte *)(PathOfExile + g_公共收包RVA) = 0x48;
	RemoveVectoredContinueHandler(OldExceptionHandler);
}

DWORD WINAPI ThreadStart(LPVOID hModule)
{
	Hook();
	while (!GetAsyncKeyState(VK_END))
	{
		if (GetAsyncKeyState(VK_NUMPAD1))
		{
			printf("切换Send视图\n");
			g_Send开关 = !g_Send开关;
		}
		if (GetAsyncKeyState(VK_NUMPAD2))
		{
			printf("切换Recv视图\n");
			g_Recv开关 = !g_Recv开关;
		}
		if (GetAsyncKeyState(VK_NUMPAD3))
		{
			printf("切换自动解析收包字段成功\n");
			g_自动解析收包字段 = !g_自动解析收包字段;
		}
		if (GetAsyncKeyState(VK_DELETE))
		{
			system("cls");
		}
		Sleep(100);
	}
	UnHook();

	FreeLibraryAndExitThread((HMODULE)hModule, 0);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
					  DWORD ul_reason_for_call,
					  LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		system("MODE CON: COLS=80 LINES=9999");
		printf("DLL_PROCESS_ATTACH\n");
		// CreateThread
		CreateThread(0, 0, ThreadStart, (LPVOID)hModule, 0, 0);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		printf("DLL_PROCESS_DETACH\n");
		FreeConsole();
		break;
	}
	return TRUE;
}

void PrintSend(void *mem, unsigned int len, WORD colour)
{

	WORD PacketID = ntohs(*(WORD *)mem);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colour);
	printf("===============================================================================\n");
	printf("SEND id:%x 包长:%d\n", PacketID, len);

	DWORD sum = 0;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colour);
	for (auto i = g_PackageFieldArray.begin(); i != g_PackageFieldArray.end(); i++)
	{
		sum += (*i).m_Size;
		hexdump((*i).m_Buffer, (*i).m_Size, 0xf);
		if (sum >= len)
			break;
	}

	hexdump(mem, len, colour);
	g_PackageFieldArray.clear();
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colour);
	printf("===============================================================================\n");
	printf("\n\n");
}

void PrintRecv(void *mem, unsigned int len, WORD colour)
{

	WORD PacketID = ntohs(*(WORD *)mem);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colour);
	printf("===============================================================================\n");
	DWORD sum = 0;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colour);
	for (auto i = g_收包字段数组.begin(); i != g_收包字段数组.end(); i++)
	{
		hexdump((*i)->m_Buffer, (*i)->m_Size, 0xf);
		delete *i;
	}
	hexdump(mem, len, colour);
	g_收包字段数组.clear();
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colour);
	printf("===============================================================================\n");
	printf("\n\n");
}
