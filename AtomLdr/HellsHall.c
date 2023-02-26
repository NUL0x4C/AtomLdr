#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "HellsHall.h"
#include "Debug.h"

#define UP		-32
#define DOWN	32

typedef struct _NTDLL {

    PBYTE                       pNtdll;
    PIMAGE_DOS_HEADER           pImgDos;
    PIMAGE_NT_HEADERS           pImgNtHdrs;
    PIMAGE_EXPORT_DIRECTORY     pImgExpDir;
    PDWORD                      pdwArrayOfFunctions;
    PDWORD                      pdwArrayOfNames;
    PWORD                       pwArrayOfOrdinals;

}NTDLL, * PNTDLL;


NTDLL       NtdllSt = { 0 };



// USED TO CUT TIME
BOOL InitilizeNtdllConfig() {

    //  CHECK
    if (NtdllSt.pdwArrayOfFunctions != NULL && NtdllSt.pdwArrayOfNames != NULL && NtdllSt.pwArrayOfOrdinals != NULL)
        return TRUE;


    PPEB                    pPeb = NULL;
    PLDR_DATA_TABLE_ENTRY   pDte = NULL;
    PBYTE                   uNtdll = NULL;

    RtlSecureZeroMemory(&NtdllSt, sizeof(NTDLL));

    //  PEB
    pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb == NULL || pPeb->OSMajorVersion != 0xA)
        return FALSE;

    //  NTDLL
    pDte = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
    if (!pDte)
        return FALSE;

    NtdllSt.pNtdll = uNtdll = pDte->DllBase;

    //  DOS
    NtdllSt.pImgDos = (PIMAGE_DOS_HEADER)uNtdll;
    if (NtdllSt.pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    //  NT
    NtdllSt.pImgNtHdrs = (PIMAGE_NT_HEADERS)(uNtdll + NtdllSt.pImgDos->e_lfanew);
    if (NtdllSt.pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    //  EXPORT
    NtdllSt.pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uNtdll + NtdllSt.pImgNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);
    if (!NtdllSt.pImgExpDir || !NtdllSt.pImgExpDir->Base)
        return NULL;

    //  ARRAYS
    NtdllSt.pdwArrayOfFunctions = (PDWORD)(uNtdll + NtdllSt.pImgExpDir->AddressOfFunctions);
    NtdllSt.pdwArrayOfNames		= (PDWORD)(uNtdll + NtdllSt.pImgExpDir->AddressOfNames);
    NtdllSt.pwArrayOfOrdinals	= (PWORD)(uNtdll + NtdllSt.pImgExpDir->AddressOfNameOrdinals);

    //  CHECK
    if (!NtdllSt.pdwArrayOfFunctions || !NtdllSt.pdwArrayOfNames || !NtdllSt.pwArrayOfOrdinals)
        return FALSE;

    return TRUE;
}


/*
	search for 'syscall; ret;' outside of 'ntdll.dll' [inside of win32u.dll]
*/
BOOL SearchForRop(OUT PVOID* ppRopAddress) {

	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
	// 'i' is used to skip over the local image and ntdll image
	unsigned int			i = 0;

	while (pDte) {

		if (pDte->FullDllName.Length != NULL) {
			// define 'SEARCH_ALL_DLLS' to search all the loaded modules - not recommended tho
			// cuz if an ROP is found outside of win32udll, it will be an RW .text section (will be done later when unhooking), 
			// and thus the process will crash
#ifdef SEARCH_ALL_DLLS
			if (i >= 2) {
#else		
			// search only in 'win32udll' because its the only module to be RX when unhooking
			if (HASHb(pDte->FullDllName.Buffer) == win32udll_CRC32b || HASHb(pDte->FullDllName.Buffer) == WIN32UDLL_CRC32b) {
#endif // SEARCH_ALL

#ifdef DEBUG
				PRINTW(L">>> Searching in \"%s\" ... \n", pDte->FullDllName.Buffer)
#endif // DEBUG
				ULONG_PTR uModule = (ULONG_PTR)pDte->InInitializationOrderLinks.Flink;
				PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)uModule;
				if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
					return FALSE;
				PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(uModule + pDosHdr->e_lfanew);
				if (pNtHdrs->Signature != IMAGE_NT_SIGNATURE)
					return FALSE;

				// search only in the text section, where we have RX permissions
				PVOID	pTxtSection = (PVOID)(uModule + pNtHdrs->OptionalHeader.BaseOfCode);
				SIZE_T	sTextSize	= (SIZE_T)pNtHdrs->OptionalHeader.SizeOfCode;

				// searching for
				// <syscall>
				// <ret>	
				// instructions
				for (size_t j = 0; j < sTextSize; j++) {
					if (*((PBYTE)pTxtSection + j) == 0x0F && *((PBYTE)pTxtSection + j + 1) == 0x05 && *((PBYTE)pTxtSection + j + 2) == 0xC3) {
#ifdef DEBUG
						PRINTA("\t[+] Found \"syscall; ret\" gadget At - 0x%p \n", ((PBYTE)pTxtSection + j))
#endif // DEBUG
						*ppRopAddress = (PVOID)((PBYTE)pTxtSection + j);
						return TRUE;
					}
				}
			}

		}
		else {
			break;
		}
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
		i++;
	}

	if (*ppRopAddress == NULL)
		return FALSE;
	else
		return TRUE;
}


/*
	used to populate the input 'SYSCALL' structure
*/
BOOL InitilizeSysFunc(IN DWORD dwSysFuncHash, OUT PSYSCALL pSyscall) {

    if (!dwSysFuncHash || (!NtdllSt.pNtdll && !InitilizeNtdllConfig()))
        return FALSE;


    for (DWORD i = 0; i < NtdllSt.pImgExpDir->NumberOfFunctions; i++) {

        CHAR* cFuncName = (CHAR*)(NtdllSt.pdwArrayOfNames[i] + NtdllSt.pNtdll);

        if (HASHb(cFuncName) == dwSysFuncHash) {
            
            pSyscall->dwSysFuncHash     = dwSysFuncHash;
            pSyscall->pSyscallAddress   = (PVOID)(NtdllSt.pdwArrayOfFunctions[NtdllSt.pwArrayOfOrdinals[i]] + NtdllSt.pNtdll);

			if (*((PBYTE)pSyscall->pSyscallAddress) == 0x4c
				&& *((PBYTE)pSyscall->pSyscallAddress + 1) == 0x8b
				&& *((PBYTE)pSyscall->pSyscallAddress + 2) == 0xd1
				&& *((PBYTE)pSyscall->pSyscallAddress + 3) == 0xb8
				&& *((PBYTE)pSyscall->pSyscallAddress + 6) == 0x00
				&& *((PBYTE)pSyscall->pSyscallAddress + 7) == 0x00) {
				BYTE high = *((PBYTE)pSyscall->pSyscallAddress + 5);
				BYTE low = *((PBYTE)pSyscall->pSyscallAddress + 4);
				pSyscall->dwSyscallNumber = (high << 8) | low;
				break;
			}

			//if hooked check the neighborhood to find clean syscall 1
			if (*((PBYTE)pSyscall->pSyscallAddress) == 0xe9) {
				for (WORD idx = 1; idx <= 500; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pSyscall->pSyscallAddress + idx * DOWN) == 0x4c
						&& *((PBYTE)pSyscall->pSyscallAddress + 1 + idx * DOWN) == 0x8b
						&& *((PBYTE)pSyscall->pSyscallAddress + 2 + idx * DOWN) == 0xd1
						&& *((PBYTE)pSyscall->pSyscallAddress + 3 + idx * DOWN) == 0xb8
						&& *((PBYTE)pSyscall->pSyscallAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pSyscall->pSyscallAddress + 7 + idx * DOWN) == 0x00) {
						BYTE high = *((PBYTE)pSyscall->pSyscallAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pSyscall->pSyscallAddress + 4 + idx * DOWN);
						pSyscall->dwSyscallNumber = (high << 8) | low - idx;
						break;
					}
					// check neighboring syscall up
					if (*((PBYTE)pSyscall->pSyscallAddress + idx * UP) == 0x4c
						&& *((PBYTE)pSyscall->pSyscallAddress + 1 + idx * UP) == 0x8b
						&& *((PBYTE)pSyscall->pSyscallAddress + 2 + idx * UP) == 0xd1
						&& *((PBYTE)pSyscall->pSyscallAddress + 3 + idx * UP) == 0xb8
						&& *((PBYTE)pSyscall->pSyscallAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pSyscall->pSyscallAddress + 7 + idx * UP) == 0x00) {
						BYTE high = *((PBYTE)pSyscall->pSyscallAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pSyscall->pSyscallAddress + 4 + idx * UP);
						pSyscall->dwSyscallNumber = (high << 8) | low + idx;
						break;
					}

				}
				break;
			}

			//if hooked check the neighborhood to find clean syscall 2
			if (*((PBYTE)pSyscall->pSyscallAddress + 3) == 0xe9) {
				for (WORD idx = 1; idx <= 500; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pSyscall->pSyscallAddress + idx * DOWN) == 0x4c
						&& *((PBYTE)pSyscall->pSyscallAddress + 1 + idx * DOWN) == 0x8b
						&& *((PBYTE)pSyscall->pSyscallAddress + 2 + idx * DOWN) == 0xd1
						&& *((PBYTE)pSyscall->pSyscallAddress + 3 + idx * DOWN) == 0xb8
						&& *((PBYTE)pSyscall->pSyscallAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pSyscall->pSyscallAddress + 7 + idx * DOWN) == 0x00) {
						BYTE high = *((PBYTE)pSyscall->pSyscallAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pSyscall->pSyscallAddress + 4 + idx * DOWN);
						pSyscall->dwSyscallNumber = (high << 8) | low - idx;
						break;
					}
					// check neighboring syscall up
					if (*((PBYTE)pSyscall->pSyscallAddress + idx * UP) == 0x4c
						&& *((PBYTE)pSyscall->pSyscallAddress + 1 + idx * UP) == 0x8b
						&& *((PBYTE)pSyscall->pSyscallAddress + 2 + idx * UP) == 0xd1
						&& *((PBYTE)pSyscall->pSyscallAddress + 3 + idx * UP) == 0xb8
						&& *((PBYTE)pSyscall->pSyscallAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pSyscall->pSyscallAddress + 7 + idx * UP) == 0x00) {
						BYTE high = *((PBYTE)pSyscall->pSyscallAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pSyscall->pSyscallAddress + 4 + idx * UP);
						pSyscall->dwSyscallNumber = (high << 8) | low + idx;
						break;
					}
				}
				break;
			}
        }
    }

	if (!pSyscall->pSyscallAddress || !pSyscall->dwSyscallNumber)
		return FALSE;

	return SearchForRop(&pSyscall->pSyscallInstAddress);
}


