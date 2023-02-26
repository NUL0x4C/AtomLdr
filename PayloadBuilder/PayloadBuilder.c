/*
	takes a .bin payload file and encrypts it with AES 256 CBC. The key and iv are then encrypted using a small xor function
	and saved inside the payload file "PayloadConfig.pc"

*/

#include <Windows.h>
#include <stdio.h>
#include <time.h>

#include "ctaes.h"

#define KEY_SIZE		0x20
#define IV_SIZE			0x10
#define FILENAME		"PayloadConfig.pc"

BOOL ReportError(const char* ApiName) {
	printf("[!] \"%s\" [ FAILED ] \t%d \n", ApiName, GetLastError());
	return FALSE;
}

BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData) {

	printf("[i] Reading \"%s\" ... ", FileInput);

	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD FileSize = NULL;
	DWORD lpNumberOfBytesRead = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return ReportError("CreateFileA");
	}

	FileSize = GetFileSize(hFile, NULL);

	unsigned char* Payload = (unsigned char*)malloc(FileSize);

	ZeroMemory(Payload, FileSize);

	if (!ReadFile(hFile, Payload, FileSize, &lpNumberOfBytesRead, NULL)) {
		return ReportError("ReadFile");
	}

	printf("[+] DONE \n");


	*pPayloadData = Payload;
	*sPayloadSize = lpNumberOfBytesRead;

	CloseHandle(hFile);

	if (*pPayloadData == NULL || *sPayloadSize == NULL)
		return FALSE;

	return TRUE;
}


VOID GenerateBytes(unsigned char* pBuff, DWORD dwBuffSize) {

	for (size_t i = 0; i < dwBuffSize; i++)
		pBuff[i] = rand() % 256;

}

BOOL WritePayloadFile(const char* FileInput, DWORD sPayloadSize, unsigned char* pPayloadData) {

	printf("[i] Writing \"%s\" ... ", FileInput);

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	DWORD	lpNumberOfBytesWritten = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return ReportError("CreateFileA");


	if (!WriteFile(hFile, pPayloadData, sPayloadSize, &lpNumberOfBytesWritten, NULL) || sPayloadSize != lpNumberOfBytesWritten)
		return ReportError("WriteFile");

	CloseHandle(hFile);

	printf("[+] DONE \n");
	return TRUE;
}



VOID HideAesKeyByIv(IN OUT PBYTE ptAesKey, IN OUT PBYTE ptAesIv) {

	for (int i = 1; i < KEY_SIZE; i++) {
		for (int j = 0; j < IV_SIZE; j++) {
			ptAesKey[i] ^= (BYTE)ptAesIv[j];
		}
	}
	for (int i = 0; i < IV_SIZE; i++) {
		ptAesIv[i] ^= (BYTE)ptAesKey[0];
	}
	for (int i = 0; i < KEY_SIZE; i++) {
		ptAesKey[i] += 0x03;
	}
	for (int i = 0; i < IV_SIZE; i++) {
		ptAesIv[i] += 0x03;
	}
}

/*

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

*/




int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("[!] Please Enter Your Payload File Name \n");
		return 0;
	}

	printf("\n");

	// seed for the key generation part
	srand(time(NULL));

	DWORD	sPayloadSize = NULL;
	PVOID	pPayloadData = NULL;

	// reading input file
	if (!ReadPayloadFile(argv[1], &sPayloadSize, &pPayloadData)) {
		return 0;
	}
	printf("\t>>> Read Payload Size : %ld\n", sPayloadSize);

	BYTE	AesKey [KEY_SIZE];
	// generate the key bytes
	GenerateBytes(AesKey, KEY_SIZE);

	// printing bytes to console
	printf("[i] The Generate Key Bytes: [ ");
	for (size_t i = 0; i < KEY_SIZE; i++)
		printf("%02X ", AesKey[i]);
	printf("]\n");

	// seed 2
	srand(time(NULL) ^ (int)AesKey[0]);

	BYTE	AesIv[IV_SIZE];
	// generate the key bytes
	GenerateBytes(AesIv, IV_SIZE);

	// printing bytes to console
	printf("[i] The Generate Iv Bytes: [ ");
	for (size_t i = 0; i < IV_SIZE; i++)
		printf("%02X ", AesIv[i]);
	printf("]\n");


	AES256_CBC_ctx ctx = { 0 };
	AES256_CBC_init(&ctx, AesKey, AesIv);
	PBYTE	ctPayloadData = NULL;
	SIZE_T	ctPayloadSize = NULL;


	// since we are using aes, we need to make sure that the payload is multiple of 16
	if (sPayloadSize % 16 != 0) {
		printf("[-] Payload Size Is Not Multiple of 16, Padding ... ");
		
		// dirty fix
		SIZE_T	PaddedPayloadSize	= sPayloadSize + 16 - (sPayloadSize % 16);
		PBYTE	PaddedPayload		= (PBYTE)malloc(PaddedPayloadSize);
		if (!PaddedPayload)
			return -1;
		ZeroMemory(PaddedPayload, PaddedPayloadSize);
		memcpy(PaddedPayload, pPayloadData, sPayloadSize);
		printf("[+] DONE \n\t>>> New Payload Size : %ld\n", PaddedPayloadSize);

		if (!AES256_CBC_encrypt(&ctx, PaddedPayload, PaddedPayloadSize, &ctPayloadData))
			return -1;

		ctPayloadSize = PaddedPayloadSize;
	}
	else {
	
		if (!AES256_CBC_encrypt(&ctx, pPayloadData, sPayloadSize, &ctPayloadData))
			return -1;

		ctPayloadSize = sPayloadSize;
	}

	free(pPayloadData);
	pPayloadData = NULL;
	printf("[+] Payload Encrypted At : 0x%p \n", ctPayloadData);


	// encrypt the key and iv
	HideAesKeyByIv(AesKey, AesIv);
	
	printf("\t>>> The Encrypted Key Bytes: [ ");
	for (size_t i = 0; i < KEY_SIZE; i++)
		printf("%02X ", AesKey[i]);
	printf("]\n");

	printf("\t>>> The Encrypted Iv Bytes: [ ");
	for (size_t i = 0; i < IV_SIZE; i++)
		printf("%02X ", AesIv[i]);
	printf("]\n");


	SIZE_T	sNewPayloadSize = (SIZE_T)(ctPayloadSize + KEY_SIZE + IV_SIZE);
	PVOID	pNewPayloadData = malloc(sNewPayloadSize);

	if(pNewPayloadData) {
		ZeroMemory(pNewPayloadData, sNewPayloadSize);
		memcpy(pNewPayloadData, AesKey, KEY_SIZE);
		memcpy((PVOID)((ULONG_PTR)pNewPayloadData + KEY_SIZE), AesIv, IV_SIZE);
		memcpy((PVOID)((ULONG_PTR)pNewPayloadData + KEY_SIZE + IV_SIZE), ctPayloadData, ctPayloadSize);
		HeapFree(GetProcessHeap(), 0, ctPayloadData);
	}



	// writing the new buffer to FILENAME
	if (!WritePayloadFile(FILENAME, sNewPayloadSize, pNewPayloadData)) {							// writing the key + the encrypted payload to FILENAME
		return -1;
	}

	// some info
	CHAR CurrentDir[MAX_PATH * 2];
	GetCurrentDirectoryA(MAX_PATH * 2, CurrentDir);

	printf("[+] File \"%s\" Is Successfully Written Under : %s \n", FILENAME, CurrentDir);
	free(pNewPayloadData);
	return 0;
}



