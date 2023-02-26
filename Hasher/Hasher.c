#include <Windows.h>
#include <stdio.h>

#define SEEDb	0xED788320	// Used by the '_CRC32b' function
#define SEEDa	0x04C11DB7	// Used by the '_CRC32a' function


DWORD _CRC32b(unsigned char* str) {

	unsigned int   byte = 0x0,
		mask = 0x0,
		crc = 0xFFFFFFFF;
	int         i = 0x0,
		j = 0x0;

	while (str[i] != 0) {
		byte = str[i];
		crc = crc ^ byte;

		for (j = 7; j >= 0; j--) {
			mask = -1 * (crc & 1);
			crc = (crc >> 1) ^ (SEEDb & mask);
		}

		i++;
	}
	return ~crc;
}


unsigned reverse(unsigned x) {
	x = ((x & 0x55555555) << 1) | ((x >> 1) & 0x55555555);
	x = ((x & 0x33333333) << 2) | ((x >> 2) & 0x33333333);
	x = ((x & 0x0F0F0F0F) << 4) | ((x >> 4) & 0x0F0F0F0F);
	x = (x << 24) | ((x & 0xFF00) << 8) |
		((x >> 8) & 0xFF00) | (x >> 24);
	return x;
}

DWORD _CRC32a(unsigned char* str) {
	int i, j;
	unsigned int byte, crc;

	i = 0;
	crc = 0xFFFFFFFF;
	while (str[i] != 0) {
		byte = str[i];
		byte = reverse(byte);
		for (j = 0; j <= 7; j++) {
			if ((int)(crc ^ byte) < 0)
				crc = (crc << 1) ^ SEEDa;
			else crc = crc << 1;
			byte = byte << 1;
		}
		i = i + 1;
	}
	return reverse(~crc);
}


#define HASHa(API)	(_CRC32a((unsigned char*)API))
#define STRa "_CRC32a"

#define HASHb(API)	(_CRC32b((unsigned char*)API))
#define STRb "_CRC32b"


int main() {


	printf("#define %s%s\t 0x%0.8X \n", "NtOpenSection", STRb, HASHb("NtOpenSection"));
	printf("#define %s%s\t 0x%0.8X \n", "NtCreateSection", STRb, HASHb("NtCreateSection"));
	printf("#define %s%s\t 0x%0.8X \n", "NtMapViewOfSection", STRb, HASHb("NtMapViewOfSection"));
	printf("#define %s%s\t 0x%0.8X \n", "NtUnmapViewOfSection", STRb, HASHb("NtUnmapViewOfSection"));
	printf("#define %s%s\t 0x%0.8X \n", "NtProtectVirtualMemory", STRb, HASHb("NtProtectVirtualMemory"));

	printf("#define %s%s\t 0x%0.8X \n", "NtOpenThread", STRb, HASHb("NtOpenThread"));
	printf("#define %s%s\t 0x%0.8X \n", "NtSuspendThread", STRb, HASHb("NtSuspendThread"));
	printf("#define %s%s\t 0x%0.8X \n", "NtResumeThread", STRb, HASHb("NtResumeThread"));

	printf("#define %s%s\t 0x%0.8X \n", "NtClose", STRb, HASHb("NtClose"));

	// hhhh
	printf("%c", '\n');

	printf("#define %s%s\t 0x%0.8X \n", "win32u", STRb, HASHb(L"win32u.dll"));
	printf("#define %s%s\t 0x%0.8X \n", "WIN32U", STRb, HASHb(L"WIN32U.DLL"));
		
	// hhhh		x2
	printf("%c%c//", '\n', '\n');

	// idk why
	signed int j = rand() % 0xFFF;
	while (1) {
		if (j - 0x5 == -0x4) {
			printf("%c%c", 0x0A, 0x0A);
			break;
		}
		printf("%c", 0x2d);
		j--;
	}

	printf("#define %s%s\t 0x%0.8X \n", "NtAllocateVirtualMemory", STRa, HASHa("NtAllocateVirtualMemory"));
	printf("#define %s%s\t 0x%0.8X \n", "NtProtectVirtualMemory", STRa, HASHa("NtProtectVirtualMemory"));
	printf("#define %s%s\t 0x%0.8X \n", "NtCreateThreadEx", STRa, HASHa("NtCreateThreadEx"));
	printf("#define %s%s\t 0x%0.8X \n", "NtQueueApcThread", STRa, HASHa("NtQueueApcThread"));
	printf("#define %s%s\t 0x%0.8X \n", "NtWaitForMultipleObjects", STRa, HASHa("NtWaitForMultipleObjects"));
	
	printf("#define %s%s\t 0x%0.8X \n", "RtlFillMemory", STRa, HASHa("RtlFillMemory"));
	printf("#define %s%s\t 0x%0.8X \n", "CreateToolhelp32Snapshot", STRa, HASHa("CreateToolhelp32Snapshot"));
	printf("#define %s%s\t 0x%0.8X \n", "Thread32First", STRa, HASHa("Thread32First"));
	printf("#define %s%s\t 0x%0.8X \n", "Thread32Next", STRa, HASHa("Thread32Next"));
	printf("#define %s%s\t 0x%0.8X \n", "CloseHandle", STRa, HASHa("CloseHandle"));

	// 0x68 0x68 0x68 0x68 
	printf("%c", 0x0A);

	printf("#define %s%s\t 0x%0.8X \n", "NTDLLDLL", STRa, HASHa("NTDLL.DLL"));
	printf("#define %s%s\t 0x%0.8X \n", "KERNEL32DLL", STRa, HASHa("KERNEL32.DLL"));
	
	// 0x68 0x68 0x68 0x68		x2
	printf("%c%c", 0x0A, 0x0A);

	printf("#define %s%s\t 0x%0.8X \n", "Atom", STRb, HASHb(L"Atom"));



	//\
	printf("#define %s%s\t 0x%0.8X \n", "", STRb, HASHb(""));
	// 
	//\
	printf("#define %s%s\t 0x%0.8X \n", "", STRa, HASHa(""));


	return 0;
}
