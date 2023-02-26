#pragma once


#ifndef HELLSHALL_H
#define HELLSHALL_H


// from 'HellsHall.asm'
extern VOID SetConfig(DWORD dwSyscallNumber, PVOID pSyscallInstAddress);
extern HellHall();

// small macro to make things neater
#define INITIALIZE_SYSCALL(ST)(SetConfig((DWORD)ST.dwSyscallNumber, ST.pSyscallInstAddress))

// from 'HellsHall'
BOOL InitilizeSysFunc(IN DWORD dwSysFuncHash, OUT PSYSCALL pSyscall);


#endif // !HELLSHALL_H
