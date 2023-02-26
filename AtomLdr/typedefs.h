#ifndef TYPEDEFS_H
#define TYPEDEFS_H

#include <Windows.h>
#include <tlhelp32.h>

typedef NTSTATUS (NTAPI* fnNtAllocateVirtualMemory)(
	IN		HANDLE			ProcessHandle,
	IN OUT	PVOID*			BaseAddress,
	IN		ULONG			ZeroBits,
	IN OUT	PULONG			RegionSize,
	IN		ULONG			AllocationType,
	IN		ULONG			Protect
);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
	IN		HANDLE          ProcessHandle,
	IN OUT	PVOID*			BaseAddress,
	IN OUT	PULONG          NumberOfBytesToProtect,
	IN		ULONG           NewAccessProtection,
	OUT		PULONG          OldAccessProtection
);

typedef NTSTATUS (NTAPI* fnNtCreateThreadEx)(
	OUT PHANDLE				ThreadHandle,                 
	IN	ACCESS_MASK			DesiredAccess,             
	IN	POBJECT_ATTRIBUTES	ObjectAttributes,   
	IN	HANDLE				ProcessHandle,                  
	IN	PVOID				StartRoutine,                   
	IN	PVOID				Argument,                   
	IN	ULONG				CreateFlags,                     
	IN	SIZE_T				ZeroBits,                      
	IN	SIZE_T				StackSize,                   
	IN	SIZE_T				MaximumStackSize,               
	IN	PPS_ATTRIBUTE_LIST	AttributeList       
);


typedef HANDLE (WINAPI* fnCreateToolhelp32Snapshot)(
	IN DWORD				dwFlags,
	IN DWORD				th32ProcessID
);

typedef BOOL (WINAPI* fnThread32First)(
	IN		HANDLE          hSnapshot,
	IN OUT	LPTHREADENTRY32 lpte
);

typedef BOOL (WINAPI* fnThread32Next)(
	IN  HANDLE				hSnapshot,
	OUT LPTHREADENTRY32		lpte
);

typedef BOOL (WINAPI* fnCloseHandle)(
	IN HANDLE				hObject
);

typedef struct _IO_STATUS_BLOCK{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
	_In_ PVOID				ApcContext,
	_In_ PIO_STATUS_BLOCK	IoStatusBlock,
	_In_ ULONG				Reserved
);

typedef NTSTATUS(NTAPI* fnNtQueueApcThread)(
	IN HANDLE               ThreadHandle,
	IN PIO_APC_ROUTINE      ApcRoutine,
	IN PVOID                ApcRoutineContext,
	IN PIO_STATUS_BLOCK     ApcStatusBlock,
	IN ULONG                ApcReserved
);

typedef enum _OBJECT_WAIT_TYPE {

	WaitAllObject,
	WaitAnyObject

} OBJECT_WAIT_TYPE, * POBJECT_WAIT_TYPE;

typedef NTSTATUS(NTAPI* fnNtWaitForMultipleObjects)(
	IN ULONG                ObjectCount,
	IN PHANDLE              ObjectsArray,
	IN OBJECT_WAIT_TYPE     WaitType,
	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       TimeOut
);


#endif //!TYPEDEFS_H

