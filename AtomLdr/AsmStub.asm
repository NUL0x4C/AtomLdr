.data
	dwSyscallNumber		DWORD	0h			; the SSn 
	qSyscallInsAddress	QWORD	0h			; the address of a "syscall; ret;" instruction 

.code


	public SetConfig
SetConfig proc	
	mov dwSyscallNumber, ecx
	mov qSyscallInsAddress, rdx			
	ret
SetConfig endp


	public HellHall
HellHall proc
	mov r10, rcx
	mov eax, dwSyscallNumber				 
	jmp qword ptr [qSyscallInsAddress]		
	ret
HellHall endp


end