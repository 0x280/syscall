.data
	wSystemCall DWORD 000h

.code 

__setup_syscall proc
    mov wSystemCall, 000h
	mov wSystemCall, ecx
	ret
__setup_syscall endp

__invoke_syscall proc
    mov r10, rcx
    mov eax, wSystemCall
    syscall
    ret
__invoke_syscall endp

end
