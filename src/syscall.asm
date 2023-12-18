.data
    dwSystemCall DWORD 000h
.code 

__setup_syscall proc
    mov dwSystemCall, 000h
    mov dwSystemCall, ecx
    ret
__setup_syscall endp

__invoke_syscall proc
    mov r10, rcx
    mov eax, dwSystemCall
    syscall
    ret
__invoke_syscall endp

end
