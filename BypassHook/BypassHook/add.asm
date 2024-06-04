; add.asm
.code
NtWriteProcessMemory PROC
  
    mov r10, rcx
    mov rax, 3Ah
    syscall
    ret          ; Return with the result in eax
NtWriteProcessMemory ENDP
END