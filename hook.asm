section .text
global hookedCallback:
extern GetSyscallName

hookedCallback:
    push rcx
    push r10
    mov rcx, r10
    call GetSyscallName
    pop r10
    pop rcx
    jmp r10