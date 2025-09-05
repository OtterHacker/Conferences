[BITS 64]
; Make the function available in the C code
global InstrumentationHook
extern InstrumentationCHook

section text
InstrumentationHook:
        ; Set some space on the stack for local variables
        push    rbp
        mov     rbp, rsp
        sub     rsp, 0x08

        ; Save the SYSRET initial value
        mov r11, rax
        ; Save the return address on the stack
        push r10

        ; Call the hook function
        mov rdx, r11
        mov rcx, r10
        call InstrumentationCHook

        ; Retrieve the calling address
        pop r10

        ; Cleanup
        leave
        ; Restore the execution flow
        jmp r10