[BITS 64]
GLOBAL InstrumentationHook
extern InstrumentationCHook

section .text
InstrumentationHook:
        push    rbp                 ; Save previous base pointer
        mov     rbp, rsp            ; Set up new base pointer
        sub     rsp, 128

        mov r11, rax
        push r10

        ;GENERATE_EXCEPTION_FRAME Rbp
        mov rdx, r11
        mov rcx, r10
        call InstrumentationCHook
        ;RESTORE_EXCEPTION_STATE Rbp

        pop r10

        leave
        jmp r10

