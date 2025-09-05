[BITS 64]
; Make the function available in the C code
global InstrumentationHook
extern InstrumentationCHook

section text
InstrumentationHook:
        ; Set some space on the stack for local variables

        push    rbp                 ; Save previous base pointer
        mov     rbp, rsp            ; Set up new base pointer
        sub     rsp, 128

        mov r11, rax
        push r10

        mov rdx, r11
        mov rcx, r10
        call InstrumentationCHook

        pop r10

        leave
        jmp r10

        end

