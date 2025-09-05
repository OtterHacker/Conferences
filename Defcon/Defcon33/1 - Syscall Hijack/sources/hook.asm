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
        ; TODO fix the call to the C hook function
        ; Hint: The C hook function takes 2 parameter
        ;           - The address of the calling function
        ;           - The current SYSRET code
        ; On x64, the calling convention says that:
        ;           - RCX hold the first parameter
        ;           - RDC hold the second parameter
        mov rdx, XX
        mov rcx, XX
        call XXXXXX

        ; Retrieve the calling address
        pop r10

        ; Cleanup
        leave
        ; Restore the execution flow
        ; TODO: Fix the jump needed to restore the execution flow
        ; Hint : In which register did we store the calling address ?
        jmp XX