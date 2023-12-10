.section .note.GNU-stack,"",@progbits
# PLT trampoline for lazy binding
    .text
    .globl trampoline
    .hidden trampoline
    .type trampoline, @function
    .align 16

trampoline:

# Your code here
    push %rbp
    mov %rsp, %rbp


    # save calling parameters
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %r8
    push %r9

    mov 8(%rbp), %rdi
    mov 16(%rbp), %rsi

    call runtimeResolve

    # restore calling parameters
    pop %r9
    pop %r8
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi
    # restore to original context.
    leave
    # remove lib address and reloc symbol from stack.
    add $16, %rsp
    # since ip is already pushed on stack, just jump to it.
    jmp *%rax