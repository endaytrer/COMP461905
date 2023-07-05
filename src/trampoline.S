# PLT trampoline for lazy binding
    .text
    .globl trampoline
    .hidden trampoline
    .type trampoline, @function
    .align 16

trampoline:

# Your code here
    push %rdi
    push %rsi

    mov 16(%rsp), %rdi
    mov 24(%rsp), %rsi

    call runtimeResolve

    pop %rsi
    pop %rdi
    call *%rax
    leave
    ret 

# Your code here
