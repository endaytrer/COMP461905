# PLT trampoline for lazy binding
.text
.globl trampoline
.hidden trampoline
.type trampoline, @function
.extern runtimeResolve

trampoline:
    
# Your code here
    stp fp, lr, [sp, #-16]!
    mov fp, sp


    # save calling parameters
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!

    ldr x0, [x16, #-8]
    ldr x1, [fp, #16]
    sub x1, x1, x16
    lsr x1, x1, #3
    sub x1, x1, #1

    bl runtimeResolve
    mov x9, x0

    ldp x6, x7, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
    ldp fp, lr, [sp], #16
    ldp x16, lr, [sp], #16
    br x9

