/*
 * Linux x86_64 freestanding no-replace directory commit helper.
 *
 * Contract:
 *   fstat(5, retained-source), newfstatat(3, argv[1], AT_SYMLINK_NOFOLLOW),
 *   renameat2(3, argv[1], 4, argv[2], RENAME_NOREPLACE),
 *   newfstatat(4, argv[2], AT_SYMLINK_NOFOLLOW)
 *   0 success, 17 EEXIST, 18 EXDEV, 64 usage/name, 111 other errno.
 *
 * The caller supplies already-open directory descriptors 3 and 4.  This
 * program performs no path lookup outside those descriptors and emits no
 * stdout/stderr bytes.
 */
.section .text
.global _start
.type _start,@function

_start:
    mov    (%rsp), %rdi
    cmp    $3, %rdi
    jne    .Lusage

    mov    16(%rsp), %r12
    mov    24(%rsp), %r13
    mov    %r12, %rdi
    call   .Lvalid_name
    test   %eax, %eax
    jz     .Lusage
    mov    %r13, %rdi
    call   .Lvalid_name
    test   %eax, %eax
    jz     .Lusage

    call   .Lvalidate_source
    test   %eax, %eax
    jz     .Lother

    mov    $316, %eax              /* __NR_renameat2 */
    mov    $3, %edi                /* old parent directory fd */
    mov    %r12, %rsi             /* old basename */
    mov    $4, %edx                /* new parent directory fd */
    mov    %r13, %r10             /* new basename */
    mov    $1, %r8d                /* RENAME_NOREPLACE */
    xor    %r9d, %r9d
    syscall
    test   %rax, %rax
    jnz    .Lrename_error

    call   .Lvalidate_destination
    test   %eax, %eax
    jz     .Lother
    jmp    .Lsuccess

.Lrename_error:
    neg    %rax
    cmp    $17, %rax
    je     .Leexist
    cmp    $18, %rax
    je     .Lexdev
    mov    $111, %edi
    jmp    .Lexit

.Lusage:
    mov    $64, %edi
    jmp    .Lexit
.Leexist:
    mov    $17, %edi
    jmp    .Lexit
.Lexdev:
    mov    $18, %edi
    jmp    .Lexit
.Lother:
    mov    $111, %edi
    jmp    .Lexit
.Lsuccess:
    xor    %edi, %edi

.Lexit:
    mov    $60, %eax               /* __NR_exit */
    syscall
    hlt

/* eax = 1 iff rdi is a nonempty basename other than . or .. and has no /. */
.type .Lvalid_name,@function
.Lvalid_name:
    movzbl (%rdi), %eax
    test   %al, %al
    jz     .Linvalid
    cmp    $'.', %al
    jne    .Lscan
    cmpb   $0, 1(%rdi)
    je     .Linvalid
    cmpb   $'.', 1(%rdi)
    jne    .Lscan
    cmpb   $0, 2(%rdi)
    je     .Linvalid
.Lscan:
    mov    %rdi, %rcx
.Lscan_byte:
    movzbl (%rcx), %eax
    test   %al, %al
    jz     .Lvalid
    cmp    $'/', %al
    je     .Linvalid
    inc    %rcx
    jmp    .Lscan_byte
.Lvalid:
    mov    $1, %eax
    ret
.Linvalid:
    xor    %eax, %eax
    ret

/* fstat retained fd 5 and compare source parent/basename immediately before rename. */
.type .Lvalidate_source,@function
.Lvalidate_source:
    mov    $5, %eax                 /* __NR_fstat */
    mov    $5, %edi                /* retained source directory fd */
    lea    .Lretained_stat(%rip), %rsi
    syscall
    test   %rax, %rax
    jnz    .Lvalidation_fail
    mov    $262, %eax               /* __NR_newfstatat */
    mov    $3, %edi                /* source parent directory fd */
    mov    %r12, %rsi              /* source basename */
    lea    .Lobserved_stat(%rip), %rdx
    mov    $256, %r10d             /* AT_SYMLINK_NOFOLLOW */
    syscall
    test   %rax, %rax
    jnz    .Lvalidation_fail
    jmp    .Lcompare_stat_records

/* Compare destination basename to the retained fd after rename. */
.type .Lvalidate_destination,@function
.Lvalidate_destination:
    mov    $262, %eax               /* __NR_newfstatat */
    mov    $4, %edi                /* destination parent directory fd */
    mov    %r13, %rsi              /* destination basename */
    lea    .Lobserved_stat(%rip), %rdx
    mov    $256, %r10d             /* AT_SYMLINK_NOFOLLOW */
    syscall
    test   %rax, %rax
    jnz    .Lvalidation_fail
    jmp    .Lcompare_stat_records

/* Require directory type and exact device, inode, mode, uid, and gid. */
.type .Lcompare_stat_records,@function
.Lcompare_stat_records:
    movl   .Lretained_stat+24(%rip), %eax
    mov    %eax, %ecx
    and    $0170000, %ecx
    cmp    $0040000, %ecx
    jne    .Lvalidation_fail
    movl   .Lobserved_stat+24(%rip), %eax
    mov    %eax, %ecx
    and    $0170000, %ecx
    cmp    $0040000, %ecx
    jne    .Lvalidation_fail
    movq   .Lretained_stat(%rip), %rax
    cmpq   .Lobserved_stat(%rip), %rax
    jne    .Lvalidation_fail
    movq   .Lretained_stat+8(%rip), %rax
    cmpq   .Lobserved_stat+8(%rip), %rax
    jne    .Lvalidation_fail
    movl   .Lretained_stat+24(%rip), %eax
    cmpl   .Lobserved_stat+24(%rip), %eax
    jne    .Lvalidation_fail
    movl   .Lretained_stat+28(%rip), %eax
    cmpl   .Lobserved_stat+28(%rip), %eax
    jne    .Lvalidation_fail
    movl   .Lretained_stat+32(%rip), %eax
    cmpl   .Lobserved_stat+32(%rip), %eax
    jne    .Lvalidation_fail
    mov    $1, %eax
    ret
.Lvalidation_fail:
    xor    %eax, %eax
    ret

.section .bss
.align 8
.Lretained_stat:
    .skip 256
.Lobserved_stat:
    .skip 256

.section .note.GNU-stack,"",@progbits
