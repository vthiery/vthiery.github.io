---
layout: post
title: Reverse Engineering the "Bomb Lab" with Cutter
date: 2023-07-12
tags:
  - reverse-engineering
  - assembly
  - x86-64
  - cutter
  - write-up
---

## Context

I recently took the excellent ["Architecture 1001: x86-64 Assembly"](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Arch1001_x86-64_Asm+2021_v1/course/) course offered by Xeno Kovah on [OpenSecurityTraining2](https://p.ost2.fyi/courses/) to consolidate my knowledge of x86-64 assembly.
The final assignment consists in solving the ["Bomb Lab"](https://gitlab.com/opensecuritytraining/arch1001_x86-64_asm_code_for_class).

Although the course suggests to use [gdb](https://sourceware.org/gdb/current/onlinedocs/) or [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/), I decided to do it differently and use [Cutter](https://cutter.re/) with the following constraints:
  - Not using debug symbols - this is something Xeno actually recommends if one has some reverse-engineering experience, or want extra challenge
  - Perform a pure static analysis - using [gdb/gef](https://hugsy.github.io/gef/) would be much smarter here, but I really wanted to practice static analysis
  - Not using [rz-ghidra](https://github.com/rizinorg/rz-ghidra) or any decompiler since that would defeat the whole point of the exercise

I used Cutter Version 2.2.1 on Debian 11 and stuck to Intel syntax. Also, even though I have been using Cutter's "Graph" view a lot, only linear disassembly code snippets will be used to illustrate my analysis.

## Analysis 

### strings

```bash
❯ strings -n8 bomb

That's number 2.  Keep going!
Halfway there!
Good work!  On to the next...
Welcome to my fiendish little bomb. You have 6 phases with
which to blow yourself up. Have a nice day!
Phase 1 defused. How about the next one?
So you got that one.  Try this one.
I am just a renegade hockey mom.
Wow! You've defused the secret stage!
So you think you can stop the bomb with ctrl-c, do you?
Curses, you've found the secret phase!
But finding it and solving it are quite different...
Congratulations! You've defused the bomb!
Invalid phase%s
The bomb has blown up.
%d %d %d %d %d %d
```

Some useful information here already:
- 6 "phases" to defuse
- "I am just a renegade hockey mom." is likely the solution of one of the first phases
- there is a "secret phase"

 Reducing the string min-len might help finding other hints, but let's jump right into some assembly already!

### main

```asm
int main (int argc, char **argv, char **envp);
; arg unsigned long argc @ rdi
; arg char **filename @ rsi
0x00001449      endbr64
0x0000144d      push rbx
0x0000144e      cmp edi, 1         ; argc
0x00001451      je 0x154f
0x00001457      mov rbx, rsi       ; argv
0x0000145a      cmp edi, 2         ; argc
0x0000145d      jne 0x1584
0x00001463      mov rdi, qword [rsi + 8] ; const char *filename
0x00001467      lea rsi, data.00003004 ; 0x3004 ; const char *mode
0x0000146e      call fopen         ; sym.imp.fopen ; FILE *fopen(const char *filename, const char *mode)
0x00001473      mov qword data.00005698, rax ; 0x5698
0x0000147a      test rax, rax
0x0000147d      je 0x1562
0x00001483      call fcn.00001b31  ; fcn.00001b31
0x00001488      lea rdi, str.Welcome_to_my_fiendish_little_bomb._You_have_6_phases_with ; 0x3088 ; const char *s
0x0000148f      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001494      lea rdi, str.which_to_blow_yourself_up._Have_a_nice_day ; 0x30c8 ; const char *s
0x0000149b      call puts          ; sym.imp.puts ; int puts(const char *s)
0x000014a0      call fcn.00001c56  ; fcn.00001c56
0x000014a5      mov rdi, rax       ; int64_t arg1
0x000014a8      call fcn.000015a7  ; fcn.000015a7
0x000014ad      call fcn.00001d9e  ; fcn.00001d9e
0x000014b2      lea rdi, str.Phase_1_defused._How_about_the_next_one ; 0x30f8 ; const char *s
0x000014b9      call puts          ; sym.imp.puts ; int puts(const char *s)
0x000014be      call fcn.00001c56  ; fcn.00001c56
0x000014c3      mov rdi, rax
0x000014c6      call fcn.000015cb  ; fcn.000015cb
0x000014cb      call fcn.00001d9e  ; fcn.00001d9e
0x000014d0      lea rdi, str.That_s_number_2.__Keep_going ; 0x303d ; const char *s
0x000014d7      call puts          ; sym.imp.puts ; int puts(const char *s)
0x000014dc      call fcn.00001c56  ; fcn.00001c56
0x000014e1      mov rdi, rax       ; const char *s
0x000014e4      call fcn.00001639  ; fcn.00001639
0x000014e9      call fcn.00001d9e  ; fcn.00001d9e
0x000014ee      lea rdi, str.Halfway_there ; 0x305b ; const char *s
0x000014f5      call puts          ; sym.imp.puts ; int puts(const char *s)
0x000014fa      call fcn.00001c56  ; fcn.00001c56
0x000014ff      mov rdi, rax       ; const char *s
0x00001502      call fcn.0000174b  ; fcn.0000174b
0x00001507      call fcn.00001d9e  ; fcn.00001d9e
0x0000150c      lea rdi, str.So_you_got_that_one.__Try_this_one. ; 0x3128 ; const char *s
0x00001513      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001518      call fcn.00001c56  ; fcn.00001c56
0x0000151d      mov rdi, rax       ; const char *s
0x00001520      call fcn.000017c4  ; fcn.000017c4
0x00001525      call fcn.00001d9e  ; fcn.00001d9e
0x0000152a      lea rdi, str.Good_work___On_to_the_next... ; 0x306a ; const char *s
0x00001531      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001536      call fcn.00001c56  ; fcn.00001c56
0x0000153b      mov rdi, rax
0x0000153e      call fcn.0000185b  ; fcn.0000185b
0x00001543      call fcn.00001d9e  ; fcn.00001d9e
0x00001548      mov eax, 0
0x0000154d      pop rbx
0x0000154e      ret
```

Quick notes:
- there is an early `call fcn.00001b31` instruction
- multiple triplets of instructions:
    - `call fcn.00001c56`
    - `call fcn.0000????` , likely the phases
    - `call fcn.00001d9e`

#### Interrupt signal

`fcn.00001b31` calls the `signal` function to handle interrupts:

```asm
fcn.00001b31 ();
0x00001b31      endbr64
0x00001b35      sub rsp, 8
0x00001b39      lea rsi, data.00001a21 ; 0x1a21 ; void *func
0x00001b40      mov edi, 2         ; int sig
0x00001b45      call signal        ; sym.imp.signal ; void signal(int sig, void *func)
0x00001b4a      add rsp, 8
0x00001b4e      ret
0x00001b4f      endbr64
0x00001b53      ret
```

with the following handler to troll users:

```asm
;-- data.00001a21:
0x00001a21      endbr64
0x00001a25      push rax
0x00001a26      pop rax
0x00001a27      sub rsp, 8
0x00001a2b      lea rdi, str.So_you_think_you_can_stop_the_bomb_with_ctrl_c__do_you ; 0x3200
0x00001a32      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001a37      mov edi, 3
0x00001a3c      call sleep         ; sym.imp.sleep ; int sleep(int s)
0x00001a41      lea rsi, str.Well... ; 0x32c2
0x00001a48      mov edi, 1
0x00001a4d      mov eax, 0
0x00001a52      call __printf_chk  ; sym.imp.__printf_chk
0x00001a57      mov rdi, qword stdout ; 0x5660
0x00001a5e      call fflush        ; sym.imp.fflush ; int fflush(FILE *stream)
0x00001a63      mov edi, 1
0x00001a68      call sleep         ; sym.imp.sleep ; int sleep(int s)
0x00001a6d      lea rdi, str.OK._: ; 0x32ca
0x00001a74      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001a79      mov edi, 0x10
0x00001a7e      call exit          ; sym.imp.exit ; void exit(int status)
0x00001a83      endbr64
0x00001a87      push rax
0x00001a88      pop rax
0x00001a89      sub rsp, 8
0x00001a8d      mov rdx, rdi
0x00001a90      lea rsi, str.Invalid_phase_s ; 0x32d2
0x00001a97      mov edi, 1
0x00001a9c      mov eax, 0
0x00001aa1      call __printf_chk  ; sym.imp.__printf_chk
0x00001aa6      mov edi, 8
0x00001aab      call exit          ; sym.imp.exit ; void exit(int status)
```

```bash
❯ ./bomb             
Welcome to my fiendish little bomb. You have 6 phases with
which to blow yourself up. Have a nice day!
^CSo you think you can stop the bomb with ctrl-c, do you?
Well...OK. :-)
```

#### Reading inputs

Looking rapidly into `fcn.00001c56` (and functions called inside), we see `stdin`, `str.Error:_Input_line_too_long`,… so it looks like it reads user inputs. Given that it’s called repeatedly in `main`, we can safely assume it is the case.

It also keeps count of the number of answers we provide using `data.00005690`:

```asm
0x00001c6d      mov esi, dword data.00005690 ; 0x5690
...
0x00001ccb      add esi, 1
0x00001cce      mov dword data.00005690, esi ; 0x5690
```

Let’s simply rename it to `read_line` and go hunt for more interesting code.

#### Check completion

`fcn.00001d9e` is called after each phase

```asm
fcn.00001d9e ();
; var int var_78h @ stack - 0x78
; var int var_74h @ stack - 0x74
; var int64_t var_70h @ stack - 0x70
; var int64_t var_18h @ stack - 0x18
0x00001d9e      endbr64
0x00001da2      sub rsp, 0x78
0x00001da6      mov rax, qword fs:[0x28]
0x00001daf      mov qword [var_18h], rax
0x00001db4      xor eax, eax
0x00001db6      cmp dword data.00005690, 6 ; 0x5690
0x00001dbd      je 0x1dd4
0x00001dbf      mov rax, qword [var_18h]
0x00001dc4      xor rax, qword fs:[0x28]
0x00001dcd      jne 0x1e42
0x00001dcf      add rsp, 0x78
0x00001dd3      ret
0x00001dd4      lea rcx, [var_74h]
0x00001dd9      lea rdx, [var_78h]
0x00001dde      lea r8, [var_70h]
0x00001de3      lea rsi, str.d__d__s ; 0x3359 ; const char *format
0x00001dea      lea rdi, data.00005790 ; 0x5790 ; const char *s
0x00001df1      call __isoc99_sscanf ; sym.imp.__isoc99_sscanf ; int sscanf(const char *s, const char *format, va_list args)
0x00001df6      cmp eax, 3         ; expect 2 numbers and a string
0x00001df9      je 0x1e09
0x00001dfb      lea rdi, str.Congratulations__You_ve_defused_the_bomb ; 0x3298 ; const char *s
0x00001e02      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001e07      jmp 0x1dbf
0x00001e09      lea rdi, [var_70h] ; int64_t arg1
0x00001e0e      lea rsi, str.DrEvil ; 0x3362 ; int64_t arg2
0x00001e15      call strings_not_equal ; strings_not_equal
0x00001e1a      test eax, eax
0x00001e1c      jne 0x1dfb
0x00001e1e      lea rdi, str.Curses__you_ve_found_the_secret_phase ; 0x3238 ; const char *s
0x00001e25      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001e2a      lea rdi, str.But_finding_it_and_solving_it_are_quite_different... ; 0x3260 ; const char *s
0x00001e31      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001e36      mov eax, 0
0x00001e3b      call fcn.000019c4  ; fcn.000019c4
0x00001e40      jmp 0x1dfb
0x00001e42      call __stack_chk_fail ; sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
0x00001e47      endbr64
```

This function uses `data.00005690` that `read_line` uses to count the number of answers we provide and checks whether we’ve reached 7 before congratulating us with `“Congratulations! You've defused the bomb!”`. 

There are other intriguing bits such as:

```asm
0x00001dd4      lea rcx, [var_74h]
0x00001dd9      lea rdx, [var_78h]
0x00001dde      lea r8, [var_70h]
0x00001de3      lea rsi, str.d__d__s ; 0x3359 ; const char *format
0x00001dea      lea rdi, data.00005790 ; 0x5790 ; const char *s
0x00001df1      call __isoc99_sscanf ; sym.imp.__isoc99_sscanf ; int sscanf(const char *s, const char *format, va_list args)
0x00001df6      cmp eax, 3
...
0x00001e09      lea rdi, [var_70h] ; int64_t arg1
0x00001e0e      lea rsi, str.DrEvil ; 0x3362 ; int64_t arg2
0x00001e15      call strings_not_equal ; strings_not_equal
0x00001e1a      test eax, eax
0x00001e1c      jne 0x1dfb
0x00001e1e      lea rdi, str.Curses__you_ve_found_the_secret_phase ; 0x3238 ; const char *s
0x00001e25      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001e2a      lea rdi, str.But_finding_it_and_solving_it_are_quite_different... ; 0x3260 ; const char *s
0x00001e31      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001e36      mov eax, 0
0x00001e3b      call fcn.000019c4  ; fcn.000019c4
```

Let’s rename this function `check_completion` and leave the secret phase aside for the time being.

### Phase 1

```asm
fcn.000015a7 (int64_t arg1);
; arg int64_t arg1 @ rdi
0x000015a7      endbr64
0x000015ab      sub rsp, 8
0x000015af      lea rsi, str.I_am_just_a_renegade_hockey_mom. ; 0x3150 ; int64_t arg2
0x000015b6      call fcn.00001ad1  ; fcn.00001ad1
0x000015bb      test eax, eax
0x000015bd      jne 0x15c4
0x000015bf      add rsp, 8
0x000015c3      ret
0x000015c4      call fcn.00001be5  ; fcn.00001be5
0x000015c9      jmp 0x15bf         ; fcn.000015a7+0x18
```

This is “phase 1”, so let’s rename it to `phase_1`. I will also take this opportunity to rename the other “phase” functions.

We see a string and a `test` followed by a `jne` instruction, so `fcn.00001ad1` is likely a string comparison function. If `eax` is not 0, then we jump to `0x000015c4` to call `fcn.00001be5` which might be our detonation function.

And indeed, it is

```asm
fcn.000015a7 (int64_t arg1);
0x00001be5      endbr64
0x00001be9      push rax
0x00001bea      pop rax
0x00001beb      sub rsp, 8
0x00001bef      lea rdi, str.BOOM  ; 0x32e3 ; const char *s
0x00001bf6      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001bfb      lea rdi, str.The_bomb_has_blown_up. ; 0x32ec ; const char *s
0x00001c02      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001c07      mov edi, 8         ; int status
0x00001c0c      call exit          ; sym.imp.exit ; void exit(int status)
```

Let’s rename it to `detonate`.

Now, the logic dictates that, if `fcn.00001ad1` is really a string comparison function, it shall return 0 if the strings are equal, and 1 if they are not. Let’s confirm that:

```asm
fcn.00001ad1 (int64_t arg1, int64_t arg2);
; arg int64_t arg1 @ rdi
; arg int64_t arg2 @ rsi
0x00001ad1      endbr64
0x00001ad5      push r12
0x00001ad7      push rbp
0x00001ad8      push rbx
0x00001ad9      mov rbx, rdi       ; arg1
0x00001adc      mov rbp, rsi       ; arg2
0x00001adf      call fcn.00001ab0  ; fcn.00001ab0
0x00001ae4      mov r12d, eax
0x00001ae7      mov rdi, rbp       ; uint64_t arg1
0x00001aea      call fcn.00001ab0  ; fcn.00001ab0
0x00001aef      mov edx, eax
0x00001af1      mov eax, 1
0x00001af6      cmp r12d, edx
0x00001af9      jne 0x1b2c
0x00001afb      movzx edx, byte [rbx]
0x00001afe      test dl, dl
0x00001b00      je 0x1b20
0x00001b02      mov eax, 0
0x00001b07      cmp byte [rbp + rax], dl
0x00001b0b      jne 0x1b27
0x00001b0d      add rax, 1
0x00001b11      movzx edx, byte [rbx + rax]
0x00001b15      test dl, dl
0x00001b17      jne 0x1b07
0x00001b19      mov eax, 0
0x00001b1e      jmp 0x1b2c
0x00001b20      mov eax, 0
0x00001b25      jmp 0x1b2c
0x00001b27      mov eax, 1
0x00001b2c      pop rbx
0x00001b2d      pop rbp
0x00001b2e      pop r12
0x00001b30      ret
```

The function `fcn.00001ab0`:

```asm
fcn.00001ab0 (uint64_t arg1);
; arg uint64_t arg1 @ rdi
0x00001ab0      endbr64
0x00001ab4      cmp byte [rdi], 0  ; arg1
0x00001ab7      je 0x1acb
0x00001ab9      mov eax, 0
0x00001abe      add rdi, 1         ; arg1
0x00001ac2      add eax, 1
0x00001ac5      cmp byte [rdi], 0  ; arg1
0x00001ac8      jne 0x1abe
0x00001aca      ret
0x00001acb      mov eax, 0
0x00001ad0      ret
```

is called twice and computes the length of the input, so let’s rename to `length`.

After a quick analysis of `fcn.00001ad1`, we can confirm that it compares strings and indeed returns 0 if equal, and 1 if not, so let’s rename it:

```asm
strings_not_equal (int64_t arg1, int64_t arg2);
; arg int64_t arg1 @ rdi
; arg int64_t arg2 @ rsi
0x00001ad1      endbr64
0x00001ad5      push r12
0x00001ad7      push rbp
0x00001ad8      push rbx
0x00001ad9      mov rbx, rdi       ; arg1
0x00001adc      mov rbp, rsi       ; arg2
0x00001adf      call length        ; compute length of arg1
0x00001ae4      mov r12d, eax
0x00001ae7      mov rdi, rbp       ; uint64_t arg1
0x00001aea      call length        ; compute length of arg2
0x00001aef      mov edx, eax
0x00001af1      mov eax, 1
0x00001af6      cmp r12d, edx      ; compare lengths of arguments
0x00001af9      jne 0x1b2c         ; return 1 if length do not match
0x00001afb      movzx edx, byte [rbx]
0x00001afe      test dl, dl
0x00001b00      je 0x1b20          ; if arg1 is null byte, strings match, return 0
0x00001b02      mov eax, 0
0x00001b07      cmp byte [rbp + rax], dl ; compare strings byte after byte
0x00001b0b      jne 0x1b27
0x00001b0d      add rax, 1
0x00001b11      movzx edx, byte [rbx + rax]
0x00001b15      test dl, dl
0x00001b17      jne 0x1b07         ; loop as long as dl is not null byte
0x00001b19      mov eax, 0         ; return 0 if strings match
0x00001b1e      jmp 0x1b2c
0x00001b20      mov eax, 0
0x00001b25      jmp 0x1b2c
0x00001b27      mov eax, 1
0x00001b2c      pop rbx
0x00001b2d      pop rbp
0x00001b2e      pop r12
0x00001b30      ret
```

Now that we have understood all the functions in `phase_1` the code is crystal clear:

```asm
phase_1 (int64_t arg1);
; arg int64_t arg1 @ rdi
0x000015a7      endbr64
0x000015ab      sub rsp, 8
0x000015af      lea rsi, str.I_am_just_a_renegade_hockey_mom. ; 0x3150 ; int64_t arg2
0x000015b6      call strings_not_equal ; strings_not_equal
0x000015bb      test eax, eax      ; set ZF to 1 if eax == 0
0x000015bd      jne 0x15c4         ; jumps if ZF is not set
0x000015bf      add rsp, 8
0x000015c3      ret
0x000015c4      call detonate
0x000015c9      jmp 0x15bf         ; phase_1+0x18
```

The answer to pass phase 1 is the string that we saw running `strings`:

```asm
;-- str.I_am_just_a_renegade_hockey_mom.:
0x00003150          .string "I am just a renegade hockey mom." ; len=33
```

### Phase 2

```asm
phase_2 ();
; var int64_t var_24h @ stack - 0x24
; var int64_t var_20h @ stack - 0x20
0x000015cb      endbr64
0x000015cf      push rbp
0x000015d0      push rbx
0x000015d1      sub rsp, 0x28
0x000015d5      mov rax, qword fs:[0x28]
0x000015de      mov qword [var_20h], rax
0x000015e3      xor eax, eax
0x000015e5      mov rsi, rsp       ; int arg2
0x000015e8      call fcn.00001c11  ; fcn.00001c11
0x000015ed      cmp dword [rsp], 1
0x000015f1      jne 0x15fd
0x000015f3      mov rbx, rsp
0x000015f6      lea rbp, [var_24h]
0x000015fb      jmp 0x1612
0x000015fd      call detonate
0x00001602      jmp 0x15f3         ; phase_2+0x28
0x00001604      call detonate
0x00001609      add rbx, 4
0x0000160d      cmp rbx, rbp
0x00001610      je 0x161d
0x00001612      mov eax, dword [rbx]
0x00001614      add eax, eax
0x00001616      cmp dword [rbx + 4], eax
0x00001619      je 0x1609
0x0000161b      jmp 0x1604
0x0000161d      mov rax, qword [var_20h]
0x00001622      xor rax, qword fs:[0x28]
0x0000162b      jne 0x1634
0x0000162d      add rsp, 0x28
0x00001631      pop rbx
0x00001632      pop rbp
0x00001633      ret
0x00001634      call __stack_chk_fail ; sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
```

There is only one function we don’t know here: `fcn.00001c11`

```asm
fcn.00001c11 (const char *s, int arg2);
; arg const char *s @ rdi
; arg int arg2 @ rsi
0x00001c11      endbr64
0x00001c15      sub rsp, 8
0x00001c19      mov rdx, rsi       ; arg2 ; results of sscanf on the stack
0x00001c1c      lea rcx, [rsi + 4] ; arg2
0x00001c20      lea rax, [rsi + 0x14] ; arg2
0x00001c24      push rax
0x00001c25      lea rax, [rsi + 0x10] ; arg2
0x00001c29      push rax
0x00001c2a      lea r9, [rsi + 0xc] ; arg2
0x00001c2e      lea r8, [rsi + 8]  ; arg2
0x00001c32      lea rsi, str.d__d__d__d__d__d ; 0x3303 ; const char *format
0x00001c39      mov eax, 0
0x00001c3e      call __isoc99_sscanf ; sym.imp.__isoc99_sscanf ; int sscanf(const char *s, const char *format, va_list args)
0x00001c43      add rsp, 0x10
0x00001c47      cmp eax, 5
0x00001c4a      jle 0x1c51
0x00001c4c      add rsp, 8
0x00001c50      ret
0x00001c51      call detonate
```

```asm
;-- str.d__d__d__d__d__d:
0x00003303          .string "%d %d %d %d %d %d" ; len=18
```

`fcn.00001c11` reads the user input expecting 6 numbers, and calls `detonate` if provided with less. Let’s rename to `read_6_numbers` :

```asm
read_6_numbers (const char *s, int arg2);
; arg const char *s @ rdi
; arg int arg2 @ rsi
0x00001c11      endbr64
0x00001c15      sub rsp, 8
0x00001c19      mov rdx, rsi       ; arg2 ; results of sscanf on the stack
0x00001c1c      lea rcx, [rsi + 4] ; arg2
0x00001c20      lea rax, [rsi + 0x14] ; arg2
0x00001c24      push rax
0x00001c25      lea rax, [rsi + 0x10] ; arg2
0x00001c29      push rax
0x00001c2a      lea r9, [rsi + 0xc] ; arg2
0x00001c2e      lea r8, [rsi + 8]  ; arg2
0x00001c32      lea rsi, str.d__d__d__d__d__d ; 0x3303 ; const char *format
0x00001c39      mov eax, 0
0x00001c3e      call __isoc99_sscanf ; sym.imp.__isoc99_sscanf ; int sscanf(const char *s, const char *format, va_list args)
0x00001c43      add rsp, 0x10
0x00001c47      cmp eax, 5         ; expect at least 6 numbers
0x00001c4a      jle 0x1c51
0x00001c4c      add rsp, 8
0x00001c50      ret
0x00001c51      call detonate
```

Now, let’s analyse `phase_2` itself:

```asm
phase_2 ();
; var int64_t var_24h @ stack - 0x24
; var int64_t var_20h @ stack - 0x20
0x000015cb      endbr64
0x000015cf      push rbp
0x000015d0      push rbx
0x000015d1      sub rsp, 0x28
0x000015d5      mov rax, qword fs:[0x28]
0x000015de      mov qword [var_20h], rax
0x000015e3      xor eax, eax
0x000015e5      mov rsi, rsp       ; int arg2
0x000015e8      call read_6_numbers ; read_6_numbers
0x000015ed      cmp dword [rsp], 1 ; first number must be 1
0x000015f1      jne 0x15fd
0x000015f3      mov rbx, rsp
0x000015f6      lea rbp, [var_24h]
0x000015fb      jmp 0x1612
0x000015fd      call detonate
0x00001602      jmp 0x15f3         ; phase_2+0x28
0x00001604      call detonate
0x00001609      add rbx, 4         ; move to next number
0x0000160d      cmp rbx, rbp
0x00001610      je 0x161d
0x00001612      mov eax, dword [rbx]
0x00001614      add eax, eax       ; double value
0x00001616      cmp dword [rbx + 4], eax ; compare 2*current with next
0x00001619      je 0x1609
0x0000161b      jmp 0x1604
0x0000161d      mov rax, qword [var_20h]
0x00001622      xor rax, qword fs:[0x28]
0x0000162b      jne 0x1634
0x0000162d      add rsp, 0x28
0x00001631      pop rbx
0x00001632      pop rbp
0x00001633      ret
0x00001634      call __stack_chk_fail ; sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
```

Quick notes:
- on `0x000015ed`, we see that the first number must be equal to `1`.
- starting at `0x00001612`, we loop over the numbers and check that the next one is twice the current value.

Therefore, the solution to phase 2 is `1 2 4 8 16 32`.

### Phase 3

```asm
phase_3 (const char *s, uint64_t arg_ch);
; arg const char *s @ rdi
; var int64_t var_18h @ stack - 0x18
; var int64_t var_14h @ stack - 0x14
; var int64_t var_10h @ stack - 0x10
; arg uint64_t arg_ch @ stack + 0xc
0x00001639      endbr64
0x0000163d      sub rsp, 0x18
0x00001641      mov rax, qword fs:[0x28]
0x0000164a      mov qword [var_10h], rax
0x0000164f      xor eax, eax
0x00001651      lea rcx, [var_14h]
0x00001656      mov rdx, rsp       ; va_list args
0x00001659      lea rsi, data.0000330f ; 0x330f ; const char *format
0x00001660      call __isoc99_sscanf ; sym.imp.__isoc99_sscanf ; int sscanf(const char *s, const char *format, va_list args)
0x00001665      cmp eax, 1
0x00001668      jle 0x1688
0x0000166a      cmp dword [rsp], 7
0x0000166e      ja case.default.switch.0x00001685
0x00001674      mov eax, dword [rsp]
0x00001677      lea rdx, data.000031a0 ; 0x31a0
0x0000167e      movsxd rax, dword [rdx + rax*4]
0x00001682      add rax, rdx
;-- switch
0x00001685      jmp rax            ; switch table (8 cases) at 0x31a0
0x00001688      call detonate
...
```

```asm
;-- data.0000330f:
0x0000330f          .string "%d %d %d %d %d %d" ; len=18
```

Quick notes:
- we are dealing with a `switch` table
- on `0x00001665` , we see a `cmp eax, 1` instruction followed by a `jle` instruction, so we need to input at least 2 numbers, even though the format provided to `sscanf` is `"%d %d %d %d %d %d"`.
- if we input a number greater than `7`, we will jump to the default case, which detonates the bomb:

```asm
;-- default:                       ; from 0x1685
0x00001704      call detonate
```

Let’s have a look at the other cases:

```asm
;-- case 0:                        ; from 0x1685
0x0000168f      mov eax, data.00000274 ; 0x274
0x00001694      sub eax, data.0000024c ; 0x24c
0x00001699      add eax, data.000002b0 ; 0x2b0
0x0000169e      sub eax, 0x7e
0x000016a1      add eax, 0x7e
0x000016a4      sub eax, 0x7e
0x000016a7      add eax, 0x7e
0x000016aa      sub eax, 0x7e
0x000016ad      cmp dword [rsp], 5
0x000016b1      jg 0x16b9
0x000016b3      cmp dword [arg_ch], eax ; 
0x000016b7      je 0x16be
0x000016b9      call explode_bomb  ; sym.explode_bomb
0x000016be      mov rax, qword [var_10h]
0x000016c3      xor rax, qword fs:[0x28]
0x000016cc      jne 0x1710
0x000016ce      add rsp, 0x18
0x000016d2      ret
;-- case 1:                        ; from 0x1685
0x000016d3      mov eax, 0
0x000016d8      jmp 0x1694
;-- case 2:                        ; from 0x1685
0x000016da      mov eax, 0
0x000016df      jmp 0x1699
;-- case 3:                        ; from 0x1685
0x000016e1      mov eax, 0
0x000016e6      jmp 0x169e
;-- case 4:                        ; from 0x1685
0x000016e8      mov eax, 0
0x000016ed      jmp 0x16a1
;-- case 5:                        ; from 0x1685
0x000016ef      mov eax, 0
0x000016f4      jmp 0x16a4
;-- case 6:                        ; from 0x1685
0x000016f6      mov eax, 0
0x000016fb      jmp 0x16a7
;-- case 7:                        ; from 0x1685
0x000016fd      mov eax, 0
0x00001702      jmp 0x16aa
```

We need to pick the first number, so that adding values from the cases allows to pass `cmp dword [arg_ch], eax` where `[arg_ch]` is set with the second number.

The solution to phase 3 is therefore: `0 602` since `602 = 0x274 - 0x24c + 0x2b0 - 0x7e + 0x7e - 0x7e + 0x7e - 0x7e`.

### Phase 4

```asm
phase_4 (const char *s, uint64_t arg_ch);
; arg const char *s @ rdi
; var int64_t var_18h @ stack - 0x18
; var int64_t var_14h @ stack - 0x14
; var int64_t var_10h @ stack - 0x10
; arg uint64_t arg_ch @ stack + 0xc
0x0000174b      endbr64
0x0000174f      sub rsp, 0x18
0x00001753      mov rax, qword fs:[0x28]
0x0000175c      mov qword [var_10h], rax
0x00001761      xor eax, eax
0x00001763      lea rcx, [var_14h]
0x00001768      mov rdx, rsp       ; va_list args
0x0000176b      lea rsi, data.0000330f ; 0x330f ; const char *format
0x00001772      call __isoc99_sscanf ; sym.imp.__isoc99_sscanf ; int sscanf(const char *s, const char *format, va_list args)
0x00001777      cmp eax, 2
0x0000177a      jne 0x1782
0x0000177c      cmp dword [rsp], 0xe
0x00001780      jbe 0x1787
0x00001782      call detonate
0x00001787      mov edx, 0xe       ; int64_t arg3
0x0000178c      mov esi, 0         ; int64_t arg2
0x00001791      mov edi, dword [rsp] ; int64_t arg1
0x00001794      call fcn.00001715  ; fcn.00001715
0x00001799      cmp eax, 0xa
0x0000179c      jne 0x17a5
0x0000179e      cmp dword [arg_ch], 0xa
0x000017a3      je 0x17aa
0x000017a5      call detonate
0x000017aa      mov rax, qword [var_10h]
0x000017af      xor rax, qword fs:[0x28]
0x000017b8      jne 0x17bf
0x000017ba      add rsp, 0x18
0x000017be      ret
0x000017bf      call __stack_chk_fail ; sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
```

Quick notes:
- `0x00001777` - it expects 2 numbers
- `0x0000177c` - the first number must be ≤`0xe`
- `0x00001799` - the result of `fcn.00001715` must be `0xa`
- `0x0000179e` - the second number is `10`

The only unknown function is `fcn.00001715`

```asm
fcn.00001715 (int64_t arg1, int64_t arg2, int64_t arg3);
; arg int64_t arg1 @ rdi
; arg int64_t arg2 @ rsi
; arg int64_t arg3 @ rdx
0x00001715      endbr64
0x00001719      push rbx
0x0000171a      mov eax, edx       ; arg3
0x0000171c      sub eax, esi       ; arg2
0x0000171e      mov ebx, eax
0x00001720      shr ebx, 0x1f
0x00001723      add ebx, eax
0x00001725      sar ebx, 1
0x00001727      add ebx, esi       ; arg2
0x00001729      cmp ebx, edi       ; arg1
0x0000172b      jg 0x1733
0x0000172d      jl 0x173f
0x0000172f      mov eax, ebx
0x00001731      pop rbx
0x00001732      ret
0x00001733      lea edx, [rbx - 1]
0x00001736      call fcn.00001715
0x0000173b      add ebx, eax
0x0000173d      jmp 0x172f
0x0000173f      lea esi, [rbx + 1]
0x00001742      call fcn.00001715
0x00001747      add ebx, eax
0x00001749      jmp 0x172f
```

The function is recursive. Let’s write some C code to understand it better:

```c
int mysterious(int arg1, int arg2, int arg3) {
  int a = arg3;
  a -= arg2;
  int b = a;
  b = b >> 0x1f;
  b += a;
  b /= 2;
  b += arg2;
  if (b > arg1) {
    int c = mysterious(arg1, arg2, b - 1);
    b += c;
  } else if (b < arg1) {
    int c = mysterious(arg1, b + 1, arg3);
    b += c;
  }
  return b;
}
```

Since we know it must yield `0xa`, we can simply use this C function and find the right input: `3`.

The answer to phase 4 is then: `3 10`.

### Phase 5

```asm
phase_5 (const char *s);
; arg const char *s @ rdi
; var int64_t var_18h @ stack - 0x18
; var uint64_t var_14h @ stack - 0x14
; var int64_t var_10h @ stack - 0x10
0x000017c4      endbr64
0x000017c8      sub rsp, 0x18
0x000017cc      mov rax, qword fs:[0x28]
0x000017d5      mov qword [var_10h], rax
0x000017da      xor eax, eax
0x000017dc      lea rcx, [var_14h]
0x000017e1      mov rdx, rsp       ; va_list args
0x000017e4      lea rsi, data.0000330f ; 0x330f ; const char *format
0x000017eb      call __isoc99_sscanf ; sym.imp.__isoc99_sscanf ; int sscanf(const char *s, const char *format, va_list args)
0x000017f0      cmp eax, 1
0x000017f3      jle 0x184f
0x000017f5      mov eax, dword [rsp]
0x000017f8      and eax, 0xf
0x000017fb      mov dword [rsp], eax
0x000017fe      cmp eax, 0xf
0x00001801      je 0x1835
0x00001803      mov ecx, 0
0x00001808      mov edx, 0
0x0000180d      lea rsi, data.000031c0 ; 0x31c0
0x00001814      add edx, 1
0x00001817      cdqe
0x00001819      mov eax, dword [rsi + rax*4]
0x0000181c      add ecx, eax
0x0000181e      cmp eax, 0xf
0x00001821      jne 0x1814
0x00001823      mov dword [rsp], 0xf
0x0000182a      cmp edx, 0xf
0x0000182d      jne 0x1835
0x0000182f      cmp dword [var_14h], ecx
0x00001833      je 0x183a
0x00001835      call detonate
0x0000183a      mov rax, qword [var_10h]
0x0000183f      xor rax, qword fs:[0x28]
0x00001848      jne 0x1856
0x0000184a      add rsp, 0x18
0x0000184e      ret
0x0000184f      call detonate
0x00001854      jmp 0x17f5         ; phase_5+0x31
0x00001856      call __stack_chk_fail ; sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
```

Quick notes:
- `0x000017f0` - it expects at least two numbers
- `0x000017f5` to `0x00001801` - first argument least significant nibble must be less than `0xf`
- `data.000031c0` is an array of numbers:

```plain
0xa, 0x2, 0xe, 0x7, 0x8, 0xc, 0xf, 0xb, 0x0, 0x4, 0x1, 0xd, 0x3, 0x9, 0x6, 0x5
  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15
```

Now, let’s look at the loop and the subsequent check:

```asm
0x000017f5      mov eax, dword [rsp]
...
0x00001803      mov ecx, 0
0x00001808      mov edx, 0
0x0000180d      lea rsi, data.000031c0 ; 0x31c0
0x00001814      add edx, 1
0x00001817      cdqe
0x00001819      mov eax, dword [rsi + rax*4]
0x0000181c      add ecx, eax
0x0000181e      cmp eax, 0xf
0x00001821      jne 0x1814
0x00001823      mov dword [rsp], 0xf
0x0000182a      cmp edx, 0xf
0x0000182d      jne 0x1835
0x0000182f      cmp dword [var_14h], ecx
0x00001833      je 0x183a
0x00001835      call detonate
```

Here, we loop over the array, using `rax` as index, which is then set to the value found in the array.

`ecx` is used to compute the sum of elements we looped through, and the loops stops when we hit the value `0xf`. The sum must then match our second argument (see `0x0000182f`).

On `0x0000182a`, we compare `edx`, which started at `0x1`, to be equal to `0xf`.

If start from the target end value, `0xf` at index 6, and only allow to loop `15 - 1` times we have the following sequence:

```c
0xf <- 0x6 <- 0xe <- 0x2 <- 0x1 <- 0xa <- 0x8 <- 0x4 
<- 0x9 <- 0xd <- 0xb <- 0x7 <- 0x3 <- 0xc <- (0x5)
```

Therefore, the first index should be `5` and the sum is:

```python
>>> 0xf + 0x6 + 0xe + 0x2 + 0x1 + 0xa + 0x8 + 0x4 + 0x9 + 0xd + 0xb + 0x7 + 0x3 + 0xc 
115
```

Phase 5 expects the answer: `5 115`.

## Phase 6

```asm
phase_6 ();
; var int64_t var_88h @ stack - 0x88
; var int64_t var_68h @ stack - 0x68
; var int64_t var_60h @ stack - 0x60
; var int64_t var_58h @ stack - 0x58
; var int64_t var_50h @ stack - 0x50
; var int64_t var_48h @ stack - 0x48
; var int64_t var_40h @ stack - 0x40
; var int64_t var_30h @ stack - 0x30
0x0000185b      endbr64
0x0000185f      push r14
0x00001861      push r13
0x00001863      push r12
0x00001865      push rbp
0x00001866      push rbx
0x00001867      sub rsp, 0x60
0x0000186b      mov rax, qword fs:[0x28]
0x00001874      mov qword [var_30h], rax
0x00001879      xor eax, eax
0x0000187b      mov r13, rsp
0x0000187e      mov rsi, r13       ; int arg2
0x00001881      call read_6_numbers
0x00001886      mov r14d, 1
0x0000188c      mov r12, rsp
0x0000188f      jmp 0x18b9
0x00001891      call detonate
0x00001896      jmp 0x18c8         ; phase_6+0x6d
0x00001898      add rbx, 1
0x0000189c      cmp ebx, 5         ; loop through next numbers
0x0000189f      jg 0x18b1
0x000018a1      mov eax, dword [r12 + rbx*4]
0x000018a5      cmp dword [rbp], eax
0x000018a8      jne 0x1898
0x000018aa      call detonate
0x000018af      jmp 0x1898         ; phase_6+0x3d
0x000018b1      add r14, 1
0x000018b5      add r13, 4
0x000018b9      mov rbp, r13
0x000018bc      mov eax, dword [r13]
0x000018c0      sub eax, 1
0x000018c3      cmp eax, 5        
0x000018c6      ja 0x1891
0x000018c8      cmp r14d, 5
0x000018cc      jg 0x18d3
0x000018ce      mov rbx, r14
0x000018d1      jmp 0x18a1
0x000018d3      mov esi, 0
0x000018d8      mov ecx, dword [rsp + rsi*4]
0x000018db      mov eax, 1
0x000018e0      lea rdx, data.00005200 ; 0x5200
0x000018e7      cmp ecx, 1
0x000018ea      jle 0x18f7
0x000018ec      mov rdx, qword [rdx + 8]
0x000018f0      add eax, 1
0x000018f3      cmp eax, ecx
0x000018f5      jne 0x18ec
0x000018f7      mov qword [rsp + rsi*8 + 0x20], rdx
0x000018fc      add rsi, 1
0x00001900      cmp rsi, 6
0x00001904      jne 0x18d8
0x00001906      mov rbx, qword [var_68h]
0x0000190b      mov rax, qword [var_60h]
0x00001910      mov qword [rbx + 8], rax
0x00001914      mov rdx, qword [var_58h]
0x00001919      mov qword [rax + 8], rdx
0x0000191d      mov rax, qword [var_50h]
0x00001922      mov qword [rdx + 8], rax
0x00001926      mov rdx, qword [var_48h]
0x0000192b      mov qword [rax + 8], rdx
0x0000192f      mov rax, qword [var_40h]
0x00001934      mov qword [rdx + 8], rax
0x00001938      mov qword [rax + 8], 0
0x00001940      mov ebp, 5
0x00001945      jmp 0x1950
0x00001947      mov rbx, qword [rbx + 8]
0x0000194b      sub ebp, 1
0x0000194e      je 0x1961
0x00001950      mov rax, qword [rbx + 8]
0x00001954      mov eax, dword [rax]
0x00001956      cmp dword [rbx], eax
0x00001958      jge 0x1947
0x0000195a      call detonate
0x0000195f      jmp 0x1947         ; phase_6+0xec
0x00001961      mov rax, qword [var_30h]
0x00001966      xor rax, qword fs:[0x28]
0x0000196f      jne 0x197e
0x00001971      add rsp, 0x60
0x00001975      pop rbx
0x00001976      pop rbp
0x00001977      pop r12
0x00001979      pop r13
0x0000197b      pop r14
0x0000197d      ret
0x0000197e      call __stack_chk_fail ; sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
```

There is a call to `read_6_numbers` followed by an unconditional `jmp` where it checks that the first number is less than or equal to 6:

```asm
0x0000187b      mov r13, rsp
0x0000187e      mov rsi, r13       ; int arg2
0x00001881      call read_6_numbers ; read_6_numbers
0x00001886      mov r14d, 1
0x0000188c      mov r12, rsp
0x0000188f      jmp 0x18b9
...
0x000018b9      mov rbp, r13
0x000018bc      mov eax, dword [r13]
0x000018c0      sub eax, 1
0x000018c3      cmp eax, 5        
0x000018c6      ja 0x1891
```

It then loops through the rest of the numbers and checks that the same value can’t be found, i.e. ensuring that it’s unique:

```asm
0x00001898      add rbx, 1
0x0000189c      cmp ebx, 5        
0x0000189f      jg 0x18b1
0x000018a1      mov eax, dword [r12 + rbx*4]
0x000018a5      cmp dword [rbp], eax
0x000018a8      jne 0x1898
0x000018aa      call detonate
```

and then moves to the next number:

```asm
0x000018b1      add r14, 1
0x000018b5      add r13, 4
```

It then loops over an array, using the 6 numbers like “indices”:

```asm
0x000018d3      mov esi, 0
0x000018d8      mov ecx, dword [rsp + rsi*4]
0x000018db      mov eax, 1
0x000018e0      lea rdx, data.00005200 ; 0x5200
0x000018e7      cmp ecx, 1
0x000018ea      jle 0x18f7
0x000018ec      mov rdx, qword [rdx + 8]
0x000018f0      add eax, 1
0x000018f3      cmp eax, ecx
0x000018f5      jne 0x18ec
0x000018f7      mov qword [rsp + rsi*8 + 0x20], rdx
0x000018fc      add rsi, 1
0x00001900      cmp rsi, 6
0x00001904      jne 0x18d8
```

The data at `data.00005200` can be seen as follows:

```asm
0x00005110      .dword 0x00000200
0x00005114      .dword 0x00000006
0x00005118      .qword 0x0000000000000000

...

0x00005200      .dword 0x00000212
0x00005204      .dword 0x00000001
0x00005208      .qword 0x0000000000005210 

0x00005210      .dword 0x000001c2
0x00005214      .dword 0x00000002
0x00005218      .qword 0x0000000000005220 

0x00005220      .dword 0x00000215
0x00005224      .dword 0x00000003
0x00005228      .qword 0x0000000000005230 

0x00005230      .dword 0x00000393
0x00005234      .dword 0x00000004
0x00005238      .qword 0x0000000000005240 

0x00005240      .dword 0x000003a7
0x00005244      .dword 0x00000005
0x00005248      .qword 0x0000000000005110
```

This looks like a linked list! The code is actually traversing it to push the addresses on the stack, following the order provided by the input numbers.

Then, we compare values and expect to find them in decreasing order:

```asm
0x00001940      mov ebp, 5
0x00001945      jmp 0x1950
0x00001947      mov rbx, qword [rbx + 8]
0x0000194b      sub ebp, 1
0x0000194e      je 0x1961
0x00001950      mov rax, qword [rbx + 8]
0x00001954      mov eax, dword [rax]
0x00001956      cmp dword [rbx], eax
0x00001958      jge 0x1947
0x0000195a      call detonate1
```

Since the addresses are pushed on the stack via `mov qword [rsp + rsi*8 + 0x20], rdx`, we need to input `5 4 3 1 6 2` to defuse phase 6.

### Secret stage

Let’s come back to the mysterious pieces we noticed in `check_completion`.

```asm
0x00001dd4      lea rcx, [var_74h]
0x00001dd9      lea rdx, [var_78h]
0x00001dde      lea r8, [var_70h]
0x00001de3      lea rsi, str.d__d__s ; 0x3359 ; const char *format
0x00001dea      lea rdi, data.00005790 ; 0x5790 ; const char *s
0x00001df1      call __isoc99_sscanf ; sym.imp.__isoc99_sscanf ; int sscanf(const char *s, const char *format, va_list args)
0x00001df6      cmp eax, 3
...
0x00001e09      lea rdi, [var_70h] ; int64_t arg1
0x00001e0e      lea rsi, str.DrEvil ; 0x3362 ; int64_t arg2
0x00001e15      call strings_not_equal ; strings_not_equal
0x00001e1a      test eax, eax
0x00001e1c      jne 0x1dfb
0x00001e1e      lea rdi, str.Curses__you_ve_found_the_secret_phase ; 0x3238 ; const char *s
0x00001e25      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001e2a      lea rdi, str.But_finding_it_and_solving_it_are_quite_different... ; 0x3260 ; const char *s
0x00001e31      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001e36      mov eax, 0
0x00001e3b      call fcn.000019c4  ; fcn.000019c4
```

The function `fcn.000019c4` mentions a “secret stage”:

```asm
fcn.000019c4 ();
...
0x00001a00      lea rdi, str.Wow__You_ve_defused_the_secret_stage ; 0x3178 ; const char *s
0x00001a07      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001a0c      call check_completion ; check_completion
...
```

#### Entering the secret stage

In order to enter the secret stage, we need to feed two numbers and the string `DrEvil` in `data.00005790`.

I couldn't find cross references to this specific location though.

Let’s come back to `read_line`, in particular on the first function it calls:

```asm
read_line ();
0x00001c56      endbr64
0x00001c5a      sub rsp, 8
0x00001c5e      mov eax, 0
0x00001c63      call fcn.00001b93  ; fcn.00001b93
0x00001c68      test rax, rax
...
```

```asm
fcn.00001b93 ();
0x00001b93      endbr64
0x00001b97      push rbp
0x00001b98      push rbx
0x00001b99      sub rsp, 8
0x00001b9d      lea rbp, data.000056a0 ; 0x56a0
0x00001ba4      movsxd rax, dword data.00005690 ; 0x5690
0x00001bab      lea rdi, [rax + rax*4]
0x00001baf      shl rdi, 4
0x00001bb3      add rdi, rbp       ; char *s
0x00001bb6      mov rdx, qword data.00005698 ; 0x5698 ; FILE *stream
0x00001bbd      mov esi, 0x50      ; 'P' ; int size
0x00001bc2      call fgets         ; sym.imp.fgets ; char *fgets(char *s, int size, FILE *stream)
...
```

A quick calculation shows that `0x5790 = 0x56a0 + 0x50 * 3`. Which means that we can get in by squeezing the string `DrEvil` as a third input of phase 4:

```bash
❯ cat ans.txt    
I am just a renegade hockey mom.
1 2 4 8 16 32
0 602
3 10 DrEvil
5 115
5 4 3 1 6 2

❯ ./bomb /tmp/ans.txt 
Welcome to my fiendish little bomb. You have 6 phases with
which to blow yourself up. Have a nice day!
Phase 1 defused. How about the next one?
That's number 2.  Keep going!
Halfway there!
So you got that one.  Try this one.
Good work!  On to the next...
Curses, you've found the secret phase!
But finding it and solving it are quite different...
```

#### Solving the secret stage

```asm
secret_stage ();
0x000019c4      endbr64
0x000019c8      push rbx
0x000019c9      call read_line     ; read_line
0x000019ce      mov rdi, rax       ; const char *str
0x000019d1      mov edx, 0xa       ; int base
0x000019d6      mov esi, 0         ; char **endptr
0x000019db      call strtol        ; sym.imp.strtol ; long strtol(const char *str, char **endptr, int base)
0x000019e0      mov rbx, rax
0x000019e3      lea eax, [rax - 1]
0x000019e6      cmp eax, data.000003e8 ; 0x3e8
0x000019eb      ja 0x1a13
0x000019ed      mov esi, ebx       ; int64_t arg2
0x000019ef      lea rdi, data.00005120 ; 0x5120 ; int64_t arg1
0x000019f6      call fcn.00001983  ; fcn.00001983
0x000019fb      cmp eax, 5
0x000019fe      jne 0x1a1a
0x00001a00      lea rdi, str.Wow__You_ve_defused_the_secret_stage ; 0x3178 ; const char *s
0x00001a07      call puts          ; sym.imp.puts ; int puts(const char *s)
0x00001a0c      call check_completion ; check_completion
0x00001a11      pop rbx
0x00001a12      ret
0x00001a13      call detonate
0x00001a18      jmp 0x19ed         ; secret_stage+0x29
0x00001a1a      call detonate
0x00001a1f      jmp 0x1a00         ; secret_stage+0x3c
```

To defuse this one, we need `fcn.00001983` to return `0x5`.

```asm
fcn.00001983 (int64_t arg1, int64_t arg2);
; arg int64_t arg1 @ rdi
; arg int64_t arg2 @ rsi
0x00001983      endbr64
0x00001987      test rdi, rdi      ; arg1
0x0000198a      je 0x19be
0x0000198c      sub rsp, 8
0x00001990      mov edx, dword [rdi] ; arg1
0x00001992      cmp edx, esi       ; arg2
0x00001994      jg 0x19a2
0x00001996      mov eax, 0
0x0000199b      jne 0x19af
0x0000199d      add rsp, 8
0x000019a1      ret
0x000019a2      mov rdi, qword [rdi + 8] ; int64_t arg1
0x000019a6      call fcn.00001983
0x000019ab      add eax, eax
0x000019ad      jmp 0x199d
0x000019af      mov rdi, qword [rdi + 0x10] ; int64_t arg1
0x000019b3      call fcn.00001983
0x000019b8      lea eax, [rax + rax + 1]
0x000019bc      jmp 0x199d
0x000019be      mov eax, 0xffffffff ; -1
0x000019c3      ret
```

It’s a recursive function, like in phase 4, so let’s write some C code again:

```c
int mysterious(int arg1, int arg2) {
	if (arg1 == 0) {
    return -1;
  }
  if (arg1 < arg2) {
    return 2 * mysterious(*(arg1 + 0x10), arg2) + 1; // right
  }
  if (arg1 > arg2) {
    return 2 * mysterious(*(arg1 + 0x8), arg2); // left
  }
  return 0; // match
}
```

The second argument is our input whilst the first argument is given by `lea rdi, data.00005120` and points to some data. Given the function above, one can expect the data to be a bunch of nodes with:

- a value
- an address (`arg1 + 0x8`)
- another address (`arg1 + 0x10`)

which sounds like a binary tree. Reshaping the data as such, we have:

```asm
0x00005030      .qword 0x0000000000000001
0x00005038      .qword 0x0000000000000000
0x00005040      .qword 0x0000000000000000
...
0x00005050      .qword 0x0000000000000063
0x00005058      .qword 0x0000000000000000
0x00005060      .qword 0x0000000000000000
...
0x00005070      .qword 0x0000000000000023
0x00005078      .qword 0x0000000000000000
0x00005080      .qword 0x0000000000000000
...
0x00005090      .qword 0x0000000000000007
0x00005098      .qword 0x0000000000000000
0x000050a0      .qword 0x0000000000000000
...
0x000050b0      .qword 0x0000000000000014
0x000050b8      .qword 0x0000000000000000
0x000050c0      .qword 0x0000000000000000
...
0x000050d0      .qword 0x000000000000002f
0x000050d8      .qword 0x0000000000000000
0x000050e0      .qword 0x0000000000000000
...
0x000050f0      .qword 0x00000000000003e9
0x000050f8      .qword 0x0000000000000000
0x00005100      .qword 0x0000000000000000
...
;-- data.00005120:
0x00005120      .qword 0x0000000000000024
0x00005128      .qword 0x0000000000005140 
0x00005130      .qword 0x0000000000005160
...
0x00005140      .qword 0x0000000000000008
0x00005148      .qword 0x00000000000051c0
0x00005150      .qword 0x0000000000005180 
...
0x00005160      .qword 0x0000000000000032
0x00005168      .qword 0x00000000000051a0 
0x00005170      .qword 0x00000000000051e0
...
0x00005180      .qword 0x0000000000000016
0x00005188      .qword 0x00000000000050b0 
0x00005190      .qword 0x0000000000005070
...
0x000051a0      .qword 0x000000000000002d
0x000051a8      .qword 0x0000000000005010 
0x000051b0      .qword 0x00000000000050d0
...
0x000051c0      .qword 0x0000000000000006
0x000051c8      .qword 0x0000000000005030
0x000051d0      .qword 0x0000000000005090
...
0x000051e0      .qword 0x000000000000006b
0x000051e8      .qword 0x0000000000005050 
0x000051f0      .qword 0x00000000000050f0
```

Since we need to reach `0x5 = 2 * (2 * (2 * (0) + 1)) + 1`, we must go right, left, and right, crossing the values: 24 → 32 → 45 → 47.

```bash
But finding it and solving it are quite different...
47
Wow! You've defused the secret stage!
Congratulations! You've defused the bomb!
```

## Conclusion

I had a great time working through this lab!

The first 3 phases were quite straightforward, whilst the difficulty increased in the remaining phases. The hardest one was unequivocally phase 6 where I deeply missed `gdb/gef`! I was quite happy to finally solve it only using static analysis though.

I would definitely recommend this exercise to beginners willing to practice reverse engineering!
