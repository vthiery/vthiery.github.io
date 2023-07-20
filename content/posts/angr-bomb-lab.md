---
layout: post
title: Solving the "Bomb Lab" with Angr
date: 2023-07-20
tags:
  - symbolic-analysis
  - angr
  - reverse-engineering
  - assembly
  - x86-64
  - write-up
---

## Context

I recently completed [Reverse Engineering 3201: Symbolic Analysis](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+RE3201_symexec+2021_V1/course/) from [OpenSecurityTraining2](https://p.ost2.fyi/courses/) and, like ["Architecture 1001: x86-64 Assembly"](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Arch1001_x86-64_Asm+2021_v1/course/), the final assignment consists in solving the ["Bomb Lab"](https://gitlab.com/opensecuritytraining/arch1001_x86-64_asm_code_for_class), but using [angr](https://angr.io/) this time. 

Since I already reversed the binary in my [last post](https://vthiery.github.io/posts/2023/07/reverse-engineering-the-bomb-lab-with-cutter/), this post will be much lighter and jump straight into Python code.

The version of `angr` used here is [9.2.59](https://github.com/angr/angr/releases/tag/v9.2.59). 

The resolution script is available on my [Gist](https://gist.github.com/vthiery/34db0ab49ca9c3b9b65ba9b80fd56a00). 

## Resolution 

- [Setup](#setup)
- [Phase 1](#phase-1)
- [Phase 2](#phase-2)
- [Phase 3](#phase-3)
- [Phase 4](#phase-4)
- [Phase 5](#phase-5)
- [Phase 6](#phase-6)
- [Secret phase](#secret-phase)

### Setup

First, let's setup the angr project and define `bomb_addr` that will be used as an `avoid` condition when calling `explore()`.

```python
import angr
import claripy
import logging


logging.getLogger("angr").setLevel("ERROR")

# Common setup
p = angr.Project("bomb", load_options={"auto_load_libs": False})

base_addr = p.loader.min_addr
functions = p.analyses.CFG().kb.functions
bomb_addr = functions.function(name="explode_bomb").addr
```

### Phase 1

This phase is pretty simple and we simply need to allow for enough space when defining the bitvector symbol:

```python
def solve_phase_1():
    phase_addr = functions.function(name="phase_1").addr
    state = p.factory.blank_state(addr=phase_addr)

    flag = claripy.BVS("flag", 8 * 50)  # should be enough
    state.memory.store(state.regs.rdi, flag)

    sim = p.factory.simgr(state)
    target_addr = base_addr + 0x000015C3  # target ret
    sim.explore(find=target_addr, avoid=bomb_addr)

    if sim.found:
        f = sim.found[0]
        s = str(
            f.solver.eval(flag, cast_to=bytes)[:32], "UTF-8"
        )  # a posteriori pretty print
        print(f'Flag 1: "{s}"')
    else:
        print("Failed to solve phase 1")
        raise SystemExit(1)
```

calling `solve_phase_1` eventually gives us the flag (you may have to wait for 30 to 40 seconds):

```sh
❯ python3 bomb.py 
Flag 1: "I am just a renegade hockey mom."
```

### Phase 2

In phase 2, there is a call to `read_six_numbers` that we need to hook:

```python
class hook_read_six_numbers(angr.SimProcedure):
    numbers = [None] * 6

    def run(self, str_addr, int_addr):
        numbers = []
        for i in range(6):
            bvs = self.state.solver.BVS(f"flag_{i}", 32)
            self.numbers[i] = bvs
            self.state.mem[int_addr].int.array(6)[i] = bvs

        return 2


# Hook `read_six_numbers` globally
p.hook(functions.function(name="read_six_numbers").addr, hook_read_six_numbers())
```

The rest of the code is straightforward and will quickly find the flag:

```python
def solve_phase_2():
    phase_addr = functions.function(name="phase_2").addr
    state = p.factory.blank_state(addr=phase_addr)

    sim = p.factory.simgr(state)
    target_addr = base_addr + 0x00001633  # target ret
    sim.explore(find=target_addr, avoid=bomb_addr)

    if sim.found:
        f = sim.found[0]
        print(
            f'Flag 2: "{" ".join([str(f.solver.eval(i)) for i in hook_read_six_numbers.numbers])}"'
        )
    else:
        print("Failed to solve phase 2")
        raise SystemExit(1)
```

```sh
❯ python3 bomb.py 
Flag 2: "1 2 4 8 16 32"
```

### Phase 3

In phase 3, we have a call to `sscanf` that we must skip. The symbolic variable must be pushed onto the stack and we must therefore stop before the function epilogue where the stack is restored.

```python
def solve_phase_3():
    phase_addr = base_addr + 0x00001665  # after sscanf
    state = p.factory.blank_state(addr=phase_addr)
    state.stack_push(claripy.BVS("flag", 64))

    sim = p.factory.simgr(state)
    target_addr = base_addr + 0x000016CC  # before stack restoration
    sim.explore(find=target_addr, avoid=bomb_addr)

    if sim.found:
        f = sim.found[0]
        flag = f.solver.eval(f.stack_pop())
        mask = 0xFFFFFFFF
        print(f'Flag 3: "{str(flag & mask)} {str(flag >> 32 & mask)}"')
    else:
        print("Failed to solve phase 3")
        raise SystemExit(1)
```

```sh
❯ python3 bomb.py
Flag 3: "0 602"
```

### Phase 4

Phase 4 can be solved just like phase 3:

```python
def solve_phase_4():
    phase_addr = base_addr + 0x00001777  # after sscanf
    state = p.factory.blank_state(addr=phase_addr)
    state.stack_push(claripy.BVS("flag", 64))

    sim = p.factory.simgr(state)
    target_addr = base_addr + 0x000017BA  # before stack restoration
    sim.explore(find=target_addr, avoid=bomb_addr)

    if sim.found:
        f = sim.found[0]
        flag = f.solver.eval(f.stack_pop())
        mask = 0xFFFFFFFF
        print(f'Flag 4: "{str(flag & mask)} {str(flag >> 32 & mask)}"')
    else:
        print("Failed to solve phase 4")
        raise SystemExit(1)
```

```sh
❯ python3 bomb.py
Flag 4: "3 10"
```

### Phase 5

  Solving phase 5 is similar to phase 3 and 4, except for the fact that the stack is modified with `mov dword [rsp], 0xf`. As a result, the value popped from the stack will be `15 115` instead of the expected `5 115`.

```python
def solve_phase_5():
    phase_addr = base_addr + 0x000017F0  # after sscanf
    state = p.factory.blank_state(addr=phase_addr)
    state.stack_push(claripy.BVS("flag", 64))

    sim = p.factory.simgr(state)
    target_addr = base_addr + 0x00001848  # before stack restoration
    sim.explore(find=target_addr, avoid=bomb_addr)

    if sim.found:
        f = sim.found[0]
        flag = f.solver.eval(
            f.stack_pop()
        )  # Result is 15 115 and not 5 115 because of mov dword [rsp], 0xf
        mask = 0xFFFFFFFF
        print(f'Flag 5: "5 {str(flag >> 32 & mask)}"')
    else:
        print("Failed to solve phase 5")
        raise SystemExit(1)
```

```sh
❯ python3 bomb.py
Flag 5: "5 115"
```

### Phase 6

Phase 6 can be solved just like phase 2:

```python
def solve_phase_6():
    phase_addr = functions.function(name="phase_6").addr
    state = p.factory.blank_state(addr=phase_addr)

    sim = p.factory.simgr(state)
    target_addr = base_addr + 0x0000197D  # target ret
    sim.explore(find=target_addr, avoid=bomb_addr)

    if sim.found:
        f = sim.found[0]
        print(
            f'Flag 6: "{" ".join([str(f.solver.eval(i)) for i in hook_read_six_numbers.numbers])}"'
        )
    else:
        print("Failed to solve phase 6")
        raise SystemExit(1)
```

Note: thos one will take quite some time to return the flag.

```sh
❯ python3 bomb.py
Flag 6: "5 4 3 1 6 2"
```

### Secret phase

To solve the secret phase, we have a call to `read_line` and `strtol` that we want to skip. Then, setting up the `rax` register to our symbol value:

```python
def solve_phase_S():
    phase_addr = base_addr + 0x000019e0 # after strtol
    state = p.factory.blank_state(addr=phase_addr)

    flag = claripy.BVS("flag", 64)
    state.regs.rax = flag

    sim = p.factory.simgr(state)
    target_addr = base_addr + 0x00001a12 # target ret
    sim.explore(find=target_addr, avoid=bomb_addr)

    if sim.found:
        f = sim.found[0]
        print(f'Flag S: "{f.solver.eval(flag, cast_to=int)}"')
    else:
        print('Failed to solve secret phase')
        raise SystemExit(1)
```

```sh
❯ python3 bomb.py
Flag S: "47"
```

## Conclusion

Solving this lab again was a nice way to play a little bit with `angr` and practice what I learnt in the course.

The resolution was a tad repetitive but I imagine there are more sophisticated and smarter ways to solve these challenges.
