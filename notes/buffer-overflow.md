### Buffer overlow notes

```console
$ make arr-over
$ lldb -- ./arr-over bbbbbbbbbbbbbbbbbb
$ br s -n main
$ r
```
Lets inspect the stack pointer before the call to strcpy:
```console
(lldb) register read rbp
     rbp = 0x00000000004011a0  arr-over`__libc_csu_init
```
So that looks what we would expect, the in `rbp` was pushed onto the stack by
the call instruction and then stored in rbp as part of the function prologue.

Now, lets first take a look at the stack:
```console
(lldb) disassemble 
arr-over`main:
    0x401126 <+0>:  push   rbp
    0x401127 <+1>:  mov    rbp, rsp
    0x40112a <+4>:  sub    rsp, 0x20
    0x40112e <+8>:  mov    dword ptr [rbp - 0x14], edi
    0x401131 <+11>: mov    qword ptr [rbp - 0x20], rsi
->  0x401135 <+15>: mov    rax, qword ptr [rbp - 0x20]
    0x401139 <+19>: add    rax, 0x8
    0x40113d <+23>: mov    rdx, qword ptr [rax]
    0x401140 <+26>: lea    rax, [rbp - 0xa]
    0x401144 <+30>: mov    rsi, rdx
    0x401147 <+33>: mov    rdi, rax
    0x40114a <+36>: call   0x401030                  ; symbol stub for: strcpy
    0x40114f <+41>: mov    eax, 0x0
    0x401154 <+46>: leave  
    0x401155 <+47>: ret    
```
After the frame prologue, space is allocated on the stack by subtracting
32 (hex 20) from the stack pointer.

To display the current stack we have to take into account that the stack growns
downwards in memory, which can been seen above with `sub rsp, 0x20` which is
subtracting 32 from rsp. But the base pointer still points to the stack
position upon entry so we can use it and then printing 32 bytes:

```console
(lldb) memory read -c 9 -f x -s 4 '$rbp - 0x20'
0x7fffffffd0d0: 0xffffd1d8 0x00007fff 0x00401040 0x00000002
0x7fffffffd0e0: 0xffffd1d0 0x00007fff 0x00000000 0x00000000
0x7fffffffd0f0: 0x00401160
```
I'm using 9 as the count so that rbp itself is also displayed so this is
showing 36 bytes of memory.

So if we look at these values closer we can find:
```
  rbp-0x20      argv/[rbp-32]                                  argc/[rbp-20]
                0x7fffffffd0d0  0x7fffffffd0d4 0x7fffffffd0d8  0x00007fffffffd0dc
      ↓            ↓               ↓               ↓                ↓
0x7fffffffd0d0:  0xffffd1d8     0x00007fff     0x00401040      0x00000002
0x7fffffffd0e0:  0xffffd1d0     0x00007fff     0x00000000      0x00000000
0x7fffffffd0f0:  0x00401160
```
So we can see where the values of argc, and argv are stored on the stack. How
about the `array` array, which is stored in `rbp-0xa` (decimal 10).
```console
(lldb) expr &array
(char (*)[10]) $95 = 0x00007fffffffd0e6

(lldb) memory read -f x -c 10 -s 1 '$rbp - 10'
0x7fffffffd0e6: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x7fffffffd0ee: 0x00 0x00
```
So where is `0x7fffffffd0e6` in the stack above?  
```
(lldb) memory read -c 36 -f x -s 1 '$rbp - 0x20'
0x7fffffffd0d0: 0xd8 0xd1 0xff 0xff 0xff 0x7f 0x00 0x00
0x7fffffffd0d8: 0x40 0x10 0x40 0x00 0x02 0x00 0x00 0x00
0x7fffffffd0e0: 0xd0 0xd1 0xff 0xff 0xff 0x7f [0x00 0x00  <-  0x00007fffffffd0e6 
0x7fffffffd0e8: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
0x7fffffffd0f0: 0x60 0x11 0x40 0x00
```

So this is before we call strcpy. Now lets take a look at the values above
rbp and what they contain before this call:
```
0x7fffffffd0f0:  0x00401160

(lldb) disassemble -n __libc_csu_init
arr-over`__libc_csu_init:
    0x401160 <+0>:   endbr64 
    0x401164 <+4>:   push   r15
```
So this is the function that called main and which the `ret` instruction will
jump to.

After strcpy we have:
```
(lldb) memory read -c 36 -f x -s 1 '$rbp - 0x20' 
0x7fffffffd0d0: 0xd8 0xd1 0xff 0xff 0xff 0x7f 0x00 0x00
0x7fffffffd0d8: 0x40 0x10 0x40 0x00 0x02 0x00 0x00 0x00
0x7fffffffd0e0: 0xd0 0xd1 0xff 0xff 0xff 0x7f 0x62 0x62
0x7fffffffd0e8: 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62
0x7fffffffd0f0: 0x62 0x62 0x62 0x62
```
And in our case it is actually intersting to see that we have written more
values than our array can hold and have started to write past rbp.
