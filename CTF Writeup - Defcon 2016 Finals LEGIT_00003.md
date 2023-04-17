## Jul 06 2017 - Fish
Overview
=========
First of all, we would like to thank [@gyno\_lbs](https://twitter.com/gyno_lbs). He asked us to make a writeup about this challenge in exchange for two free Binary Ninja licenses. As a result, most of the analyses in this writeup were re-done using Binary Ninja. Thanks to the insane reversing skills of my teammate **fish**, we were able to find a number of vulnerabilities in the this challenge (most of this writeup is written by him).
**LEGIT_00003** is an interpreter and JITter for PowerPC. Upon start, it takes the following information from stdin:

- A 3-byte string, either “INT” for interpreter, or “JIT” for JITter. 
- A DWORD `sort` specifying what to output after execution. Setting it to 1 will output the hash of memory and registers, and 2 outputs all values - inside registers and memory.
- A byte stream from `stdin`, beginning with a DWORD that specifies the length. The binary parses it, and initializes a virtual memory structure (whose pointer locates at `0x80e4d4c`). 
Then LEGIT_00003 launches either the interpreting engine or the JITTing engine, and executes at most 1000 instructions.

According to the file name “OPENING.RNB” used in function `parse_data_buffer()`/`sub_80799e0()`, the challenge is actually an emulator for WiiBrew.

Thanks to the effort we spent in building Mechanical Phish, during DEFCON CTF we had a powerful patching system, **Patcherex**. It was a great system that enabled us to easily create and manage our patches. Additionally, we applied some of the generic patches we developed for our CRS, which turned out to be useful for general defense. In the end, the full binary reassembling gave our replacement binary better performance, and made it much harder for other teams to diff our binary with the original binary to learn our patches.

Vuln 0x0: stack buffer overflow in `parse_data_buffer()`
-------------------------------------------------------
From analyzing function `parse_data_buffer()`/`sub_80799e0()`, we learned that LEGIT_00003 treats the input byte stream as a file system, parses files out of it, and initializes ROM (whose pointer is stored at `0x80e4d4c`) with the contents of the file.

Function `ReadFile()`/`sub_8078e10()` takes the following arguments:a file descriptor (`fd`), a pointer to the buffer (`dst`), size to read (`size`), and a pointer to an integer that receives how many bytes are read (`bytes_read`). At `0x807a56d`, the call to function `ReadFile()` will write to a stack buffer buffer, where `esi` at `0x807a553` being the size parameter holds how many bytes to read into the buffer. Since the maximum value of `esi` is not limited, a buffer overflow occurs if the size is a big number. Further reversing shows that `size` is parsed from the file system, and thus fully controlled by the attacker. Since the buffer is located at `$ebp - 0x3958`, setting size to any value greater than `0x3958` will overwrite the return address on the stack. This vulnerability can be used in both type 1 and type 2 POVs.

![](/content/images/2016/10/Pasted-image-at-2016_10_04-12_51-AM--3-.png)

Patching this vulnerability is easy - we simply add a check `esi` to make sure that it is not greater than the stack buffer. Here is the patch we used during the game:

```
PATCH_EXIT_LABEL = AddLabelPatch(0x807dfe0, 'sys_exit')
PATCH = InsertCodePatch(0x807a517, """
cmp esi, 0x3900
jg {.sys_exit}
""")
```

Vuln 0x1: integer overflow in `SetFilePointer()`
----------------------------------------------
Function `SetFilePointer`/`sub_8078db0()` takes three arguments: `fd` (int), `offset` (unsigned int), and a pointer holding the new file offset. As shown in the following figure, `FILE_OFFSET` is updated only when the new offset is less than or equal to `FILE_SIZE`, which makes sense... really?

The problem here is, that the comparison at `0x8078dc9` is a signed comparison, which means any negative offset will work here. Later when `FILE_OFFSET` is used as the beginning offset for content loading from the user-supplied file to ROM, an overbound memory read is achieved.

We found this vulnerability from reversing other teams’ patched binaries, and as far as I remember, we didn’t write any exploit using this vulnerability.

![](/content/images/2016/10/Pasted-image-at-2016_10_04-12_51-AM--2-.png)

The patch is changing `cmovle` to `cmovbe`.

```
PATCH = InsertCodePatch(0x8078dc9, """
cmovbe eax, edx
""")
PATCH_REMOVE_INS = RemoveInstructionPatch(0x8078dc9, None)
```

Vuln 0x2: arbitrary memory read in `memory_read_8()`
--------------------------------------------------
Function `memory_read_8()`/`sub_807c680()` reads 8 consecutive bytes from ROM, and returns a 64-bit integer in `edx:eax`. Correspondingly, function `memory_write_8()`/`sub_807c7b0()` takes 8 bytes from `edx:eax` and writes it to an offset (stored in `ecx`) in ROM specified by user.

Here are the implementations of those two functions. Do you see anything abnormal?

![](/content/images/2016/10/Pasted-image-at-2016_10_04-12_52-AM--8-.png)

![](/content/images/2016/10/Pasted-image-at-2016_10_04-12_52-AM--9-.png)


You must have gotten it within a second - `ecx` in function `memory_read_8()` is not masked, which leads to an arbitrary memory read. This vulnerability can be directly used in a type 2 POV to read out the flag page. However, since we are reading from `MEMORY + ecx`, and `MEMORY` is dynamically allocated during initialization phase, exploiting it is difficult if the team applies a generic patch that randomizes memory allocation upon the start of the binary.

`memory_read_8()` is used in multiple opcodes, including `lfd` (whose handler is located at `0x804bf10`), `lfdu` (`0x804bf50`), etc. Using any of those instructions can give us an arbitrary read.

The patch is simple: just properly mask `ecx` in function `memory_read_8()`.
```
PATCH = InsertCodePatch(0x807c685, """
and ecx, 0x1ffffff
""")
```

Vuln 0x3: arbitrary memory write in `op_vsx_extensions()`
-------------------------------------------------------
There is an arbitrary memory write in function `op_vsx_extensions()`/`sub_804d7d0()` that is caused by the same issue: `address` (`esi` here) is not checked or masked before being used as an index to ROM. As shown in the following two screenshots, `esi`, which holds the offset into ROM for memory write later on at `0x804dc3b`, is directly extracted from a PowerPC instruction coming from the user. Before the memory write, `esi` is neither checked nor masked, and an arbitrary memory overwrite could happen.

![](/content/images/2016/10/Pasted-image-at-2016_10_04-12_52-AM--7-.png)

![](/content/images/2016/10/Pasted-image-at-2016_10_04-12_52-AM--6-.png)


To trigger this vulnerability, we need to build a PowerPC VSX instruction that satisfies the following conditions:

- 8th bit of the instruction must be 1 (`0x804d80f`).
- Sort (`SOME_REGISTERS` located at `0x8097a10` indexed by `operand_1`) is `4` or `6 `(see the switch structure at `0x804d8dd`). For us, this was the hardest condition to satisfy, which I will explain later.
When used as an immediate value, address has only 12 bits. We should set reg (`operand_2`) to any of the 32 registers so that we have a full control over the address we are writing to.
- Value of the memory write at `0x804dc3b` comes from one of the floating point registers, so we can use `lfd` to load the value into one of the FRs before using the VSX instruction to trigger the overwrite.

During the game, we were stuck in writing an exploit for this vulnerability for a *very* long time, since we simply couldn't find any PowerPC instruction that overwrites the freaking `SOME_REGISTERS` array at `0x8097a10`. All X-refs in the binary showed us that the array was only read from, not written to. Only until the morning of the last day did I think of special purpose registers in PowerPC, which, was hinted somehow by a random guy in our team. Too bad that I don’t remember who he was :-(

In short, PowerPC provides a bunch of special purpose registers (SPRs) that can be written via the `mtspr` (the handler is function `op_mtspr()`/`sub_804a750()`) instruction. The following code, which I just resurrected from our chatlog at DEFCON, generates an `mtspr` instruction that overwrites an SPR with value from a GR (general purpose register).

```
def mtspr(spr_offset, reg_offset):
   opcode = 0x1f
   sub_opcode = 0x1d3

   bits = bin(opcode)[2:].rjust(6, '0') # opcode
   bits += bin(reg_offset)[2:].rjust(5, '0')
   bits += bin(spr_offset & 0x1f)[2:].rjust(5, '0')
   bits += bin((spr_offset & 0x3e0) >> 5)[2:].rjust(5, '0')
   bits += bin(sub_opcode)[2:].rjust(10, '0') # sub-opcode
   bits += '0'

   return struct.pack(">I", int(bits, 2))
```

Here is the patch we applied to mask the address:
```
PATCH = InsertCodePatch(0x804dc32, """
and esi, 0x1ffffff
""")
```

Vuln 0x4: arbitrary memory write in `sub_8067a10()`
------------------------------------------------
This one is the same as the previous one, happens at another handler. I didn’t even bother to figure out what handler it is - just patched it during the game.

Here is the patch:
```
PATCH = InsertCodePatch(0x8067e44, """
and esi, 0x1ffffff
""")
```

Vuln 0x5: sandbox escaping by twi
----------------------------------
After spending several hours in reversing the interpreter, we switched to the JITTing part. We found that the function `jit_generate_call()`/`sub_8053b30()` generates an x86 `call` instruction (opcode `e8`), as shown below.

![](/content/images/2016/10/Pasted-image-at-2016_10_04-12_52-AM--5-.png)

X-refs show five different locations where function `jit_generate_call()` is referenced.

![](/content/images/2016/10/Pasted-image-at-2016_10_04-12_30-AM.png)

Examining each reference, we found that only in function `jit_op_twi()`/`sub_8069dc8()` can we freely control the address passed to `jit_generate_call()`, which essentially allows a sandbox (or emulator? I dunno) escape by executing arbitrary code in the binary. This function turns out to be a privileged syscall instruction, which, makes a lot of sense...

![](/content/images/2016/10/Pasted-image-at-2016_10_04-12_53-AM.png)

We patched it by nopping the very last call in function `jit_op_twi()`. It impacted the functionality for sure, but was a “good enough” patch that didn’t fail any SLA check.

```
PATCH_a = RemoveInstructionPatch(0x8069dcf, None)
PATCH_b = RemoveInstructionPatch(0x8069dd4, None)
```

Vuln 0x6: corrupted `mov` instruction generated by JIT engine
--------------------------------------------------------------
From analyzing one of **PPP**'s replacement CBs, we noticed a patch in the function `WRITEMEM32()`/`sub_805aa20()` that allowed us to identify another vulnerability. When generating a `mov` instruction of an 8-bit immediate, the JIT engine generates an invalid instruction as a result of not correctly updating the pointer to the destination buffer of the JIT code. The result is that the "immediate" operand partially overwrites the generated `mov` instruction.

![](/content/images/2016/10/Pasted-image-at-2016_10_04-12_48-AM.png)

The patches we used for this vulnerability are the following:
```
PATCH_a_0 = InsertCodePatch(0x805ab2f, """
mov [edx+ecx+6], al
""")
PATCH_a_1 = RemoveInstructionPatch(0x805ab2f, None)
PATCH_b_0 = InsertCodePatch(0x805ab58, """
mov [edx+ecx+6], al
""")
PATCH_b_1 = RemoveInstructionPatch(0x805ab58, None)
PATCH_c_0 = InsertCodePatch(0x805ab83, """
mov [edx+ecx+6], al
""")
PATCH_c_1 = RemoveInstructionPatch(0x805ab83, None)
PATCH_d_0 = InsertCodePatch(0x805abae, """
mov [edx+ecx+6], al
""")
PATCH_d_1 = RemoveInstructionPatch(0x805abae, None)
```

Vuln 0xff: flag page used to initialize registers
------------

The 32 general purpose registers are initialized in `sub_8048890()` with the following formulae:

```
for (i = 0; i < 32; ++i) {
    GR[i] = (FLAG_PAGE[i] ^ FLAG_PAGE[i + 32]) & 0xf00f70f0;
}
```

General registers are printable at the end of the execution by setting `sort` to `1`. However, there seems to be too many missing bits for us to correctly recover the flag.

Final Words
==========

A smart defense
----------------
One team switched `“INT”` and `“JIT”` in their replacement binary, which, considering that both the interpreter and the JITter should have same (or mostly the same) functionalities, and they have different vulnerabilities, is a really smart way of defending.

It’s actually open sourced!
----------------------------
It turns out that the source code of this PowerPC interpreter/JITTer was based on an open source project. Team **b1o0p** figured that out during the game, which greatly helped their reversing and exploiting. We didn’t even bother to Google those strings - the only thing we had from Google for this Challenge is the PowerPC ISA spec :-( what a nooby mistake.
