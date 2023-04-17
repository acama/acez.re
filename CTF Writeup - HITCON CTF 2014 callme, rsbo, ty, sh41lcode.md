## Aug 18 2014 - acez
I had a lot of fun playing HITCON CTF this weekend so I decided I would make writeups for the challenges I worked on. In this post I provide my solutions for [callme](#callme), [rsbo](#rsbo), [ty](#ty) and [sha1lcode](#sha1lcode). Since [stkof](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/) was a more serious binary, I decided to make a seperate post for it which can be found [here](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/).

#callme
**callme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=5202d364883e59ee9842759ac8d3fe4e9831d3fa, stripped**

* `Partial RELRO`
* `Canary found`
* `NX disabled` 
* `No PIE`
* `No RPATH`   
* `No RUNPATH`

This binary simulated a simple voicemail and asked the user to leave a "message" which was read from `stdin` into a static buffer
```language-c
int voicemail()
{
 ...
    read_str(&static_buf, 1024);
 ...
    process_message();
 ...
  return result;
}
```
The `process_message()` function setup some format strings on the stack, got the current time and called another function that I called `mononoke()` (not sure why) with the format string as an argument. The `mononoke()` function copied the `static_buf` and the local time (in string format) into a local stack buffer of size 128 with `sprintf()` using the format string passed by the `process_message()` function.
Obviously there is a stack-based buffer overflow in the mononoke() function however the binary has stack canaries enabled and there is no way to leak the stack canaries before trashing them.
The trick here is to overflow the local buffer and keep writing until the format string prepared by `process_message()` is overwriten. This way it is possible to trigger a format string vulnerability. Since the stack canary is overwritten the `___stack_chk_fail()` function will get called therefore we overwrite the GOT entry of that function with an address pointing in static_buf where we will store our shellcode.The flag: `HITCON{D1d y0u kn0w f0rma7 57rin9 aut0m@ta?}`. The exploit for this challenge can be found [here](https://github.com/acama/ctf-writeups/tree/master/hitcon2014/callme).

#rsbo
**rsbo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=f55cab43de46d4c195e09e1f62b22284b4fec38b, not stripped**

* `Partial RELRO`
* `No canary found`
* `NX enabled` 
* `No PIE`
* `No RPATH`   
* `No RUNPATH`

This binary had a straightforward stack-based buffer overflow caused by the function read\_80\_bytes() which actually read 0x80 (128) bytes into a local stack buffer of size 80. However the binary swapped bytes the bytes based on a semi-random seed. I did not look too much into that part so I don't know if there was a way to predict this. In order to swap the bytes, the binary iterates over all the input bytes and swaps the current byte with another byte at some random index:
```language-c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int r;
  char buf[80];
  int tmp;
  int ridx;
  size_t nbytes;
  signed int i;

  alarm(0x1Eu);
  init();
  nbytes = read_80_bytes(buf);
  for ( i = 0; i < (signed int)nbytes; ++i )
  {
    r = rand();
    ridx = r % (i + 1);
    tmp = buf[i];
    buf[i] = buf[r % (i + 1)];
    buf[ridx] = tmp;
  }
  write(1, buf, nbytes);
  return 0;
}
```
Since the bytes get swapped in some apparently random manner, we have a very small chance of having our data look like it's original state after the swapping operations. The plan is to overwrite the nbytes variable with 0 which will cause the loop to terminate and increase our chances of having the remaining bytes of our data be intact. From running a few tests, this is the case most of the time. We perform a ropchain that reads some more data a.k.a our second stage rop chain into .bss which is at a static location and then we "replay" the binary and do the same initial steps as the first time but only this time we "pivot" the stack to the .bss where our second stage rop chain is located. Since the binary uses open(), read(), write() we can just use those functions to read the flag: `HITCON{Y0ur rand0m pay1oad s33ms w0rk, 1uckv 9uy}`. Thanks jay for helping me with this challenge. The exploit can be found [here](https://github.com/acama/ctf-writeups/tree/master/hitcon2014/rsbo).

#ty
**ty: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 3.7.0, BuildID[sha1]=a72f76067f5d6eec22db05df0472af130e242027, not stripped**

* `Partial RELRO`
* `No canary found`
* `NX disabled` 
* `No PIE`
* `No RPATH`   
* `No RUNPATH`


This binary was kind of an "oh-shit" moment for me because I had planned on setting up an aarch64 qemu virtual machine for a while but never got around to doing it due to lazyness issues.
This executable open's /dev/urandom,reads from `stdin` a string representing the amount of bytes to be read in the `code` static buffer. It then passes that string to strtol and makes sure that it is less than 256. After that it reads the specified amount of bytes from `stdin` into `code` and then reads an equal amount from /dev/urandom in a static buffer called `rnd`. It then xors each byte in "code" with the corresponding byte in "rnd". Finally, it jumps to code.
Since there is no way (that I know of) of predicting the output from /dev/urandom, I had to find a way around this. The category of the challenge ("pwning") hinted that there was a vulnerability somewhere in the executable. Looking at readline:
```language-asm
...
.text:00000000004008D0 loc_4008D0                              
.text:00000000004008D0             LDRB            W2, [X19]
.text:00000000004008D4             CMP             W2, #0xA
.text:00000000004008D8             B.EQ            loc_400904
.text:00000000004008DC             CMP             W20, W21
.text:00000000004008E0             ADD             X19, X19, #1
.text:00000000004008E4             B.EQ            loc_40091C
.text:00000000004008E8 loc_4008E8                              
.text:00000000004008E8             MOV             X1, X19
.text:00000000004008EC             MOV             W0, #0
.text:00000000004008F0             MOV             X2, #1
.text:00000000004008F4             BL              read_0
.text:00000000004008F8             CMP             X0, #1
.text:00000000004008FC             ADD             W20, W20, #1
.text:0000000000400900             B.EQ            loc_4008D0
.text:0000000000400904
.text:0000000000400904 loc_400904                              
.text:0000000000400904             STRB            WZR, [X19]
.text:0000000000400908             MOV             W0, #0
.text:000000000040090C             LDP             X19, X20, [SP,#0x20+var_10]
.text:0000000000400910             LDP             X21, X22, [SP,#0x20+var_s0]
.text:0000000000400914             LDP             X29, X30, [SP+0x20+var_20],#0x30
.text:0000000000400918             RET
...
```
The problem here is that the `ADD` at `4008E0` happens after the `CMP` which here compares the given length to the counter. This means that `X19` is now pointing to the byte right after the and at `400904` a null is written to it. This means that whatever is after our buffer gets nulled out if we provide a string that is 8 bytes long. Luckily right after the buffer is the file descriptor returned by the open("/dev/urandom"). Since we are overwriting this with a null, the executable will read from stdin instead of /dev/urandom. We send a bunch of 0's so that our payload in `code` stays intact. The flag: `HITCON{HAve_FuN_4_NXTGen_P1at4|m}`. The exploit can be found [here](https://github.com/acama/ctf-writeups/tree/master/hitcon2014/ty).

#sha1lcode
**sha1lcode: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=24f99f7521c7cfd4ca74c2701a28994b38fcd046, not stripped**

* `Partial RELRO`
* `No canary found`
* `NX disabled` 
* `No PIE`
* `No RPATH`   
* `No RUNPATH`

This challenge was a "shellcoding" challenge just like in last year's defcon qualifiers. The binary reads a number `n < 1000` from `stdin` and then reads n * 16 bytes. It then performs the SHA1 of the input 16 bytes at a time and then concatenates those SHA1 sums and then tries to execute them. I brainstormed with [@zardus]() who suggested that I write my shellcode in the follwing method:
Say the shellcode I want to execute is **S<sub>1</sub>S<sub>2</sub>S<sub>3</sub>S<sub>4</sub>**, all I need to do is find some SHA1's that look like the following:

- **S<sub>1</sub>J<sub>n</sub>X<sub>0</sub>X<sub>1</sub>...X<sub>n</sub>**
- **S<sub>2</sub>J<sub>n</sub>X<sub>0</sub>X<sub>1</sub>...X<sub>n</sub>**
- **S<sub>3</sub>J<sub>n</sub>X<sub>0</sub>X<sub>1</sub>...X<sub>n</sub>**
- **S<sub>4</sub>J<sub>n</sub>X<sub>0</sub>X<sub>1</sub>...X<sub>n</sub>**

The **J<sub>i</sub>** represent jumps by **n** and the **X<sub>i</sub>**'s represent random values (rest of SHA1). This way we execute our shellcode little by little. Finding SHA1's with the **S<sub>i</sub>** is a relatively easy task but since I am lazy I will execute as little as I can in this way. We will read "clean" shellcode to a (any) stack address and then jump to that. Examining the stack at the start of our shellcode I came up with the following stage 1 shellcode:
```language-asm
	push	rbx		# rbx contains
	pop		rdi		# 0 = stdin
	push	rbx
	pop		rax		# 0 = syscall_read 
	push	rbp		# rbp contains a stack address
	pop		rsi
	syscall
	call	rbp		# execute clean shellcode
```
All these instructions are 2 byte instructions except for the syscall which is 3 bytes long. The reason I chose these is because bruteforcing the SHA1's runs faster, the less bytes you need to match.
The corresponding input sequences are respectively:
```language-c
	"00000000000000000000000021498201".decode('hex') 
	"00000000000000000000000087014200".decode('hex')
	"00000000000000000000000021498201".decode('hex')
	"0000000000000000000000007b3e0701".decode('hex')
	"0000000000000000000000005b972701".decode('hex')
	"00000000000000000000000041160500".decode('hex')
	"000000000000000000000000f9252fdc".decode('hex')
	"00000000000000000000000093650000".decode('hex')
```
The flag: `HITCON{Warning: over 80 percent unused bytes in your sha1lcode}`.
The exploit for this challenge can be found [here](https://github.com/acama/ctf-writeups/tree/master/hitcon2014/sha1lcode).
