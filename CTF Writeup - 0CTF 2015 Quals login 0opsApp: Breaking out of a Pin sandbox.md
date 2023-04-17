# Introduction
**login: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=aaf466b83156cb16970b254de9d45994bef6e9f9, stripped**

* `Full RELRO`
* `Canary found`
* `NX enabled` 
* `PIE enabled`
* `No RPATH`   
* `No RUNPATH`

**sandbox.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=cfb30b9146f4c31ab241aa1e46f62b3780724290, not stripped**

The challenge consists of an application (_login_) and a pintool (_sandbox.so_). The application is a "login service" with a simple format string vulnerability (there's a little more to it but that's not the interesting part of this challenge). The following C code summarizes how the pintool works:
```language-c
int main(int argc, const char **argv, const char **envp)
{
  int err;
  
  err = PIN_Init(*(LEVEL_PINCLIENT **)&argc, (int)argv, (char **)envp);
  if ( !err )
  {
   PIN_AddSyscallEntryFunction((__int64)syscall_check, 0LL);
   PIN_StartProgram((LEVEL_PINCLIENT *)syscall_check);
    return 0;
  }
  return 1;
}
```
It registers a pre-syscall hook, `syscall_check()`, which is summarized in the pseudo code below:
```language-c
unsigned int syscall_check(unsigned int a1, __int64 a2, unsigned int a3, __int64 a4)
{
    unsigned int sc_num; // rax@1
    static int activated;

    sc_num = LEVEL_PINCLIENT::PIN_GetSyscallNumber((LEVEL_PINCLIENT *)a2, a3);
    switch(sc_num){
        case SYS_read:
            break;
        case SYS_write:
            break;
        case SYS_open:
            if(!open_check(a1, a2, a3))
                exit(-1);
            break;
        case SYS_alarm:
            if(activated)
                exit(-1);
            activated = 1;
            if(mprotect(&activated, 0x1000, PROT_READ))
                exit(-1); 
        case SYS_exit:
            break;
        case SYS_exit_groups:
            break;
        default:
            if(activated)
                exit(-1);
            break;
    }
    return sc_num;
}

```
Basically, the function allows all syscalls as long as the `activated` variable is not set. When it sees an `alarm` syscall, it sets the `activated` variable and from then on, only the syscalls `read`, `open`, `write`, `exit`, `exitgroups`, and `alarm` are allowed. Note that it makes sure to mprotect the `activated` variable after it gets set, so that it can't get modified afterwards.

# Attacking Pin
After reading the following [article](https://github.com/lgeek/dynamorio_pin_escape) I learned that Pin doesn't do anything to prevent the instrumented binary from modifying Pin's memory. With this knowledge I decided to attack the pintool. First let's have a look at the address space layout of the process:
```
304000000-3047e4000 r-xp 00000000 ca:00 67856                            pinbin
3047e4000-3049e3000 ---p 00000000 00:00 0
3049e3000-304a87000 rw-p 007e3000 ca:00 67856                            pinbin
304a87000-304aa8000 rw-p 00000000 00:00 0
304aa8000-304aad000 rwxp 00000000 00:00 0
304aad000-304b11000 rw-p 00000000 00:00 0
304b11000-304b26000 rwxp 00000000 00:00 0
304b27000-304b28000 rwxp 00000000 00:00 0
304b2b000-304b66000 rwxp 00000000 00:00 0
304b66000-304b67000 ---p 00000000 00:00 0
304b67000-304b97000 rw-p 00000000 00:00 0
...
7f1476c23000-7f1476dde000 r-xp 00000000 ca:00 57703                      libc.so.6_1
7f1476dde000-7f1476fdd000 ---p 001bb000 ca:00 57703                      libc.so.6_1
7f1476fdd000-7f1476fe1000 r--p 001ba000 ca:00 57703                      libc.so.6_1
7f1476fe1000-7f1476fe3000 rw-p 001be000 ca:00 57703                      libc.so.6_1
...
7f1488653000-7f1488dfb000 r-xp 00000000 ca:00 58893                      sandbox.so
7f1488dfb000-7f1488ffb000 ---p 007a8000 ca:00 58893                      sandbox.so
7f1488ffb000-7f14890a1000 r--p 007a8000 ca:00 58893                      sandbox.so
7f14890a1000-7f14890a3000 rw-p 0084e000 ca:00 58893                      sandbox.so
...
7f148a2f8000-7f148a2fa000 r-xp 00000000 ca:00 57789                      login
7f148a4f9000-7f148a4fa000 r--p 00001000 ca:00 57789                      login
7f148a4fa000-7f148a4fb000 rw-p 00002000 ca:00 57789                      login
...
```
One interesting thing that we see here is that there are some `rwx` pages in the address space. These pages seem very useful, since we can place shellcode in one of them and jump there. This doesn't directly allow us to break out of the sandbox but it still makes our lives easier. Another interesting thing is that after running the binary multiple times and on different machines, the pinbin always seems to be mapped at the same address. Therefore, we have a the address of some region marked `rwx` where we can store our shellcode and jump to.

## Finding sandbox.so
Since I decided to attack the `sandbox.so` pintool, I first had to find its address. As we can see from the address space layout, its base address seems to be randomized. Since I could already leak the base address of `libc.so.6`, I calculated the offset between `libc.so.6` and `sandbox.so` which is constant. However, after running some tests, it seemed like this constant was different accross machines although it was relatively close. I then bruteforced "around" the value on my machine to find the value of this constant on the target machine. You can find more information about this "constant" [here](http://cybersecurity.upv.es/attacks/offset2lib/offset2lib.html). This method wasn't intellectually satisfying for me so I decided to find another way.

### Introducing DT_DEBUG
When you run `readelf -d` on an ELF binary, you can notice that there usually is a `DEBUG` entry in the `.dynamic` section of the binary:
```
Dynamic section at offset 0x87e3e0 contains 26 entries:
  Tag        Type                         Name/Value
...
 0x0000000000000015 (DEBUG)              0x0
...
```
As far as I can tell, this entry is only there for debugging purposes but it contains information that is useful to us. At runtime, the entry is populated by the loader with a pointer to a structure of type `r_debug` which among other things contains the following:
```c
struct r_debug
  {
    ...
    struct link_map *r_map;	/* Head of the chain of loaded objects.  */
	...
  };

```
The `link_map` structure is defined as follows:
```language-c
struct link_map
  {
   
    ElfW(Addr) l_addr;		/* Base address shared object is loaded at.  */
    char *l_name;		/* Absolute file name object was found in.  */
    ...
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
  };
```
We can execute shellcode and we know the base address of the `pinbin` binary so all we need to do is get the `r_debug` data structure and then traverse the `link_map` linked list to find the base address of `sandbox.so` :) .

## Corrupting the syscallEntryList
Now that we know the address of sandbox.so, we need to find a way to actually break out of the sandbox. Since Pin allows you to register hooks/functions that get called everytime a syscall is issued, my assumption was that there was a list of these functions somewhere so I reversed the pintool a bit and sure enough I found that list. The following pseudo code shows the subroutine that is in charge of getting function pointers from that list and calling them when a syscall is issued:
```
__int64 LEVEL_PINCLIENT::CallSyscallEntry(LEVEL_PINCLIENT *this, __int64 a2, unsigned int a3)
{
    LEVEL_PINCLIENT::EnterPinClientMasterMode(this);
    if ( (Listend - syscallEntryList) >> 3 )
    {
        ...
        // For each entry in list, call function pointer 
        ...
    }
    return LEVEL_PINCLIENT::ExitPinClientMasterMode(this);
}
```
Basically this function checks whether there are any entries in the list and if so, it goes through it and calls the function pointers contained in the different entries. Both `Listend` and `syscallEntryList` are global variables in `.bss` so we can write to them. By setting both to `NULL` we can bypass the check. We can now issue any system calls we want and the instrumentation function will never get called!

You can find the full exploit code [here](https://github.com/acama/ctf/tree/master/0ctfquals2015/0opsApp).
Thanks to [mpizza]() and [salls]() for their help with this challenge.
