## Oct 31 2014 - acez
# Introduction
A few weeks ago, a couple of friends and I decided to take a look at the PS Vita in order to see if we could exploit it in any way. Since I didn't really have an idea where to start, I did some research in order to get some information about the Vita. I fell on an [interesting blog post](http://wololo.net/2014/09/22/native-vita-hacking-whats-the-situation-so-far-part-2/) which seemed to indicate that looking at Webkit vulnerabilities would be a good start. After getting in touch with the authors of the blog post, they agreed to point me to a vulnerability that was present in the Vita's Webkit module at the time. This vulnerability is described [here](http://packetstormsecurity.com/files/123089/Packet-Storm-Advisory-2013-0903-1-Apple-Safari-Heap-Buffer-Overflow.html) and it includes a proof of concept which makes our lives that much easier. In this blog post, I will describe how **freebot**, [johntheropper](https://twitter.com/johntheropper) and I were able to exploit this vulnerability and gain code execution on the Vita. The exploit code can be found in the [webkitties](https://github.com/acama/webkitties) github repository which provides `akai` minimal "SDK" which allows to run code on the Vita (with the same privileges as the Webcore process) and `webkooz` a memory utility which can be used to dump and browse memory.

# A Few things about the Vita
The PS Vita runs on a ARMv7 Cortex-A9 processor with a kernel that seems to be completely proprietary. It implements the modern protections such as XN and ASLR and the web browser seems to be sandboxed and WebKit runs in a seperate process different from the browser. To read more about the Vita checkout [this](http://yifan.lu/2012/12/12/playstation-vita-the-progress-and-the-plan/) link.

# No debugging environment?
For obvious reasons, it was not possible to debug the Vita during the development of the exploit and therefore we had to be creative and come up with ways to do so. What turned out to be very useful for debugging and developping our ROP chain were the bytes `\xfe\xe7` which are the opcodes for a Thumb infinite loop instruction. We also used the memory utility provided in the github repository in order dump code, find ROP gadgets, and explore memory to locate shared libraries/modules. A lot of stuff had to be freeballed and done in the dark. We also used the [midori](http://midori-browser.org/) web browser with a vulnerable version of Webkit which helped a little.

# The exploit
The exploit can be broken down into two main parts. The first one is leveraging the Webkit vulnerability to get arbitrary memory read/write. This step allows us dump memory and get the base addresses of the modules from which we will get ROP gadgets and therefore defeat ASLR. The second one is hijacking the instruction pointer to execute "arbitrary" code through ROP and still be able to return to JavaScript in order to keep the arbitrary memory access obtained in the first part. This allows us to have turing completeness.

## Getting Arbitrary Memory Read
The Webkit vulnerability is a heap based buffer overflow in JavaScriptCore JSArray::sort(...) method. When manipulated correctly this overflow can allow us to have an out of bounds read/write. From the proof of concept from [packet storm](http://packetstormsecurity.com/files/123088/), we are able to get an out of bounds read/write which does half of the job for this step. We then use this primitive to corrupt an ArrayBuffer object's internal data structures to modify the size and base address of the array. The interesting ArrayBuffer structure can be summarized as follows:
```language-c
ArrayBuffer_info_t{
	void * base_address;
	size_t size;
}
```
We modify the size field to be some very very large number and the base address to be `0`. This ArrayBuffer can now read and write from arbitrary locations in memory.
The trick here is that to corrupt the object's internal structure, we need to first find it in memory. We do so by "spraying" the memory with a lot of ArrayBuffers of size `0xABC0` that we keep in a list. We then look for that magic value in memory. Once we find it we modify it and then go through our list of sprayed ArrayBuffers and call the `.byteLength` method to see which object's size has been modified and therefore get the reference object whose internal data structure we will corrupt. We now have an arbitrary memory read/write primitive.

## Arbitrary code execution or JSoS: JavaScript on Steroids
The method used in the packet storm proof of concept takes advantage of the fact JIT is enabled in Safari but unfortunately this is not the case on the PS Vita. We need to figure out a way to execute arbitrary code. Since this is C++, we can just create a fake vtable and replace an object's vtable with our fake vtable. We then call a virtual method to direct execution where we want. From this point, a typical approach would be to write a ROP chain to map an area of memory as `rwx`, store our shellcode there and then we are done. But that is not going to happen. The Vita seems to have some serious sandboxing going on and from what I've been told, it is not possible to map areas of memory as executable from the Webkit process. 
At this point we started writing a ROP chain that would make the Vita connect to a port and send a message but we quickly realized that this wouldn't be really useful since for every thing we would need to do, we would need to modify the ROP chain or write a whole new one. We then thought of a solution: if we can find a virtual method that takes `n` arguments, we can just overwrite its vptr with the address of a library function we want to call and now we can call any library function that takes `n` arguments and still be able to return to the JavaScript. After some hours of searching for a good candidate virtual method and finally finding one, we realised that our master plan had a fundamental mistake... Since this is C++, when a method is called `r0` contains the `this` pointer so we can't control the contents of `r0`. Hence, we decided to go another route. We still ROP, but at the beginning of our ROP chain we save all the registers and we restore them at the end. So our ROP chain should look something like the following:
```language-asm
push {callee_saved_registers}
...
do our stuff here
...
pop {callee_saved_registers}
```
Unfortunately we weren't able to find the gadgets to do that or at least it seemed pretty complicated. After some discussion we realized that some functions in libc did exactly what we needed: `setjmp()`/`longjmp()`. So we changed our plans.
`setjmp()` takes one argument which must be passed in `r0` but as stated earlier, we do not control `r0` which contains the `this` pointer at the time we hijack execution. This means that the object gets overwritten with the saved context after we call `setjmp()` therefore we need to copy the object to some location prior to calling it and then restore afterwards. To summarize the new plan of action:

* Find a convenient Javascript object to corrupt to gain code execution.
* Save the object's data to some static location `saved_object`.
* Overwrite a vptr of the virtual methods of the object with the address of `setjmp()`.
* Call `setjmp()` and copy the context to some static location `saved_context`.
* Restore the object from `saved_object`.
* Overwrite the vptr again with our ROP stuff which sets up `r0-r3` and calls a function and after the function returns, calls `longjmp(saved_context)` to restore the context and return to JavaScript.

For the first point, our choice for the object was lead by three criteria:

* the method should be virtual, since non-virtual methods don't have an entry in the virtual table;
* the method parameters should be a basic type such as an integer or a float; in this way we can control the value of the register used for that parameter directly and completely;
* the object should be easy to find by scanning memory;

To find an appropriate method we grep'd through all the IDL files (which define an interface between JavaScript and C++ object) looking for methods taking integers, and then checking in the corresponding header file if it was virtual or not. A good candidate was the [scrollLeft][1] attribute of the DOM Element class, which is an integer and its [corresponding setter is virtual][2]. Therefore, we could control the `r1` register (`r0` was reserved for the `this` implicit argument). We also considered the [SVGPathConsumer.arcTo][6] method, which would allow to control way more register, however, for reasons we didn't investigate, in our test browser environment all the parameters were going on the stack.

To invoke `setScrollLeft` we just have to set the `scrollLeft` attribute of an HTML element, for instance:
```language-javascript
var element = document.createElement("span");
element.scrollLeft = 0x65646362;
```

However finding a `span` element scanning the memory is not straightforward. Therefore we looked for an object, inheriting from the Element class, easy to identify and in particular having in the data of the class an integer value we can set from JavaScript to an easily recognizible value. Sadly, this was not the case for the `scrollLeft` itself, whose value [is not directly stored in the class data][3]. After a bit of digging we found that a good candidate was the [rows field in HTMLTextAreaElement][4], which is [stored directly][5] as a member of the class.

As in the method used in the first step, we create a series of `<textarea>` elements, we set the number of rows to a recognizible value (through `textarea.rows = 0x65646362`) and then start to scan memory. When we find one of them, we change the value of the `rows` field by directly accessing memory to another value, then we scan the list of `textarea`s we created and find the one with a different number of rows: that's our guy.

In the end, the exploit allows us to do things such as:
```language-javascript
/*
   Connect to ip on given port and
   send msg
*/

function socket_send(ip, port, msg){

    var scenet = libraries.SceNet.functions;
    var sockaddr = allocate_memory(32); 

    mymemset(sockaddr, 0, SIZEOF_SIN);

    aspace[sockaddr] = SIZEOF_SIN;
    aspace[sockaddr + 1] = SCE_NET_AF_INET;

    var PORT = port;
    logdbg("Calling nethtons()");
    var r = scenet.sceNetHtons(PORT); 
    logdbg("-> 0x" + r.toString(16) + "\n"); 
    aspace16[((sockaddr + 2) / 2)] = r;

    aspace32[(sockaddr + 4) / 4] = inet_addr(ip);

    var dbgname = "test_socket\x00";
    var dbgnameaddr = allocate_memory(dbgname.length);

    mymemcpy(dbgnameaddr, dbgname, dbgname.length);

    logdbg("Calling SceNetSocket()");
    var sockfd = scenet.sceNetSocket(dbgnameaddr, SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);
    logdbg("-> 0x" + sockfd.toString(16) + "\n"); 

    logdbg("Calling SceNetConnect()");
    var r = scenet.sceNetConnect(sockfd, sockaddr, SIZEOF_SIN); 
    logdbg("-> 0x" + r.toString(16) + "\n"); 

    var msgaddr = allocate_memory(msg.length);

    mymemcpy(msgaddr, msg, msg.length);

    logdbg("Calling SceNetSend()");
    var sent = scenet.sceNetSend(sockfd, msgaddr, msg.length, 0);
    logdbg("-> 0x" + sent.toString(16) + "\n"); 

    logdbg("Calling SceNetClose()");
    var sent = scenet.sceNetSocketClose(sockfd, 0, 0, 0);
    logdbg("-> 0x" + sent.toString(16) + "\n"); 
}

socket_send("192.168.1.107", 9999, "Hello World From the Vita!\n");

```
For more details, check out the [github repo](https://github.com/acama/webkitties)

# Conclusions
This exploit allows us to have a testing framework / SDK that can be used to aid in reversing modules and testing to find more interesting vulnerabilities. You shouldn't confuse this exploit for what it is not. It is not a hack that allows you to run whatever you want on the Vita and is limited to the privileges of the Webkit process. 
Our next move will be to look at the Vita some more to try and figure out if we can exploit anything that has higher privileges than the Webkit process. A **lot** of work still needs to be done.

# Thanks
[johntheropper](https://twitter.com/johntheropper) and **freebot** for working with me on this exploit.
[yifanlu](https://twitter.com/yifanlu) for being my documentation and answering any question I had about the Vita, [Josh Axey](https://twitter.com/Josh_Axey) for helping me learn about the Vita and test the exploits.
acid_snake, codelion and anybody else I might have forgotten and who made this possible.


[1]: https://github.com/WebKit/webkit/blob/257d8625c93d977621cc3c56d6698d06856f2c1a/Source/WebCore/dom/Element.idl#L77
[2]: https://github.com/WebKit/webkit/blob/257d8625c93d977621cc3c56d6698d06856f2c1a/Source/WebCore/dom/Element.h#L187
[3]: https://github.com/WebKit/webkit/blob/257d8625c93d977621cc3c56d6698d06856f2c1a/Source/WebCore/dom/Element.cpp#L481
[4]: https://github.com/WebKit/webkit/blob/257d8625c93d977621cc3c56d6698d06856f2c1a/Source/WebCore/html/HTMLTextAreaElement.idl#L35
[5]: https://github.com/WebKit/webkit/blob/257d8625c93d977621cc3c56d6698d06856f2c1a/Source/WebCore/html/HTMLTextAreaElement.h#L117
[6]: https://github.com/WebKit/webkit/blob/257d8625c93d977621cc3c56d6698d06856f2c1a/Source/WebCore/svg/SVGPathConsumer.h#L64
