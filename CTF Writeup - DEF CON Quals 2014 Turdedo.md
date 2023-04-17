## May 20 2014 - acez

This past weekend I took part in the Defcon Quals 2014 and one of the challenges I worked on that I really liked was the "turdedo" (Selir 3) challenge so I decided to make a writeup for it. I worked on this challenge with [@zardus](https://twitter.com/Zardus) and [@antoniob](@_antonio_bc_).

# Description

The challenge claims to implement the teredo IPv6 tunneling protocol. I had never heard of this protocol before and I really didn't feel like reading RFC's or whatnot so I just decided to reverse the binary and see what kind of input it wants.
From a high level glance we see two interesting functions in the binary. One of them I call `rm_percent_n()`, which seems to replace the occurences of %n from some user input and the other one, `shell_func()` which executes a restricted "shell" that only has "ls", "pwd", "echo", "uname", "help" and "exit" commands. It also contains a "cat" command which doesn't do anything. Command injections do not work since there is some input sanitization going on for all the commands except for "echo" because it doesn't actually call the "echo" shell command but instead just prints back the input to the user.
The service accepts two types of packets that vaguely have the following format:
```language-c
struct turdedo_packet {
    int	unused;
    uint16_t data_len;	// length of payload
    int8_t protocol; 	// protocol number
    ...
    int8_t fragment_identifier; // Which set of fragments does this belong to
    ...
    enum{
    	uint16_t fragment_offset;	// offset of current fragment used in IPv6
        uint16_t destport;		// destination port must match 3544, used in UDP
    }
    ...
	char data[1452]; // Actual payload
};
```
The protocol field can have one of two values: 44 and 17 which from [this](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml) seem to be respectively IPv6-frag and UDP protocol numbers.
The IPv6-frag packet encapsulates a UDP packet in the `data` field. Moreover, the IPv6-frag protocol makes it possible to send fragmented UDP packets which are stored in a global list of fragmented packet buffers. The fragments with the matching `fragment_identifier` (among other things) are stored in the same fragment buffer. The offset of the fragment carried by the current IPv6-frag packet is specified in the `fragment_offset` field. If the LSB of this field is set to 1, then the UDP packet being carried is a fragment and the service stores it at the specified `fragment_offset` (ignoring the LSB) in the fragment buffer and goes back to read some more packets. If the LSB of this field is set to 0, then the packet is considered to be the last fragment and the service stores it in the fragment buffer, constructs a turdedo_packet with the `protocol` field set to 17 (UDP) and sends it to the UDP handling routine.
In order to reach the `shell_function()`, a three-way handshake first needs to be performed. I will not describe this process because it is not relevant to actually exploiting the service.
Now, after reaching the `shell_function()` we see that there is a format string vulnerability with `snprintf()` when we use the "echo" command.
Unfortunately, the `rm_percent_n()` function we talked about earlier is called on any UDP packet that has size greater than `0x10`, the size of the IPv6-frag header + the size of the UDP header (8 + 8). This means that if we have some data in our UDP packet, the "%n"'s will be replaced with "%\_" since the size would be greater than `0x10`. Therefore we can easily leak data from memory with things such as "%x" and "%s" but we cannot write to memory using "%n" type format specifiers because they get replaced with %\_.
        
# The Exploit

The main goal of this challenge then becomes finding a way to bypass the `rm_percent_n()` function. In order to do so let's take a look at some part of the IPv6-fragment handling function.
```language-c
	fragment_buffer_ptr = find_fragment_buffer(packet_data);
    if ( fragment_buffer_ptr )
    {
      fragment_offset = ntohs(packet_data->fragment_offset & 0xF8FF);
      result = fragment_offset + ntohs(packet_data->data_len) - 8;
      if ( result > 0xFFFF )
        return result;
      _is_frag = ntohs(packet_data->fragment_offset & 0x100);
      udp_packet_buffer = fragment_buffer_ptr->packet_data_ptr;
      
      ...
      
      if ( ntohs(packet_data->data_len) > 0x10u )
      {
        data_len = ntohs(packet_data->data_len);
        remove_percent_n(packet_data->data, data_len - 8);
      }
      data_len = ntohs(packet_data->data_len);
      memcpy(udp_packet_buffer + fragment_offset + 40, packet_data->data, data_len - 8);
      if ( _is_frag )
      {
        timestamp = time(0);
        fragment_buffer_ptr->timestamp = timestamp;
      }
      else
      {
        ...
        process_udp_packet(udp_packet_buffer, ...);
        ...
      }
```
Here `packet_data->data_len` and `packet_data->data` refer to the length and data of the UDP packet encapsulated in the IPv6 packet. With the `fragment_offset` passed to the `memcpy()` we can control the offset into the `udp_packet_buffer` where the current UDP fragment (including the 8 byte header) will be written. The `udp_packet_buffer` will then be passed to the UDP handling routine which will pass the payload of the UDP packet to the `shell_function()`. In order inject a "%n" in our data, we will take advantage of this fragmentation scheme. 
One important things to know are that we control the first 2 bytes of the UDP header. These constitute the `fragment_identifier` identifier field we talked about earlier and can be set to arbitrary values but they need to match for each groups of fragmented packets.
Another important thing to know is that the 8 byte UDP header is nullbyte-free or at least can be made nullbyte-free. This is because the "mandatory" fields don't contain null-bytes and so we can just fill in the other bytes with printable characters. 
The way we will construct our data containing the "%n" is as follows:

- All the fragment packets we send will have the first byte of their `fragment_identifier` field set to "n" and the second byte set to a non-null byte.
- We send the first fragment of some large size (say 800 bytes) UDP packet containing the "echo" command and our format strings seperated and padded with spaces and not containing the "n" but containing the "%". It will look something like this "echo %**wsize**<sub>1</sub>u%**offset**<sub>1</sub>$ [space\_padding] %**wsize**<sub>2</sub>u%**offset**<sub>2</sub>$ [space\_padding] ... %**wsize**<sub>m</sub>u%**offset**<sub>m</sub>$ [space\_padding]". 
- We then make another fragment that has no data (therefore its size is <= 0x10) and make sure `fragment_offset` lies whithin the [space\_padding] area of our string. We will do this for the _m_ format strings that we have.
- In the end we will end up with something that will look like this "echo %**wsize**<sub>1</sub>u%**offset**<sub>1</sub>$ [space\_padding +  **n** + rest\_of\_header + space\_padding] %**wsize**<sub>2</sub>u%**offset**<sub>2</sub>$ [space\_padding +  **n** + rest\_of\_header + space\_padding] ... %**wsize**<sub>m</sub>u%**offset**<sub>m</sub>$ [space\_padding +  **n** + rest\_of\_header + space\_padding]".

Now that we have our "%n", the way we obtain arbitrary code execution which was neatly found by zardus is to overwrite the return address of the `snprintf()` call and make it point inside the `shell_func()` right before the `popen()` call. Since the `snprintf()` is called from `shell_func()` the stack will be restored and `popen()` will be called with our original unsanitized input. This will allow us to cause a "command-injection" through which we can execute any shell command.

You can find the full code for the exploit [here](https://github.com/acama/ctf-writeups/tree/master/defconquals2014/turdedo).
Thanks to LegitBS for another great DC Quals.


