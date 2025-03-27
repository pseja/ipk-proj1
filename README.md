# IPK Layer 4 Scanner - Documentation
Author: Lukáš Pšeja

Login: xpsejal00

Date: 27.3.2025

Variant: Omega

## Author's note<a id="authorsnote"></a>
This documentation will be structured as a tutorial with the most useful information I could find for someone who doesn't know anything about TCP/UDP scanning so that when I or someone else comes and reads this documentation will be able to understand how it was done. Time spent on this project was 60 hours flat not counting the reading of the bibliography that was given to us and I learned how to use [tmux](https://en.wikipedia.org/wiki/Tmux) which was a great help during development as well as other networking tools like [wireshark](https://en.wikipedia.org/wiki/Wireshark), [nmap](https://en.wikipedia.org/wiki/Nmap), [netcat](https://en.wikipedia.org/wiki/Netcat) and others.

## Introduction<a id="introduction"></a>
The IPK Layer 4 Scanner is a command-line tool inspired by nmap designed to perform TCP and UDP port scanning on both IPv4 and IPv6 addresses. It supports scanning of specific ports, port ranges or port lists, and provides output on the status of said scanned ports. The application also includes functionality for listing active network interfaces and information about them as well as validating input arguments using [getopt](https://en.wikipedia.org/wiki/Getopt) and detailed error messages in case of something failing to execute.

This documentation provides an overview of networking theory needed for this project, the application's functionality, implementation details, testing, bonus functionality and bibliography.

## Theory<a id="theory"></a>
A port scanner is an application designed to probe a server or host for open ports. Such an application may be used by administrators to verify security policies of their networks and by attackers to identify network services running on a host and exploit vulnerabilities. [[1]](#bib1)

### TCP SYN scanning<a id="theory-tcp-syn-scanning"></a>
This technique is often referred to as "half-open" scanning, because you don't open a full TCP connection. You send a *SYN packet*, as if you are going to open a real connection and wait for a response. A *SYN|ACK* indicates the port is listening. A *RST* is indicative of a non-listener. If a *SYN|ACK* is received, you immediately send a *RST* to tear down the connection (actually the kernel does this for us). The primary advantage to this scanning technique is that fewer sites will log it. Unfortunately you need root privileges to build these custom SYN packets. [[2]](#bib2)
![SYN scan of open port 22](/imgs/Ereet_Packet_Trace_Syn_Open.png)[[3]](#bib3)
The figure above shows how successful port scan is done (they are all successful in a way). There can be two more alternatives that can happen when scanning like this. The first one is that the port is closed:
![SYN scan of closed port 113](/imgs/Ereet_Packet_Trace_Syn_Closed.png)[[4]](#bib4)
SYN packet is send to port 113 and the server sends back RST response which says to us that the port is definitely closed. What nmap does in this situation is that it tries to send another packet and test if it was for real the answer it was meant to be.
![SYN scan of filtered port 139](/imgs/Ereet_Packet_Trace_Syn_Filtered.png)[[5]](#bib5)
Again and again, SYN packet is sent once trying to see if something is open on port 139. Nothing is sent back, so our program is printing `address 139 filtered`. There should also be a second SYN packet sent but i didn't catch that in the assignment so I didn't implement that.

So for this project we could be thinking of something like this:
| Response | Output   |
|----------|----------|
| SYN/ACK  | open     |
| RST      | closed   |
| timeout  | filtered |

### UDP ICMP scanning<a id="theory-udp-icmp-scanning"></a>
UDP is a connectionless protocol so there is no equivalent to a TCP SYN packet. However, if a UDP packet is sent to a port that is not open, the system will respond with an ICMP port unreachable message. Most UDP port scanners use this scanning method, and use the absence of a response to infer that a port is open. However, if a port is blocked by a firewall, this method will falsely report that the port is open. If the port unreachable message is blocked, all ports will appear open. [[6]](#bib6)

In this project, there can arise two scenarios
1) We sent a packet and destination unreachable was returned:

![udp destination unreachable](/imgs/udp1.png)

we can assume that this is a closed port.

2) We send a packet but something else than destination unreachable was sent back:

![udp nothing sent back](/imgs/udp2.png)

we can assume that this is an open port for the simplicity of this project.

So for UDP we could be thinking of something like this:
| Response                | Output |
|-------------------------|--------|
| Destination Unreachable | closed |
| anything else           | open   |

Note: in IPv4 "Destination Unreachable" has the type of 3 and code 3, but in IPv6 it has the type of 1 code 4.

## Implementation<a id="implementation"></a>
As said in the [Author's note](#authors-note) I took this project as some sort of a "tutorial" where I would like to show people (me included if I need this functionality later in life) how it's done and they could see the differences of each implementation side by side. I think that I reached this goal even though it may not be what the teachers expected from this documentation and implementation (i hope they like it though).

Not all things are functional, like scanning the `localhost` address with `lo` interface or scanning `localhost` address with other interfaces. The message is being sent and I can see it in Wireshark but the program doesn't catch it and I haven't figured out why.

This project is organized like so
```sh
.
├── CHANGELOG.md
├── imgs/
├── LICENCE
├── Makefile
├── README.md
├── src/
└── test/
```

where the `CHANGELOG.md`, `README.md` and `LICENCE` are the documentation files and the source files are `Makefile` and the header `.h` files in the `src/` directory along with the implementation `.c` files.

`src/` directory:
```sh
src/
├── argparse.c
├── argparse.h
├── colors.h
├── error.c
├── error.h
├── main.c
├── network_utils.c
├── network_utils.h
├── scanner.c
└── scanner.h
```

- `argparse.c` and `argparse.h` handle command-line argument parsing and validation. Includes functions for parsing port numbers, ranges, and target addresses.
- `colors.h` provides color codes for formatted terminal output.
- `error.c` and `error.h` implement utilities for consistent error reporting and logging.
- `main.c` the entry point of the application. Orchestrates the scanning process by parsing arguments, handling signals, and invoking scanning functions.
- `network_utils.c` and `network_utils.h` contain helper functions for network-related tasks, such as validating IP addresses, retrieving network interfaces, and resolving target addresses.
- `scanner.c` and `scanner.h` implement the core scanning logic for TCP and UDP protocols, including checksum calculation and packet construction.

`test/` directory:
```sh
test/
└── argtest.sh
```

- `argtest.sh` a Bash script for testing the argument parsing functionality of the application. It validates various input scenarios, such as valid and invalid arguments, and checks the program's behavior against expected outcomes. The script outputs the results of each test case to the terminal. (The testing can be reproduced by commenting out lines `75` and `77` in `main.c` and running `make test`) here is the proof of testing:

![proof of argtest functioning](/imgs/argtest-main-c-commented.png)
![proof of argtest command-line](/imgs/argtest-cmd.png)

### TCP SYN scanning<a id="implementation-tcp-syn-scanning"></a>
- A segment buffer is initialized to hold the packet data.
- The ip header (`struct iphdr` for IPv4 and `struct ip6_hdr` for IPv6) and TCP header (`struct tcphdr`) are constructed within the segment buffer.
- Interface and server ip addresses are fetched.
- Ip header is filled.
- Tcp header is filled.
- TCP pseudo header is initialized and filled.
- Final tcp checksum is calculated.
- Destination socket address is setup for `sendto()`.
- Response socket and send socket are initialized (has to be in this order, when talking to some colleagues they got localhost packet receiving working this way).
- `sendto()` the filled segment.
- Close send socket because it is not needed anymore.
- Set the timeout for receiving a response.
- Using `select()` for handling timeout.
- Load the incoming packet with `recvfrom()` into a buffer.
- Adjust the offsets for reading the correct flags in the buffer (this is different for IPv4 and IPv6).
- ???
- Profit.

This is the general structure of what the code does, in this regard I like to say that the code is the best documentation for this. But at least I can give you some bibliography I used in constructing the packets.

<a id="ipv4-header"></a>The IPv4 header was constructed by using this structure:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
[[7]](#bib7)

<a id="ipv6-header"></a>and the IPv6 header like this:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                         Source Address                        +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                      Destination Address                      +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
[[8]](#bib8)

TCP header was filled out using this:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
[[9]](#bib9)

TCPv4 pseudo header:

```
+--------+--------+--------+--------+
|           Source Address          |
+--------+--------+--------+--------+
|         Destination Address       |
+--------+--------+--------+--------+
|  zero  |  PTCL  |    TCP Length   |
+--------+--------+--------+--------+
```
[[7]](#bib7)

and the TCPv6 pseudo header:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                         Source Address                        +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                      Destination Address                      +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Upper-Layer Packet Length                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      zero                     |  Next Header  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
[[8]](#bib8)

### UDP ICMP scanning<a id="implementation-udp-icmp-scanning"></a>
- A datagram buffer is initialized to hold the packet data.
- The ip header (`struct iphdr` for IPv4 and `struct ip6_hdr` for IPv6) and UDP header (`struct udphdr`) are constructed within the datagram buffer.
- Interface, server ip and source ip addresses are fetched.
- Ip header is filled.
- UDP header is filled.
- UDP pseudo header is initialized and filled.
- Final udp checksum is calculated.
- Destination socket address is setup for `sendto()`.
- Response socket and send socket are initialized (has to be in this order, when talking to some colleagues they got localhost packet receiving working this way).
- `sendto()` the filled segment.
- Close send socket because it is not needed anymore.
- Set the timeout for receiving a response.
- Using `select()` for handling timeout.
- Load the incoming packet with `recvfrom()` into a buffer.
- Adjust the offsets for reading the correct flags in the buffer (this is different for IPv4 and IPv6).
- ???
- Profit.

This is the structure of the UDP packet:
```
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source      |   Destination   |
|      Port       |      Port       |
+--------+--------+--------+--------+
|                 |                 |
|     Length      |    Checksum     |
+--------+--------+--------+--------+
|
|          data octets ...
+---------------- ...
```
[[11]](#bib11)


As you can see, when you put this process side by side it is very similar to TCP, in fact I copied the TCP code and just changed the structures to UDP and it was working pretty fine.

Also when jumping from IPv4 to IPv6 code I was using the [beej.us guide](https://beej.us/guide/bgnet/html/index.html#jumping-from-ipv4-to-ipv6). The full document is available in this bibliography link: [[10]](#bib10)

## Bonus functionality<a id="bonus-functionality"></a>
I wouldn't count it as a bonus functionality per se but I implemented the interface printing functionality to return more information along the interfaces, like the description of the interface and its addresses and I used the `colors.h` underline white color just to make it more readable.

## Testing<a id="testing"></a>
During the testing phase I used Ubuntu 24.04 WSL and the virtual machine provided with the assignment.

### Tested sites
- `localhost`
- `scanme.nmap.org` public testing target provided by the nmap project

### Testing scenarios
1. Open ports - testing that the scanner correctly recognizes open ports.
2. Closed ports - testing the recognition of closed ports.
3. Filtered ports - testing the scenario when the port is blocked or filtered.

### Testing tools
- monitoring using Wireshark
- opening ports on localhost using Netcat

### Screenshots
Showcase of the program correctly printing IPv4 and IPv6 responses.

![ipv4 and ipv6 vm testing](/imgs/vm-testing.png)


Showcase of the program not seeing the incoming localhost packets showing every port as filtered, but in Wireshark the packets are correct.

![ipv4 localhost vm testing](/imgs/vm-testing1.png)

## Bibliography <a id="bibliography"></a>
[1] <a id="bib1"></a> Port scanner. Online. Available from: https://en.wikipedia.org/wiki/Port_scanner [Accessed 27 March 2025].

[2] <a id="bib2"></a> Nmap: The Art of Port Scanning. Online. Available from: https://nmap.org/nmap_doc.html#syn [Accessed 27 March 2025].

[3] <a id="bib3"></a> TCP SYN (Stealth) Scan (-sS). Online. Available from: https://nmap.org/book/synscan.html#idm45751291614384 [Accessed 27 March 2025].

[4] <a id="bib4"></a> TCP SYN (Stealth) Scan (-sS). Online. Available from: https://nmap.org/book/synscan.html#idm45751291602576 [Accessed 27 March 2025].

[5] <a id="bib5"></a> TCP SYN (Stealth) Scan (-sS). Online. Available from: https://nmap.org/book/synscan.html#idm45751291595200 [Accessed 27 March 2025].

[6] <a id="bib6"></a> Port scanner. Online. Available from: https://en.wikipedia.org/w/index.php?title=Port_scanner#UDP_scanning [Accessed 27 March 2025].

[7] <a id="bib7"></a> RFC 791: Internet Protocol, 1981. Online. Request for Comments. Internet Engineering Task Force. Available from: https://www.rfc-editor.org/rfc/rfc791#section-3.1 [Accessed 27 March 2025].

[8] <a id="bib8"></a> RFC 8200: Internet Protocol, Version 6 (IPv6) Specification, 2017. Online. Request for Comments. Internet Engineering Task Force. Online. Available from: https://www.rfc-editor.org/rfc/rfc8200#section-3 [Accessed 27 March 2025].

[9] <a id="bib9"></a> RFC 793: Transmission Control Protocol, 1981. Online. Request for Comments. Internet Engineering Task Force. Available from: https://www.rfc-editor.org/rfc/rfc793#section-3.1 [Accessed 27 March 2025].

[10] <a id="bib10"></a> Beej's Guide to Network Programming. Using Internet Sockets. Brian “Beej Jorgensen” Hall Online. Available from: https://beej.us/guide/bgnet/html/index.html [Accessed 27 March 2025].

[11] <a id="bib11"></a> RFC 768: User Datagram Protocol, 1980. Online. Request for Comments. Internet Engineering Task Force. Available from: https://www.rfc-editor.org/rfc/rfc768 [Accessed 27 March 2025].
