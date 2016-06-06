1.Application Layer 

1)URL 
For making HTTP header, the first thing we need to do is to analyze the URL inputted by user. Uniform Resource Locator (URL) commonly has 3 parts, protocol, hostname and filename. The program will split the URL into different parts depending on °∞/°±, and judge whether each part is legal or not. If the user doesn°Øt specify the filename, the default we give will be °∞index.html°±. 

2)Source and Destination IP address
The program can find destination IP address by resolving the hostname getting from the URL. However, for source IP, it is more complex. If we resolve localhost name directly, it will return local loop address, which can be °∞127.0.0.1°±. For solving this problem, we first create a socket to connect to a website, in our case it°Øs °∞david.choffnes.com°±, and the analyze the socket to get the source IP address using sock.getsockname().

3)HTTP Header Making
Because the main duty of the program is to download the webpage using raw socket, so we use HTTP1.1 and °∞GET°± method to make HTTP header. The following is HTTP header we use.
GET filename HTTP/1.1
Host: HostName
Accept: text/html
Accept-Language: en-US,en
Connection: keep-alive


2.Transport Layer (TCP)

                     TCP Pseudo Header
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Zeros    |    Protocol    |          TCP Length           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                         TCP Header
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

1)TCP Header Making
For making TCP header, the program should know the following parameters: destination port, source port, TCP flags, TCP payload, window size and so on. The destination port will be 80, and the source port will be a random number from 1025 to 65536 by using random model in Python. TCP flags is varying depending on different situation. TCP payload will be HTTP header, otherwise it will be empty, like sending a ACK or FIN. For making checksum for TCP header, the program first need to calculate the pseud TCP header, which contains source IP, destination IP, protocol and TCP length part, then put pseudo TCP header and TCP segment together to calculate checksum. The most important part is sequence number and ACK. They will be calculated depend on the payload.

2)TCP Header Extracting
In TCP segment, sequence number, ACK number and TCP flags are important information, they will be extracted from segment and passed to upper layer. Other parameters, like TCP offset, port number, will be used to check whether the segment is right one inside the function, and they won°Øt be passed to upper layer.

3)Out of Order Package Handling
The program has a small buff for out of order packages. The program has a pointer, pointing to the latest packages. When out of order package come, program will buff it and send back ACK which the pointer points to. However, there will be a °∞gap°± between out of order package and the point. Once the gap is filled, the pointer will move to latest ACK package. 

4)Congestion Window
Congestion window begin at 1. After each successful ACK, congestion window will increase 1. For time out, its value goes back to 0 and maximum is under 1000. If the program cannot receive the right package within 60 seconds, it will be considered as time out.


3.Network Layer (IP)

                          IP Header
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

1)IP Header Making
The parameter new for here is IP identification number. At beginning, the program will generate a random number. Every time sending package, IP identification number will plus 1. 64 is enough for TTL.

2)IP Datagram Receiving
For receiving the IP datagram, the program will check the source and destination IP, and then check whether it is fragment. 

4.Data Link Layer (Ethernet)

To send a packet through ethernet frame MAC address of the destination(next_hop) should be found before sending the packet on wire. So we constructed a ARP request frame using all the parameters mentioned below and created and sent as broadcast with request for MAC address of the gateway IP address. Once a reply is received from the gateway IP it is processed and given as Destination MAC for subsequent ARP frames sent for TCP connection, data collection and close the connection.

1)ARP
				ARP Header
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Hardware Type          |        Protocol Type          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Mac Addr len | Proto Addr len|       Operation Code          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Sender Mac Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  			Sender IP                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Mac Address                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Target IP                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

2)Ethernet Header Making

The Ethernet header is constructed for each packet and combined with rest of the headers and data sent to the gateway and will be handled by the gateway with subsequent next hop MAC addresses till destination. We faced problems in constructing the packets and defragmenting the packet from hex to real value. The ARP Request and Reply part was made possible by reading through the structure and they didn’t have checksum part similar to IP and TCP. So we followed the same methodology in constructing TCP and IP in this and completed the packet. Created RAW socket and used receiving socket to filter out only IP packets(0x0800) to the Upper layer.

3)Ethernet Frame Extracting

Because we have good upper layer filter, like source/destination IP filter at Network Layer, source/destination port and sequence/acknowledge number filter at Transport Layer, also nowadays switches just broadcast package at first time, the information in Ethernet frame is useless for the program. The program just removes the Ethernet header, which commonly is 14 bytes, and padding bytes which will be added when frame is less than minimum size, and pass the Ethernet payload to upper layer.


5.Program Using
Makefile gives the permission for the programs in the folder. rawhttpget.py is the main program. rawhttpget is shell script to set up the firewall and pass the parameter from command line to Python program.