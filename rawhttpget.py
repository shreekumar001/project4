#!/usr/bin/python
import struct, socket, sys, random, re, time, os, uuid, binascii

#############################################################
# Socket set up
global sock_sed, sock_rev
try:
    sock_sed = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock_sed.bind(('eth0', 0))
    sock_rev = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0800))
except:
    print "Cannot open sockets"
    sys.exit()

#############################################################
global cnwd
cnwd = 1
#Status 1, get ACK cnwd+1; Status 2, package drop or time out, cnwd
def CNWDControl(status):
    global cnwd
    if status == 1 and cnwd < 1000:
        cnwd = cnwd + 1
    if status == 0:
        cnwd = 1

#############################################################
#timer
global timer
timer = time.time()
def timeout():
    global timer
    if time.time() > (timer + 60):
        print "time out"
        CNWDControl(0)
        sys.exit()

#############################################################
# find next hop Ip address
def Nexthop_ip():
    try:
        next_hop = os.popen('route -n | grep UG | awk -F" " \'{print $2}\'')
        next_hop = next_hop.read()
        next_hop = next_hop[:-1]
        return next_hop
    except:
        print "No Nexthop IP address"
        sys.exit()
def transfernumtomac(macnum):
    chrmac = ""
    for i in range(0,6):
        chrmac= chr(macnum & 0xff) + chrmac
        macnum = macnum/0x100
    return chrmac

#############################################################
# Make ARP request header
def arp_request(htype,ptype,hlen,iplen,opcode,src_mac,dst_mac,src_ip,dst_ip):
    arp_frame = struct.pack('!HHBBH6s4s6s4s',htype,ptype,hlen,iplen,opcode,src_mac,src_ip,dst_mac,dst_ip)
    return arp_frame

#############################################################
# Make ethernet packet header
def eth_packet(src,dst,proto,data):
    eth_frame = struct.pack('!6s6sH',dst,src,proto)+data
    return eth_frame

#############################################################
def get_mac(sip,gw_ip):
    # ARP structure
    ARP_REQUEST = 1
    ARP_REPLY = 2
    hard_type = 0x0001
    proto = 0x0800
    header_len = 6
    ip_len = 4
    src_mac = source_mac
    dest_mac = transfernumtomac(0)
    brd_mac = transfernumtomac(0xffffffffffff)
    src_ip = sip
    dest_ip = gw_ip
        
    #set send and recv scokets
    s_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s_sock.bind(('eth0', 0))
    r_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
    r_sock.setblocking(0)
    r_sock.settimeout(10)
        
    # create arp packet and send through raw socket
    arp_req = arp_request(hard_type,proto,header_len,ip_len,ARP_REQUEST,src_mac,dest_mac,src_ip,dest_ip)
    req_frame = eth_packet(src_mac,brd_mac, 0x0806,arp_req)
    s_sock.sendto(req_frame,('eth0', 0))
        
    # receive raw_ frame from the raw_socket and extract ethernet header
    raw_frame = r_sock.recv(4096)
    dst, src, proto = struct.unpack('!6s6sH', raw_frame[:14])
    data = raw_frame[14:]
    source = binascii.hexlify(src)
    destination = binascii.hexlify(dst)
        
    # extract arp reply
    hard_type,proto,header_len,ip_len,opcode,gw_mac,gw_ip,dest_mac,dest_ip = struct.unpack('!HHBBH6s4s6s4s',data[:28])
        
    # format src mac,ip and dest mac,ip
    gw_mac = binascii.hexlify(gw_mac)
    g_mac = transfernumtomac(int(gw_mac,16))
    return g_mac


##############################################################
#Get Source IP, Destination IP, FileName and HTTPHeader
global IPSrc, IPDes
def GetIPSrc():
    try:
        sock = socket.socket (socket.AF_INET,socket.SOCK_DGRAM)
        sock.connect(("david.choffnes.com",80))
        IPSrc = sock.getsockname()[0]
    except:
        print "Cannot get the Source IP"
        sys.exit()
    del sock
    return IPSrc

def HTTPMaker (url):
    URL = url
    URL = URL.split("/")
    Location = ""
    if URL[0].lower() != "http:" or len(URL)<3 or URL[2] == "" or URL[1] != "":
        print "Invalid URL, Please input it again"
        sys.exit()
    else:
        HostName = URL[2]
    if len(URL) == 3 or (len(URL) == 4 and URL[3] == ""):
        FileName = "index.html"
        Location = "index.html"
    else:
        if len(URL) > 3:
            for i in range(0,len(URL)-3):
                if URL[i+3] != "":
                    Location = Location + "/" + URL[i+3]
                else:
                    if (i + 3) < (len(URL) - 1):
                        print "URL format problem"
                        sys.exit()
            if url[-1] == "/":
                Location = Location + "/"
            if URL[-1] == "":
                FileName = URL[-2]
            else:
                FileName = URL[-1]
    try:
        HostIP = socket.gethostbyname(HostName)
    except:
        print"Invalid URL"
        sys.exit()
    
    HTTPline1 = "GET " + Location + " " + "HTTP/1.1" + "\r\n"
    HTTPline2 = "Host:" + HostName + "\r\nAccept: text/html\r\nAccept-Language: en-US,en\r\n"
    HTTPline3 = "Connection: keep-alive\r\n\r\n"
    HTTPHeader = HTTPline1 + HTTPline2 + HTTPline3
    return (HTTPHeader,HostIP,FileName)

WebURL = sys.argv[1]
IPSrc = GetIPSrc()
HTTPHeader,IPDesn,FileName = HTTPMaker(WebURL)
IPSrc = socket.inet_aton(IPSrc)
IPDes = socket.inet_aton(IPDesn)
gw_ip = socket.inet_aton(Nexthop_ip())
source_mac = transfernumtomac(uuid.getnode())
destination_mac = get_mac(IPSrc,gw_ip)
#print destination_mac

##############################################################
#Set TCP source port, destination port and IP identification number
global IPIDnum,TCPSrcPort,TCPDesPort
IPIDnum = random.randint(0,65535)
TCPSrcPort = random.randint(1025,65535)
TCPDesPort = 80
def IPIDnumPlus():
    global IPIDnum
    if IPIDnum == 65535:
        IPIDnum = 0
    else:
        IPIDnum = IPIDnum + 1

##############################################################
#Functions for making package

def checksum (header,ifcheck=0,packagetype=1):
    if ifcheck != 0:
        if packagetype == 1:
            CheckPosition = 10    #IP Header Checksum Position
        elif packagetype == 2:
            CheckPosition = 28
        else:
            pass #error information
        HeaderCheck = (ord(header[CheckPosition]) << 8) + ord(header[CheckPosition+1])
        header = header[0:CheckPosition] + chr(0)*2 + header[CheckPosition+2:]
    if len(header)%2 == 1:
        header = header + chr(0)
    Check = 0
    for i in range (0,len(header)/2):
        #print hex(( ord(header[i*2]) << 8 ) + ord(header[i*2+1]))
        Check = Check + (( ord(header[i*2]) << 8 ) + ord(header[i*2+1]))
    while 1:
        tmp = Check
        if (Check >> 16) == 0:
            break
        else:
            Check = (tmp & 0xffff) + (tmp >> 16)
    if ifcheck == 0:
        Check = ~Check & 0xffff
        return Check
    else:
        tmp = Check + HeaderCheck
        Check = (tmp & 0xffff) + (tmp >> 16)
        if Check == 0xffff:
            return 1
        else:
            return 0

def PackageSed (tcpseq,tcpack,tcpflags,data=""):
    ##########################################################
    #TCP Header Maker
    #tcpflags have 5 elements, ACK, PSH, RST, SYN and FIN
    global sock_sed
    global IPIDnum,TCPSrcPort,TCPDesPort,IPSrc,IPDes
    TCPFifthHex = 6
    TCPSeq = tcpseq
    TCPACK = tcpack
    TCPDoff = 5
    TCPFack, TCPFpsh, TCPFrst, TCPFsyn, TCPFfin = tcpflags
    TCPWinSize = 2048
    TCPChecksum = 0
    TCPUrgent = 0
    SeventhHex = (TCPDoff << 12) + (TCPFack << 4) + (TCPFpsh << 3) + (TCPFrst << 2) + (TCPFsyn << 1) + TCPFfin
    TCPHeader = struct.pack("!HHLLHHHH",TCPSrcPort,TCPDesPort,TCPSeq,TCPACK,SeventhHex,TCPWinSize,TCPChecksum,TCPUrgent)
    TCPPseudoHeader = struct.pack("!4s4sHH",IPSrc,IPDes,TCPFifthHex,len(TCPHeader + data))
    TCPChecksum = checksum(TCPPseudoHeader + TCPHeader + data,0,2)
    TCPHeader = struct.pack("!HHLLHHHH",TCPSrcPort,TCPDesPort,TCPSeq,TCPACK,SeventhHex,TCPWinSize,TCPChecksum,TCPUrgent)
    TCPPackage = TCPHeader + data
    ##########################################################
    #IP Header Maker
    IPVersion = 4
    IPIHL = 5
    IPServ = 0
    IPLen = len(TCPPackage) + IPIHL * 4
    IPFlag = 2
    IPFrag = 0
    IPTTL = 64
    IPProtocol = 6
    IPChecksum = 0
    FirstHex = (IPVersion << 12) + (IPIHL << 8) + IPServ
    ForthHex = (IPFlag << 13) + IPFrag
    FifthHex = (IPTTL << 8) + IPProtocol
    IPHeader = struct.pack("!HHHHHH4s4s",FirstHex,IPLen,IPIDnum,ForthHex,FifthHex,IPChecksum,IPSrc,IPDes)
    IPChecksum = checksum (IPHeader,0,1)
    IPHeader = struct.pack("!HHHHHH4s4s",FirstHex,IPLen,IPIDnum,ForthHex,FifthHex,IPChecksum,IPSrc,IPDes)
    data = IPHeader + TCPPackage
    protocol = 0x0800
    Frame = eth_packet(source_mac,destination_mac,protocol,data)
    sock_sed.sendto(Frame,('eth0', 0))
    IPIDnumPlus()
    return

##############################################################
#Functions for receiving package
def PackageRev():
    global sock_rev,TCPSrcPort,TCPDesPort,IPDes,timer
    while 1:
        data = sock_rev.recvfrom(65535)
        #Extract Ethernet Header
        Data = data[0][14:]
        #Extract IP Header and check
        if Data[12:16] != IPDes or ord(Data[9]) != 6:
            continue
        IPIHL = ord(Data[0]) & 0x0f
        IPHeaderLen = IPIHL * 4
        IPLen = (ord(Data[2]) << 8) + ord(Data[3])
        IPHeader = Data[0:IPHeaderLen]
        if checksum(IPHeader,1,1) == 0:
            continue
        IPID = (ord(Data[4]) << 8) + ord(Data[5])
        #Extract TCP Header and check
        TCPPseudoHeader = Data[12:20] + struct.pack("!HH",6,IPLen-IPHeaderLen) + Data[IPHeaderLen:IPLen]
        if checksum(TCPPseudoHeader,1,2) == 0:
            continue
        RevTCPSrcPort,RevTCPDesPort,TCPSeq,TCPACK,SeventhHex,TCPWinSize = struct.unpack("!HHLLHH",Data[IPHeaderLen:IPHeaderLen+16])
        if RevTCPDesPort != TCPSrcPort or RevTCPSrcPort != TCPDesPort:
            continue
        break
        timeout()
    TCPDoff = SeventhHex >> 12
    TCPHeaderLen = TCPDoff * 4
    PackageInfo = Data[IPHeaderLen + TCPHeaderLen: IPLen]
    TCPFfin = SeventhHex & 0x01
    TCPFsyn = (SeventhHex >> 1) & 0x01
    TCPFack = (SeventhHex >> 4) & 0x01
    timer = time.time()
    return (TCPSeq,TCPACK,TCPFsyn,TCPFack,TCPFfin,PackageInfo)

##############################################################
#Three Way Handshake
global TCPSeq,TCPACK
def HandShake(httpheader):
    global TCPSeq, TCPACK
    TCPSeq = random.randint(0,0xffffffff)
    TCPACK = 0
    PackageSed(TCPSeq,TCPACK,(0,0,0,1,0))
    RevTCPSeq,RevTCPACK,TCPFsyn,TCPFack,TCPFfin,PackageInfo = PackageRev()
    CNWDControl(1)
    TCPACK = RevTCPSeq + 1
    TCPSeq = RevTCPACK
    PackageSed(TCPSeq,TCPACK,(1,0,0,0,0))
    PackageSed(TCPSeq,TCPACK,(1,0,0,0,0),httpheader)
    TCPSeq = TCPSeq + len(httpheader)
    #Dont forget to check next sequence number
    return

##############################################################
#Write WebPage to a file
def WebCheck (filename,webpage):
    global chunk
    #Get HTTP status
    FileName = filename
    DataPoint = open (FileName,"w")
    HTTPStatus = re.findall(r"HTTP/1.1 (\d+) ",webpage)
    if len(HTTPStatus) != 1 or HTTPStatus[0] != "200":
        print "HTTP Status is not 200: requested page not available"
        sys.exit()
    HTTPHeaderLen = webpage.index("\r\n\r\n")
    if chunk == 1:
        WebPage = webpage[HTTPHeaderLen+2:]
        HTTPChunk = re.findall("\r\n.+?\r\n",WebPage)
        for i in HTTPChunk:
            WebPage = WebPage.replace(i,"")
        DataPoint.write(WebPage[:-2])
    else:
        WebPage = webpage[HTTPHeaderLen+4:]
        DataPoint.write(WebPage)
    DataPoint.close()

##############################################################
#Main Program
global chunk
chunk = 0
WebPage = ""

HandShake(HTTPHeader)

#Send the HTTP Request and get HTTP Header
while 1:
    RevTCPSeq,RevTCPACK,TCPFsyn,TCPFack,TCPFfin,PackageInfo = PackageRev()
    if RevTCPACK != TCPSeq or RevTCPSeq != TCPACK:
        PackageSed(TCPSeq-len(HTTPHeader),TCPACK,(1,0,0,0,0))
        continue
    else:
        if len(PackageInfo)<10:
            continue
        CNWDControl(1)
        TCPACK = TCPACK + len(PackageInfo)
        PackageSed(TCPSeq,TCPACK,(1,0,0,0,0))
        WebPage = WebPage + PackageInfo
        if len(re.findall("chunked\r\n",PackageInfo)) > 0:
            chunk = 1
            break
        else:
            chunk = 0
            break

#Receive the rest of the packages
while 1:
    RevTCPSeq,RevTCPACK,TCPFsyn,TCPFack,TCPFfin,PackageInfo = PackageRev()
    if RevTCPACK != TCPSeq or RevTCPSeq != TCPACK:
        PackageSed(TCPSeq,TCPACK,(1,0,0,0,0))
        continue
    else:
        CNWDControl(1)
        TCPACK = TCPACK + len(PackageInfo)
        WebPage = WebPage + PackageInfo
        if chunk == 1:
            PackageSed(TCPSeq,TCPACK,(1,0,0,0,0))
            EndPoint = re.findall ("\r\n0\r\n",PackageInfo)
            if len(EndPoint) > 0:
                PackageSed(TCPSeq,TCPACK,(1,0,0,0,1))
                while 1:
                    RevTCPSeq,RevTCPACK,TCPFsyn,TCPFack,TCPFfin,PackageInfo = PackageRev()
                    if RevTCPACK != (TCPSeq + 1) or RevTCPSeq != TCPACK:
                        continue
                    else:
                        TCPSeq = RevTCPACK
                        PackageSed(TCPSeq,TCPACK+1,(1,0,0,0,0))
                        #RevTCPSeq,RevTCPACK,TCPFsyn,TCPFack,TCPFfin,PackageInfo = PackageRev()
                        break
                break
        if chunk == 0:
            if TCPFfin == 1:
                PackageSed(TCPSeq,TCPACK,(1,0,0,0,1))
                RevTCPSeq,RevTCPACK,TCPFsyn,TCPFack,TCPFfin,PackageInfo = PackageRev()
                while 1:
                    if RevTCPACK != (TCPSeq + 1) or RevTCPSeq != (TCPACK + 1):
                        RevTCPSeq,RevTCPACK,TCPFsyn,TCPFack,TCPFfin,PackageInfo = PackageRev()
                        continue
                    else:
                        PackageSed(TCPSeq+1,TCPACK+1,(1,0,0,0,0))
                        break
                break
            else:
                PackageSed(TCPSeq,TCPACK,(1,0,0,0,0))
WebCheck (FileName,WebPage)