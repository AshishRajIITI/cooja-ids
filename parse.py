from bs4 import BeautifulSoup
import subprocess

cmd = "tshark -T pdml -r test.pcap > pdmltest.xml"
p=subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=1, shell=True, universal_newlines=True)
p.wait()
file = open("pdmltest.xml", "r")
contents = file.read()
soup = BeautifulSoup(contents, 'xml')
packets = soup.find_all('packet')
count_ieee=0
count_udp=0
count_6lowpan=0
count_icmpv6=0
for packet in packets:
    frame=packet.find('proto',attrs={"name": "frame"})
    frame_protocol=packet.find('field',attrs={"name": "frame.protocols"})
    protocol= frame_protocol["show"]
    
    if protocol=="wpan:data":
        # IEEE 802.15.4
        # print("IEEE802.15.4")
        count_ieee+=1
    elif protocol=="wpan:6lowpan:ipv6:udp:data":
        # UDP
        # print("UDP")
        count_udp+=1
    elif protocol=="wpan:6lowpan:data":
        # 6LoWPAN
        # print("6LoWPAN")
        count_6lowpan+=1
    elif protocol=="wpan:6lowpan:ipv6:icmpv6":
        # ICMPv6
        # print("ICMPv6")
        count_icmpv6+=1
print("udp", count_udp)
print("ieee", count_ieee)
print("6low", count_6lowpan)
print("icmp", count_icmpv6)