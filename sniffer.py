import scapy.all as scapy

from scapy.layers import http




def sniffer(interface): 
    print("-----------------------------------")
    print("[+] * Sniffer Has Started...! * [+]")
    print("-----------------------------------")
    
    scapy.sniff(iface=interface, store=False, prn=process)





def process(packet):

    if packet.haslayer(http.HTTPRequest):
 
        print("[+] ",packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path) 
       
        if packet.haslayer(scapy.Raw):
       
            request  = packet[scapy.Raw].load 
            
            print("[*_*] ->->->->-> ",request)

sniffer("eth0")
