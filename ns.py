#!/usr/bin/env python
import scapy.all as scapy
import argparse
def get_agrument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t",dest="target",help="Target Ip / ip range")
    options = parser.parse_args()
    return options
def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    brodcst  = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_and_brodcst = brodcst/arp_req
    ip_mac_dict = []
    anslist = scapy.srp(arp_req_and_brodcst,timeout=1,verbose=False)[0]
    for element in anslist:
        ip_mac ={"ip":element[1].psrc,"mac":element[1].hwsrc}
        ip_mac_dict.append(ip_mac)
    return ip_mac_dict
def resul_print(result):
    print("IP\t\t\tMAC ADRESS\n--------------------------------------------")
    for client in result:
        print(client["ip"]+"\t\t"+client["mac"])



options = get_agrument()

sar = scan(options.target)
resul_print(sar)