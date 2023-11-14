from scapy.all import *
import time

def listen_dhcp(packet):
    # Fungsi untuk memantau paket DHCP
    target_mac, requested_ip, hostname, vendor_id = [None] * 4
    # Dapatkan alamat MAC yang meminta
    if packet.haslayer(Ether):
        target_mac = packet.getlayer(Ether).src
        dhcp_options = packet[DHCP].options
        # Dapatkan Opsi DHCP
        for item in dhcp_options:
            try:
                label, value = item
            except ValueError:
                continue
            # Dapatkan alamat IP yang diminta
            if label == "requested_addr":
                requested_ip = value
            # Dapatkan Nama Host dari perangkat
            elif label == "hostname":
                hostname = value.decode()
            # Dapatkan ID vendor
            elif label == "vendor_class_id":
                vendor_id = value.decode()
        # Jika semua variabel tidak None, cetak detail Perangkat
        if all([target_mac, vendor_id, hostname, requested_ip]):
            time_now = time.strftime("[%Y-%m-%d - %H:%M:%S]")
            print(f"{time_now} : {target_mac} - {hostname} / {vendor_id} meminta {requested_ip}")

if __name__ == "__main__":
    # Mendengarkan paket DHCP dan memprosesnya
    sniff(prn=listen_dhcp, filter="udp and (port 67 or 68)")
