from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
from collections import Counter

print("=" * 72)
print(" CodeAlpha Task 1 - Basic Network Sniffer")
print(" Use only on this computer / your own Wi-Fi.")
print(" Press Ctrl+C to stop early.")
print("=" * 72)
print()

stats = Counter()
packet_no = 0

def is_mostly_text(data):
    if not data:
        return False
    good = 0
    for b in data:
        if 32 <= b <= 126 or b in (9, 10, 13):
            good += 1
    return (good / len(data)) >= 0.85

def payload_info(packet):
    if Raw not in packet:
        return "none"
    data = bytes(packet[Raw].load)
    if is_mostly_text(data):
        text = data[:40].decode("ascii", errors="replace")
        return "text: " + repr(text)
    return "binary/encrypted (" + str(len(data)) + " bytes)"

def process_packet(packet):
    global packet_no
    if IP not in packet:
        return

    packet_no += 1
    src = packet[IP].src
    dst = packet[IP].dst
    time = datetime.now().strftime("%H:%M:%S")

    if TCP in packet:
        proto = "TCP"
        extra = str(packet[TCP].sport) + " -> " + str(packet[TCP].dport)
    elif UDP in packet:
        proto = "UDP"
        extra = str(packet[UDP].sport) + " -> " + str(packet[UDP].dport)
    elif ICMP in packet:
        proto = "ICMP"
        extra = "control message"
    else:
        proto = "IP/" + str(packet[IP].proto)
        extra = "-"

    stats[proto] += 1

    print(f"{packet_no:02d} [{time}] {proto:4}  {src:15} -> {dst:15}  {extra}")
    print("    payload: " + payload_info(packet))

print("Capturing 40 packets...\n")
sniff(prn=process_packet, store=False, count=40, filter="ip")

print("\n" + "-" * 72)
print("Summary")
print("-" * 72)
print("Total packets shown:", sum(stats.values()))
for proto, n in stats.most_common():
    print(" ", proto + ":", n)
print("\nCapture finished.")