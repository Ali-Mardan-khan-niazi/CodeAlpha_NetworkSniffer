			CodeAlpha Task 1 - Basic Network Sniffer
		    (Internship project for CodeAlpha Cyber Security)

What this project does?

 This Python program captures network packets on the local computer and shows:

- time
- protocol (TCP, UDP, ICMP)
- source IP
- destination IP
- ports
- a short payload note

It uses Scapy. On Windows it also needs Npcap.

How to run?

1. Install Python 3
2. Install Npcap from https://npcap.com
3. Open Command Prompt as Administrator
4. Install requirements:

```bash
pip install -r requirements.txt

5. Run:
```bash
python sniffer.py

Press Ctrl+C to stop early. The program also stops after 40 packets.

Important:
Use this only on your own computer or your own network. Do not capture other people's traffic.

What I learned:
- How IP packets are structured
- Difference between TCP, UDP, and ICMP
- Why HTTPS payload looks encrypted
- How to capture packets with Python and Scapy

Author

ALI_MARDAN_KHAN_NIAZI
CodeAlpha Cyber Security Internship