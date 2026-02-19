from scapy.all import PcapReader, UDP, DNS

pcap = "/proj/softmeasure-PG0/CICD/organized/dns/attack_dns.pcap"

total = 0
dns = 0
udp53 = 0

with PcapReader(pcap) as r:
    for pkt in r:
        if pkt.haslayer(UDP):
            total += 1

            if pkt[UDP].dport == 53:
                udp53 += 1

            if pkt.haslayer(DNS):
                dns += 1

        if total >= 1000:
            break

print("UDP pkts (first 1000):", total)
print("UDP dport 53:", udp53)
print("DNS layers:", dns)
