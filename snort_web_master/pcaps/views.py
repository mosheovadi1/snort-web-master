from django.shortcuts import render

# Create your views here.


def verify_legal_pcap(filename):
    import dpkt
    counter = 0

    for ts, pkt in dpkt.pcap.Reader(open(filename, 'br')):

        counter += 1
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

    if not counter:
        return False
    return True
