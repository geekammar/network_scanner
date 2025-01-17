import scapy.all as scapy
import optparse



def network_scanner_parser():
    parser = optparse.OptionParser()
    parser.add_option("-r","--range",dest= "network_range",help="spacify network range you want to scan")
    option,argument = parser.parse_args()
    if not option.network_range :
        parser.error("\n[+] Usege: sudo python3 network_scanner.py -r <network range> \n[+] Example: sudo python3 network_scanner.py -r 1.2.3.4/24")
    return option


#172.31.44.105
def network_scaner(network_range):
    broadcast_ether = scapy.Ether(dst= "ff:ff:ff:ff:ff:ff")
    arp_request = scapy.ARP(pdst= str(network_range))
    arp_broadcast_request = broadcast_ether/arp_request
    responses = scapy.srp(arp_broadcast_request,timeout=1)
    return responses
    #print(arp_broadcast_request.summary)
    #print(responses)


def print_scaned(responses):
    live_machines = responses[0]
    print("ip \t\t\t  mac")
    print("-----------------------------------------")
    for machine in live_machines:
        print(machine[1].psrc + "\t\t" + machine[1].hwsrc)



network_range = network_scanner_parser()
#print(network_range.network_range)
scaned_machines = network_scaner(network_range.network_range)
print_scaned(scaned_machines)
