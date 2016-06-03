from scapy.all import *
import subprocess
import re

gateway_ip = None
gateway_mac = None

# command to find default gateway mac
route = subprocess.check_output(['route', '-n'])

# extract mac
for _ in route.split('\n'):
  # up and is gateway
  if "UG" in _:
    gateway_ip = re.split('[\s]+', _)[1]
    break

# command to find default gateay ip based on mac
arp = subprocess.check_output(['arp', '-a', '-n'])

for _ in arp.split('\n'):
  if '({})'.format(gateway_ip) in _:
    gateway_mac = re.split('[\s]+', _)[3]
    break

print 'IP: {} MAC: {}'.format(gateway_ip, gateway_mac)

# sniffer's callback
def callback(pkt):
  # op 2 is 'is-at', mismatch between new mac and old 
  if ARP in pkt and pkt[ARP].op == 2 and pkt[ARP].psrc == gateway_ip and pkt[ARP].hwsrc != gateway_mac:
    print '[*] ARP poisoning detected. MAC: {}'.format(pkt[ARP].hwsrc)
    check_attacker(pkt[ARP].hwsrc)

# try to figure out attacker's identity from arp cache
def check_attacker(mac):
  arp = subprocess.check_output(['arp', '-a', '-n'])
  for line in arp.split('\n'):
    # gateway ip is not candidate for attacker
    if mac in line and gateway_ip not in line:
      line = re.split('[)(\s]+', line)
      print '[*] Attacker has ip {} => {}'.format(line[1], line[3])

# sniff for all ARP packets
sniff(filter='arp', prn=callback, store=0)
