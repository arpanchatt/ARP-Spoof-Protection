import scapy.all as scapy
import subprocess as sub
import time
import sys
import platform


def scanNetwork(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	broadcast_address = broadcast/arp_request
	answered = scapy.srp(broadcast_address,timeout=2, verbose=False)[0]
	return answered[0][1].hwsrc

def abolishConnection():
	print("[-] Disconnecting your network.......please wait for 30 seconds")
	if(os_platform == "Linux"):
		sub.call("ifconfig "+interface+" down", shell=True)
	if(os_platform == "Windows"):
		sub.call("netsh interface set interface "+interface+" disable")
	time.sleep(30)


def restoreConnection():
	print("[+] Restoring connection.......please wait")
	if(os_platform == "Linux"):
		sub.call("ifconfig "+interface+" up", shell=True)
	if(os_platform == "Windows"):
		sub.call("netsh interface set interface "+interface+" enable")
	time.sleep(2)
	print("[+] Connection Restored")

def catchPacket(interface):
	scapy.sniff(iface=interface, store=False, prn=detectSpoof)

def detectSpoof(packet):
	try:
		if(packet.haslayer(scapy.ARP) and packet['ARP'].op == 2):
			real_mac = scanNetwork(packet['ARP'].psrc)
			response_mac = packet['ARP'].hwsrc
			if(real_mac != response_mac):
				print("\n[+] Your System is under attack!!")
				abolishConnection()
				restoreConnection()
				catchPacket(interface)
	except IndexError:
		pass


os_platform = platform.system()

print("\n-----------Interfaces Available----------\n")
if(os_platform == "Linux"):
	sub.call("nmcli device status",shell=True)
elif(os_platform == "Windows"):
	sub.call("netsh interface show interface",shell=True)
try:
	interface = input("\nEnter the interface name from the following(state=connected): ")
	catchPacket(interface)
except ValueError:
	print("\nWrong interface entered")
	sys.exit
