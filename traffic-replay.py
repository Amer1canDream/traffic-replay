from scapy.all import *
from scapy_http import http
import threading
from time import sleep
import socket
import logging
import os
from threading import Thread

srcIP = os.environ['srcIP']
dstIP = os.environ['dstIP']
PORTS = os.environ['PORTS']

logging.basicConfig(filename="traffic-replay.log", level=logging.DEBUG)

class Sniffer(Thread):

    def __init__(self, sP, dP, interface="eth0"):

        super().__init__()
        self.sP = sP
        self.dP = dP
        self.SOCKETS = {}
        self.interface = interface

    def connect(self, connectID):

        logging.debug("Connect trying to {host}:{port}".format(host=dstIP, port=self.dP))

        try:

            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((dstIP, int(self.dP)))
            self.SOCKETS[connectID] = self.conn
            self.SOCKETS[connectID].setblocking(0)
            logging.debug("Connection established {host}:{port}".format(host=dstIP, port=self.dP))

        except:

            logging.debug("Cant connect to {host}:{port}".format(host=dstIP, port=self.dP))

    def run(self):

        logging.info("Start sniffing... {port}".format(port=self.sP))
        sniff(iface=self.interface,
              filter="tcp and dst host {dstHost} and dst port {dstPort}".format(dstHost=srcIP, dstPort=self.sP),
              prn=self.getData, store=0)

    def getData(self, packet):

        connectID = str(packet.getlayer(IP).src) + ':' + str(packet.getlayer(TCP).sport)

        if connectID not in self.SOCKETS:
            self.connect(connectID=connectID)

        if packet.getlayer(TCP).flags.F and connectID in self.SOCKETS:
            logging.debug("FIN flag {id} connection closed".format(id=connectID))
            self.SOCKETS[connectID].close()
            del self.SOCKETS[connectID]

        if packet.getlayer(Raw) and connectID in self.SOCKETS:

            data = bytes(packet.getlayer(Raw))

            try:

                self.SOCKETS[connectID].send(data)
                d = self.SOCKETS[connectID].recv(1500)

            except:

                logging.debug("Connection refused   {host}:{port} ".format(host=dstIP, port=self.dP))

        print(self.SOCKETS)

for ports in PORTS:
    Sniffer(ports[0], ports[1]).start()
    print('src: ' + srcIP + ':' + ports[0])
    print('dst: ' + dstIP + ':' + ports[1])
