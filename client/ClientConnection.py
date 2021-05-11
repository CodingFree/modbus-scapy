from scapy.contrib.modbus import ModbusADUResponse
import logging


import socket

class ClientConnection():
    def __init__(self,  dst_ip, dst_port, timeout, buf_size):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(timeout)

        self.dst_port = dst_port
        self.dst_ip = dst_ip
        self.buf_size = buf_size

    
    def connect(self):
        self.s.connect((self.dst_ip, self.dst_port))
    
    def mbreceive(self):
        logging.debug('receiving packets')
        raw_pkt = self.s.recv(self.buf_size)
        return ModbusADUResponse(raw_pkt)

    def mbsend(self, mbresponse):
        self.s.send(bytes(mbresponse))
    
    def close(self):
        self.s.close()
