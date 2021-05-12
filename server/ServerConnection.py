from scapy.contrib.modbus import ModbusADURequest
from serverlog import log
import socket

class ServerConnection():
    def __init__(self, buf_size, port):
        
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.buf_size = buf_size

        self.s.bind(('', port))
        self.s.listen()

        log.info('socket binded to {}'.format(port))

    
    def wait_for_client(self):
        log.info('waiting for a new client...')
        c, addr = self.s.accept()
        self.conn = c

        log.debug('connection established with {}:{}'.format(addr[0], addr[1]))
    
    def mbreceive(self):
        log.debug('receiving packets')
        raw_pkt = self.conn.recv(self.buf_size)
        
        if not raw_pkt:
            return None 
        return ModbusADURequest(raw_pkt)
    
    def mbsend(self, mbresponse):
        self.conn.send(bytes(mbresponse))
    
    def close(self):
        self.s.close()



