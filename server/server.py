#!/usr/bin/python3

import time
import configparser
import sys
import signal

from ServerResponser import *
from ServerConnection import ServerConnection
from Device import save_devices, init_devices
from serverlog import log
from scapy.all import *
load_contrib('modbus')


config = configparser.ConfigParser()
config.read('server.ini')

def loadconfig_helper(key_major, key_minor, default_value, cast_to_int):
    global config
    try:
        result = config[key_major][key_minor]
    except:
        print("unable to load config entry '[{}][{}]'; using default '{}'".format(key_major, key_minor, default_value))
        result = default_value
    if cast_to_int == True:
        return int(result)
    return result

port      = loadconfig_helper('tcp', 'port', 502, True)
buf_size  = loadconfig_helper('tcp', 'buf_size', 1024, True) 
level_str = loadconfig_helper('log', 'level', 'debug', False)

if level_str == 'debug':
    logging.basicConfig(level = logging.DEBUG)

elif level_str == 'info':
    logging.basicConfig(level = logging.INFO)

elif level_str == 'warning':
    logging.basicConfig(level = logging.WARNING)

elif level_str == 'error':
    logging.basicConfig(level = logging.ERROR)


_devices_loaded = False # usefull in  signal_handling

def signal_handling(signum, frame):
    global connection
    if _devices_loaded == True:
        save_devices()
    log.info('closing server')
    exit(0)

signal.signal(signal.SIGINT, signal_handling) 

init_devices()
_devices_loaded = True

connection = ServerConnection(buf_size, port)




while True:
    # wait for a client
    connection.wait_for_client()

    while True:
        query = connection.mbreceive()

        if query == None:
            # wait for new client
            break

        mbresponse = None

        if ModbusADURequest in query:
            log.info('modbus request received')
            if ModbusPDU01ReadCoilsRequest in query:
                mbresponse = ReadCoilsResponser().make_mbresponse(query)
            
            elif ModbusPDU02ReadDiscreteInputsRequest in query:
                mbresponse = ReadDiscreteInputResponser().make_mbresponse(query)

            elif ModbusPDU03ReadHoldingRegistersRequest in query:
                mbresponse = ReadHoldingRegisterResponser().make_mbresponse(query)
            
            elif ModbusPDU04ReadInputRegistersRequest in query:
                mbresponse = ReadInputRegisterResponser().make_mbresponse(query)
            
            elif ModbusPDU05WriteSingleCoilRequest in query:
                mbresponse = WriteSingleCoilResponser().make_mbresponse(query)
            
            elif ModbusPDU06WriteSingleRegisterRequest in query:
                mbresponse = WriteSingleHoldingRegister().make_mbresponse(query)

            elif ModbusPDU10WriteMultipleRegistersRequest in query:
                mbresponse = WriteMultipleRegisters().make_mbresponse(query)

            elif ModbusPDU0FWriteMultipleCoilsRequest in query:
                mbresponse = WriteMultipleCoils().make_mbresponse(query)

            else:
                log.warning('the function requested by the client does not exist; ignoring it')
                continue
        
        if mbresponse != None:
            connection.mbsend(mbresponse)