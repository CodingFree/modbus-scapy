#!/usr/bin/python3

from ClientConnection import ClientConnection
from ClientRequester import *
import configparser


config = configparser.ConfigParser()

config.read('client.ini')

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

timeout  = loadconfig_helper('tcp', 'timeout', None, True)
dst_port = loadconfig_helper('tcp', 'dst_port', 502, True)
buf_size = loadconfig_helper('tcp', 'dst_port', 1024, True) 

current_slave = None
connection    = None


def print_welcome():
    print('Welcome to the modubus master simulator!')
    print("Type 'help' to list all avaiable commands.")

def connect(argv):
    global connection
    global timeout
    global dst_port
    global buf_size

    if len(argv) != 2:
        print('usage: connect <server ip>')
        return
    connection = ClientConnection(argv[1], dst_port, timeout, buf_size)
    connection.connect()

def close(argv):
    global connection
    if connection != None:
        connection.close()

def quit(argv):
    close(argv)
    exit()

def help(argv):
    print('help          - list all avaiable commands')
    print('connect <ip>  - to connect to a server')
    print('slave         - select a slave')
    print('fun           - execute a modbus function')
    print('close         - close the connection to the server')
    print('quit          - exit the aplication')



def slave(argv):
    global current_slave

    if len(argv) != 2:
        print('usage: pick <slave id>')
        return

    current_slave = int(argv[1])

def fun(arvg):
    global tcp_ip
    global connection

    if len(argv) != 2:
        print('usage: fun <function code>')
        print('to list functions code do: fun help')
        return

    if argv[1] == 'help':
        print('code - name:')
        print('1    - Read Coils')
        print('2    - Read Discrete Input')
        print('3    - Read Holding Registers')
        print('4    - Read Input Registers')
        print('5    - Write Single Coil')
        print('6    - Write Single Holding Register')
        print('8    - Write multiple coils')
        print('9    - Write multiple resisters')

        return 

    code = int(argv[1])

    if code == 1:
        requester = ReadCoils()
    elif code == 2:
        requester = ReadDiscreteInput()
    elif code == 3:
        requester = ReadHoldindRegisters()
    elif code == 4:
        requester = ReadInputRegisters()
    elif code == 5:
        requester = WriteSingleCoil()
    elif code == 6:
        requester = WriteSingleHoldingResgister()
    elif code == 8:
        requester = WriteMultipleCoils()
    elif code == 9:
        requester = WriteMultipleRegisters()
    else:
        print("Invalid code. Use 'help' to list all avaiable funtions.")
    
    request = requester.make_request(current_slave)
    try:
        if connection == None:
            raise OSError
        connection.mbsend(request)
        response = connection.mbreceive()
        requester.show_response(response)
    except:
        print('Error! Check if the connection is on.')
        return



print_welcome()
while True:
    argv = input('> ').split()

    if len(argv) == 0:
        continue
    try:
        if argv[0] == 'connect':
            connect(argv)
        elif argv[0] == 'close':
            close(argv)
        elif argv[0] == 'help':
            help(argv)
        elif argv[0] == 'slave':
            slave(argv)
        elif argv[0] == 'fun':
            fun(argv)
        elif argv[0] == 'quit':
            quit(argv)
        else:
            print("No command named '{}' found!".format(argv[0]))
    except socket.timeout:
        # catch only this exception (the ther left for debugging proposes)
        print('Error: operation timeout')



