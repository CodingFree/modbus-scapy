import json
import logging

devices = {}


class Device:
    def __init__(self, ncoils, nregisters, ndcoils, niregisters):
        self.coils      = [0] * ncoils
        self.registers  = [0] * nregisters
        self.dcoils     = [0] * ndcoils # TODO change name to dinputs
        self.iregisters = [0] * niregisters

    def __get_range(self, start_addr, quantity, data):
        if start_addr + quantity > len(data):
            return None
        return data[start_addr: start_addr + quantity]

    def get_coils(self, start_addr, quantity):
        return self.__get_range(start_addr, quantity, self.coils)

    def get_dinputs(self, start_addr, quantity):
        return self.__get_range(start_addr, quantity, self.dcoils)
    
    def get_registers(self, start_addr, quantity):
        return self.__get_range(start_addr, quantity, self.registers)
    
    def get_iregisters(self, start_addr, quantity):
        return self.__get_range(start_addr, quantity, self.iregisters)

    def __merge_range(self, start_addr, array, subarray):
        for i in range(0, len(subarray)):
            array[start_addr + i] = subarray[i]

    def set_coils(self, start_addr, new_values):
        self.__merge_range(start_addr, self.coils, new_values)
    
    def set_coil(self, address, value):
        self.coils[address] = value

    def set_registers(self, start_addr, new_values):
        self.__merge_range(start_addr, self.registers, new_values)

    def set_register(self, address, value):
        self.registers[address] = value

def init_devices():

    while True:
        filename = input('load devices from > ')
        try:
            file = open(filename)
            data = json.load(file)

            for device in data:
                id = device['id']
                devices[id] = Device(0, 0, 0, 0)
                devices[id].coils = device['coils']
                devices[id].dcoils = device['dcoils']
                devices[id].registers = device['registers']
                devices[id].iregisters = device['iregisters']
        except FileNotFoundError:
            logging.error('file not found')
            continue
        except:
            logging.error('error tring to load data')
            continue
        break

def save_devices():

    filename = ''

    filename = input('save devices as (blank line to ignore) > ')

    if filename == '':
        return

    data = []
    for id, device in devices.items():
        entry = {}
        entry['id']         = id
        entry['coils']      = device.coils
        entry['dcoils']     = device.dcoils
        entry['registers']  = device.registers
        entry['iregisters'] = device.iregisters
        data.append(entry)

    with open(filename, 'w') as file:
        json.dump(data, file)
        logging.info('devices saved')
        
        



