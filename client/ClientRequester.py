from abc import ABC, abstractmethod
from scapy.contrib.modbus import *

from scapy.all import *

transition_number = 0

class ClientRequester(ABC):

    def make_request(self, unit_id):
        global transition_number 
        
        self.query = self._input() 

        transition_number = transition_number + 1
        self.query.transId = transition_number
        request = ModbusADURequest()/self.query
        request.unitId  = unit_id
        
        return request
    
    def _error_message(self, mberror_data):
        print('Something wrong happened. Error code: {}'.format(mberror_data.exceptCode))
    
    @abstractmethod
    def _input(self, query):
        pass
    
    @abstractmethod
    def show_response(self, mbresponse):
        pass


class ReadCoils(ClientRequester):
    def _input(self):
        mbquery = ModbusPDU01ReadCoilsRequest()
        start = int(input('Enter start address: '))
        # quant will be usefull later (see show())
        self.quant = int(input('Enter quantity     : '))

        mbquery.startAddr = start
        mbquery.quantity  = self.quant
        return mbquery
    
    def show_response(self, mbresponse):
        if ModbusPDU01ReadCoilsError in mbresponse:
            self._error_message(mbresponse)
            return 

        coil_status = mbresponse.coilStatus[0]
        data = [int(i) for i in list('{0:0b}'.format(coil_status))]
        data.reverse()
        data = data +  [0] * (self.quant - len(data))
        print(data)
    

class ReadDiscreteInput(ClientRequester):
    def _input(self):
        mbquery = ModbusPDU02ReadDiscreteInputsRequest()
        start = int(input('Enter start address: '))
        # quant will be usefull later (see show_response())
        self.quant = int(input('Enter quantity     : '))

        mbquery.startAddr = start
        mbquery.quantity  = self.quant
        return mbquery
    
    def show_response(self, mbresponse):
        if ModbusPDU02ReadDiscreteInputsError in mbresponse:
            self._error_message(mbresponse)
            return

        input_status = mbresponse.inputStatus[0]
        data = [int(i) for i in list('{0:0b}'.format(input_status))]
        data.reverse()
        data = data +  [0] * (self.quant - len(data))
        print(data)


class ReadHoldindRegisters(ClientRequester):
    def _input(self):
        mbquery = ModbusPDU03ReadHoldingRegistersRequest()
        start = int(input('Enter start address: '))
        quant = int(input('Enter quantity     : '))

        mbquery.startAddr = start
        mbquery.quantity  = quant
        return mbquery
    
    def show_response(self, mbresponse):
        if ModbusPDU03ReadHoldingRegistersError in mbresponse:
            self._error_message(mbresponse)
            return
        print(mbresponse.registerVal)

class ReadInputRegisters(ClientRequester):
    def _input(self):
        mbquery = ModbusPDU04ReadInputRegistersRequest()
        start = int(input('Enter start address: '))
        quant = int(input('Enter quantity     : '))

        mbquery.startAddr = start
        mbquery.quantity  = quant
        return mbquery
    
    def show_response(self, mbresponse):
        if ModbusPDU04ReadInputRegistersError in mbresponse:
            self._error_message(mbresponse)
            return
        print(mbresponse.registerVal)

class WriteSingleCoil(ClientRequester):
    def _input(self):
        mbquery = ModbusPDU05WriteSingleCoilRequest()
        address   = int(input('address: '))
        
        while True:
            value = int(input('value  : '))
            if value == 0 or value == 1:
                if value == 1:
                    value = 0xff00
                break

            print('you are writing to a coil, value must to be 0 or 1')
    
        mbquery.outputAddr  = address
        mbquery.outputValue = value
        return mbquery
    
    def show_response(self, mbresponse):
        if ModbusPDU05WriteSingleCoilError in mbresponse:
            self._error_message(mbresponse)
            return
        print('value writed sucessfully')
    
class WriteSingleHoldingResgister(ClientRequester):
    def _input(self):

        mbquery = ModbusPDU06WriteSingleRegisterRequest()
        address = int(input('address: '))
        value   = int(input('value  : '))

        mbquery.registerAddr  = address
        mbquery.registerValue = value
        return mbquery
    
    def show_response(self, mbresponse):
        if ModbusPDU06WriteSingleRegisterError in mbresponse:
            self._error_message(mbresponse)
            return
        print('value writed sucessfully')

class WriteMultipleCoils(ClientRequester):
    def _input(self):
        mbquery = ModbusPDU0FWriteMultipleCoilsRequest()
        address  = int(input('start address: '))

        while True:
            try:
                values   = list(map(int, input('values       : ').split()))
                outputs_value = int("".join(str(x) for x in values), 2)
            except ValueError:
                print('invalid values')
                continue
            break

        mbquery.startAddr         = address
        mbquery.quantityOutput    = len(values)
        mbquery.outputsValue      = outputs_value
        return mbquery
    
    
    def show_response(self, mbresponse):
        if ModbusPDU0FWriteMultipleCoilsError in mbresponse:
            self._error_message(mbresponse)
            return
        print('values writed sucessfully')
    

class WriteMultipleRegisters(ClientRequester):
    def _input(self):
        mbquery = ModbusPDU10WriteMultipleRegistersRequest()
        address  = int(input('start address: '))
        values   = list(map(int, input('values       : ').split()))

        mbquery.startAddr         = address
        mbquery.quantityRegisters = len(values)
        mbquery.outputsValue      = values
        return mbquery
    
    def show_response(self, mbresponse):
        if ModbusPDU10WriteMultipleRegistersError in mbresponse:
            self._error_message(mbresponse)
            return
        print('values writed sucessfully')
    
    
