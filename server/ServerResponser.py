"""This module generates the responses for a given request.
   It does NOT send the responses NEITHER receives them.    

"""



from abc import ABC, abstractmethod
from Device import *
from scapy.all import *
load_contrib('modbus')

from serverlog import log




class Responser(ABC):
    """Responser abstract class.

    Every 'modbus responser' class are inherited from this.

    """
    def make_mbresponse(self, query):
        """Function to generate the response for the given query

        Args:
            query: a modbus query
        
        Returns:
            A modbus response. Note that the response is not a complete
            package ready to be sent, it is just the modbus part, without tcp/ip.
        """

        log.debug('making response for transitions no. {}'.format(query.transId))
        
        self._load_query_data(query)
        data = ModbusADUResponse()
        data.unitId = query.unitId
        return data/self._make_response_tail()

    @abstractmethod
    def _load_query_data(self, query):
        pass

    @abstractmethod
    def _make_response_tail(self):
        pass
    
    def _illegal_device(self, error):
        log.error('illegal device')
        error.exceptCode = 11
        return error
    
    def _illegal_address(self, error):
        log.error('illegal address')
        error.exceptCode = 2
        return error
        

class ReadCoilsResponser(Responser):
    def _load_query_data(self, query):
        log.info('client requested read coils')
        self.unit_id     = query[ModbusADURequest].unitId
        self.start_addr  = query[ModbusADURequest].startAddr
        self.quantity    = query[ModbusADURequest].quantity

        log.debug('reading {} coils from address {} of device {}'.format(self.quantity, self.start_addr, self.unit_id))
    
    def _make_response_tail(self):
        global devices

        if self.unit_id not in devices:
            return self._illegal_device(ModbusPDU01ReadCoilsError())
        
        device = devices[self.unit_id]
        coils  = device.get_coils(self.start_addr, self.quantity)

        if coils == None:
            return self._illegal_address(ModbusPDU01ReadCoilsError())

        coils.reverse()
        
        # TODO do better
        tmp_value = int("".join(str(x) for x in coils), 2) #really need it?? a byte field would be better

        response = ModbusPDU01ReadCoilsResponse()
        response.coilStatus = [tmp_value]

        return response


class ReadDiscreteInputResponser(Responser):
    def _load_query_data(self, query):
        log.info('client requested read discrete inputs')
        self.unit_id     = query[ModbusADURequest].unitId
        self.start_addr  = query[ModbusADURequest].startAddr
        self.quantity    = query[ModbusADURequest].quantity

        log.debug('reading {} discrete inputs from address {} of device {}'.format(self.quantity, self.start_addr, self.unit_id))
    
    def _make_response_tail(self):
        global devices

        if self.unit_id not in devices:
            return self._illegal_device(ModbusPDU02ReadDiscreteInputsError())
        
        device = devices[self.unit_id]
        dinputs  = device.get_dinputs(self.start_addr, self.quantity)

        if dinputs == None:
            return self._illegal_address(ModbusPDU02ReadDiscreteInputsError())

        dinputs.reverse()
        
        # TODO do better
        tmp_value = int("".join(str(x) for x in dinputs), 2) #really need it?? a byte field would be better

        response = ModbusPDU02ReadDiscreteInputsResponse()
        response.inputStatus = [tmp_value]

        return response


class ReadHoldingRegisterResponser(Responser):
    def _load_query_data(self, query):
        log.info('client requested to read register values')
        self.unit_id     = query[ModbusADURequest].unitId
        self.start_addr  = query[ModbusADURequest].startAddr
        self.quantity    = query[ModbusADURequest].quantity

        log.debug('reading {} register values from address {} of device {}'
                        .format(self.quantity, self.start_addr, self.unit_id))

    
    def _make_response_tail(self):
        global devices

        if self.unit_id not in devices:
            return self._illegal_device(ModbusPDU03ReadHoldingRegistersError())

        device = devices[self.unit_id]
        registers  = device.get_iregisters(self.start_addr, self.quantity)

        if registers == None:
            return self._illegal_address(ModbusPDU03ReadHoldingRegistersError())

        response = ModbusPDU03ReadHoldingRegistersResponse()
        response.registerVal = registers
        return response

class ReadInputRegisterResponser(Responser):
    def _load_query_data(self, query):
        log.info('client requested to read register values')
        self.unit_id     = query[ModbusADURequest].unitId
        self.start_addr  = query[ModbusADURequest].startAddr
        self.quantity    = query[ModbusADURequest].quantity

        log.debug('reading {} register values from address {} of device {}'
                        .format(self.quantity, self.start_addr, self.unit_id))

    
    def _make_response_tail(self):
        global devices

        if self.unit_id not in devices:
            return self._illegal_device(ModbusPDU04ReadInputRegistersError())

        device = devices[self.unit_id]
        registers  = device.get_registers(self.start_addr, self.quantity)

        if registers == None:
            return self._illegal_address(ModbusPDU04ReadInputRegistersError())

        response = ModbusPDU04ReadInputRegistersResponse()
        response.registerVal = registers
        return response


class WriteSingleCoilResponser(Responser):
    def _load_query_data(self, query):
        log.info('client requested to write single coil')

        self.unit_id  = query[ModbusADURequest].unitId
        self.address  = query[ModbusADURequest].outputAddr
        self.value    = query[ModbusADURequest].outputValue

        if self.value == 0xff00:
            self.value = 1
        
    
    def _make_response_tail(self):
        global devices

        if self.unit_id not in devices:
            return self._illegal_device(ModbusPDU05WriteSingleCoilError())
        device = devices[self.unit_id]
        
        if self.address >= len(device.coils):
            return self._illegal_address(ModbusPDU05WriteSingleCoilError())
        
        device.set_coil(self.address, self.value)

        
        response = ModbusPDU05WriteSingleCoilResponse()
        response.outputValue = self.value
        response.outputAddr  = self.address

        return response

class WriteSingleHoldingRegister(Responser):
    def _load_query_data(self, query):
        log.info('client requested to write single register')
        self.unit_id  = query[ModbusADURequest].unitId
        self.address  = query[ModbusADURequest].registerAddr
        self.value    = query[ModbusADURequest].registerValue

        if self.value == 0xff00:
            self.value = 1
        
    
    def _make_response_tail(self):
        global devices

        if self.unit_id not in devices:
            return self._illegal_device(ModbusPDU06WriteSingleRegisterError())

        device = devices[self.unit_id]

        if self.address >= len(device.registers):
            return self._illegal_address(ModbusPDU06WriteSingleRegisterError())

        device.set_register(self.address, self.value)

        response = ModbusPDU06WriteSingleRegisterResponse()
        response.registerAddr  = self.address
        response.registerValue = self.value

        return response


class WriteMultipleCoils(Responser):
    def _load_query_data(self, query):
        log.info('client requested to write multiple coils')
        self.unit_id  = query.unitId
        self.start_addr  = query.startAddr
        quant = query.quantityOutput

        outputs_value = query.outputsValue[0]
        data   = [int(i) for i in list('{0:0b}'.format(outputs_value))]
        data.reverse()
        data = data +  [0] * (quant - len(data))
        self.values = data
    
    def _make_response_tail(self):
        global devices

        if self.unit_id not in devices:
            return self._illegal_device(ModbusPDU0FWriteMultipleCoilsError())
        
        device = devices[self.unit_id]

        if self.start_addr + len(self.values) >= len(device.registers):
            return self._illegal_address(ModbusPDU0FWriteMultipleCoilsError())

        device.set_coils(self.start_addr, self.values)

        response = ModbusPDU0FWriteMultipleCoilsResponse()
        return response

class WriteMultipleRegisters(Responser):
    def _load_query_data(self, query):
        log.info('client requested to write multiple registers')
        self.unit_id  = query[ModbusADURequest].unitId
        self.start_addr  = query[ModbusADURequest].startAddr
        self.values   = query[ModbusADURequest].outputsValue
    
    def _make_response_tail(self):
        global devices

        if self.unit_id not in devices:
            return self._illegal_device(ModbusPDU10WriteMultipleRegistersError())
        
        device = devices[self.unit_id]

        if self.start_addr + len(self.values) >= len(device.registers):
            return self._illegal_address(ModbusPDU10WriteMultipleRegistersError())

        device.set_registers(self.start_addr, self.values)

        response = ModbusPDU06WriteSingleRegisterResponse()
        response.show()

        return response