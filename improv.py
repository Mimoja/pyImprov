#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from enum import Enum

import logging

logger = logging.getLogger(name=__name__)


class ImprovCapabilities(Enum):
    IDENTIFY = 0x01


class ImprovError(Enum):
    NONE = 0x00
    INVALID_RPC = 0x01
    UNKNOWN_RPC = 0x02
    UNABLE_TO_CONNECT = 0x03
    NOT_AUTHORIZED = 0x04
    UNKNOWN = 0xFF


class ImprovState(Enum):
    STOPPED = 0x00
    AWAITING_AUTHORIZATION = 0x01
    AUTHORIZED = 0x02
    PROVISIONING = 0x03
    PROVISIONED = 0x04


class ImprovCommand(Enum):
    UNKNOWN = 0x00
    WIFI_SETTINGS = 0x01
    IDENTIFY = 0x02
    GET_CURRENT_STATE = 0x02
    GET_DEVICE_INFO = 0x03
    GET_WIFI_NETWORKS = 0x04
    BAD_CHECKSUM = 0xFF


class ImprovSerialType(Enum):
    CURRENT_STATE = 0x01
    ERROR_STATE = 0x02
    RPC = 0x03
    RPC_RESPONSE = 0x04


class ImprovUUID(Enum):
    SERVICE_UUID = "00467768-6228-2272-4663-277478268000"
    STATUS_UUID = "00467768-6228-2272-4663-277478268001"
    ERROR_UUID = "00467768-6228-2272-4663-277478268002"
    RPC_COMMAND_UUID = "00467768-6228-2272-4663-277478268003"
    RPC_RESULT_UUID = "00467768-6228-2272-4663-277478268004"
    CAPABILITIES_UUID = "00467768-6228-2272-4663-277478268005"


class ImprovProtocol:
    VERSION = 1

    def __init__(self, wifi_connect_callback, requires_authorization: bool = False) -> None:
        self.requires_authorization = requires_authorization
        if requires_authorization:
            self.state = ImprovState.AWAITING_AUTHORIZATION
        else:
            self.state = ImprovState.AUTHORIZED
        self.identify_callback = None
        self.wifi_connect_callback = wifi_connect_callback
        self.last_error = ImprovError.NONE
        self.rpc_response = b""

    def calculateChecksum(data: bytearray) -> int:
        calculated_checksum = 0
        for b in data:
            calculated_checksum += b
        return (calculated_checksum & 0xFF)

    def parse_improv_data(data: bytearray) -> tuple:
        """Boundschecks and Parses a raw bytearray into an RPC command

        Args:
            data (bytearray): raw ble data

        Returns:
            tuple: First entry for the command, following entries are parameters
        """
        try:
            command = ImprovCommand(data[0])
        except ValueError as verr:
            return (ImprovCommand.UNKNOWN,)

        logging.info(f"Command recieved: {command}")
        length = data[1]

        if (length != len(data) - 3):
            logging.warning(f"length mismatch: {length}  != {len(data) - 3}")
            return (ImprovCommand.UNKNOWN,)

        checksum = data[-1]
        calculated_checksum = ImprovProtocol.calculateChecksum(data[:-1])

        if ((calculated_checksum & 0xFF) != checksum):
            logging.warning(
                f"Checksums are {hex(checksum)} and {hex(calculated_checksum)}")
            return (ImprovCommand.BAD_CHECKSUM,)

        if (command == ImprovCommand.WIFI_SETTINGS):
            ssid_length = data[2]
            ssid_end = 3 + ssid_length
            # We need at least one byte for the pw length
            if ssid_end >= len(data) - 1:
                return (command,)
            ssid = data[3: ssid_end]

            password_length = data[ssid_end]
            password_start = ssid_end + 1
            if password_start + password_length >= len(data):
                return (command,)
            password = data[password_start: password_start + password_length]

            return (command, ssid, password)

        return (command,)

    def build_rpc_response(command: ImprovCommand, data: list[str]) -> bytearray:
        """Builds an bytearray from an command and data to be passed to the caller

        Args:
            command (ImprovCommand): The RPC command this is answering
            data (list[str]): data to be passed to the caller, e.g. redirect urls 
            
        Returns:
            bytearray: Formated bytearray with length and checksum fields
        """
        response = bytearray()
        response += command.value.to_bytes(1,'little')
        # Leave space for length field
        response += b"\x00"
        for url in data:
            response += len(url).to_bytes(1,'little')
            response += url.encode("utf-8")

        response[1] = len(response) - 2
        response += ImprovProtocol.calculateChecksum(response).to_bytes(1,'little')
        return response

    def handle_read(self, uuid: str) -> bytearray:
        match uuid:
            case ImprovUUID.STATUS_UUID.value:
                return bytearray(self.state.value.to_bytes(1,'little'))
            case ImprovUUID.CAPABILITIES_UUID.value:
                if self.identify_callback != None:
                    return bytearray([0x01])
                return bytearray([0x01])
            case ImprovUUID.ERROR_UUID.value:
                return bytearray(self.last_error.value.to_bytes(1,'little'))
            case ImprovUUID.RPC_RESULT_UUID.value:
                return self.rpc_response
            case _:
                return bytearray()

    def handle_write(self, uuid: str, data: bytearray) -> (str, bytearray):
        match uuid:
            case ImprovUUID.RPC_COMMAND_UUID.value:
                self.last_error = ImprovError.NONE
                parsed = ImprovProtocol.parse_improv_data(data)
                command = parsed[0]

                match command:
                    case ImprovCommand.BAD_CHECKSUM:
                        self.last_error = ImprovError.INVALID_RPC
                    case ImprovCommand.WIFI_SETTINGS:
                        if self.state.value < ImprovState.AUTHORIZED.value:
                            self.last_error = ImprovError.NOT_AUTHORIZED
                        elif len(parsed) >= 3:
                            ssid = parsed[1]
                            password = parsed[2]

                            if self.wifi_connect_callback == None:
                                self.last_error = ImprovError.UNABLE_TO_CONNECT
                            else:
                                rpc_urls = self.wifi_connect_callback(
                                    ssid, password)
                                if rpc_urls != None:
                                    self.rpc_response = ImprovProtocol.build_rpc_response(
                                        ImprovCommand.WIFI_SETTINGS, rpc_urls)
                                else:
                                    self.last_error = ImprovError.UNABLE_TO_CONNECT
                        else:
                            self.last_error = ImprovError.INVALID_RPC
                    case ImprovCommand.IDENTIFY:
                        if self.identify_callback != None:
                            self.identify_callback()
                            return (None, None)
                        else:
                            self.last_error = ImprovError.INVALID_RPC
                    case ImprovCommand.GET_CURRENT_STATE:
                        self.rpc_response = ImprovProtocol.build_rpc_response(
                            ImprovCommand.GET_CURRENT_STATE, [
                                self.state.value.to_bytes(1,'little')]
                        )
                    case ImprovCommand.GET_DEVICE_INFO:
                        print(
                            "Client requested GET_DEVICE_INFO but it is not implemented")
                        self.last_error = ImprovError.UNKNOWN_RPC
                    case ImprovCommand.GET_WIFI_NETWORKS:
                        print(
                            "Client requested GET_WIFI_NETWORKS but it is not implemented")
                        self.last_error = ImprovError.UNKNOWN_RPC
                    case _:
                        self.last_error = ImprovError.UNKNOWN_RPC
                if self.last_error != ImprovError.NONE:
                    print(
                        f"An error occured during execution: {self.last_error}")
                    return (ImprovUUID.ERROR_UUID.value, bytearray(self.last_error.value.to_bytes(1,'little')))
                print(f"RPC response: {self.rpc_response}")
                return (ImprovUUID.RPC_RESULT_UUID.value, self.rpc_response)
            # Not our UUID
            case _:
                return (None, None)
