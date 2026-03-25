#!/usr/bin/env python3

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from enum import Enum
from typing import cast

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


WifiConnectCallback = Callable[[bytearray, bytearray], list[str] | None]
IdentifyCallback = Callable[[], None]
WifiNetworksCallback = Callable[[], list[str] | None]
DeviceInfoCallback = Callable[[], list[str] | None]


class ImprovProtocol:
    VERSION: int = 1

    def __init__(
        self,
        wifi_connect_callback: WifiConnectCallback,
        requires_authorization: bool = False,
        identify_callback: IdentifyCallback | None = None,
        wifi_networks_callback: WifiNetworksCallback | None = None,
        device_info_callback: DeviceInfoCallback | None = None,
        max_response_bytes: int = 100,
    ) -> None:
        self.requires_authorization: bool = requires_authorization
        if requires_authorization:
            self.state: ImprovState = ImprovState.AWAITING_AUTHORIZATION
        else:
            self.state = ImprovState.AUTHORIZED
        self.identify_callback: IdentifyCallback | None = identify_callback
        self.wifi_connect_callback: WifiConnectCallback = wifi_connect_callback
        self.wifi_networks_callback: WifiNetworksCallback | None = (
            wifi_networks_callback
        )
        self.device_info_callback: DeviceInfoCallback | None = device_info_callback
        self.last_error: ImprovError = ImprovError.NONE
        self.rpc_response: bytes | list[bytearray] = b""
        self.max_response_bytes: int = max_response_bytes

    def calculateChecksum(self, data: bytearray | bytes) -> int:
        calculated_checksum: int = 0
        for b in data:
            calculated_checksum += b
        return calculated_checksum & 0xFF

    def parse_improv_data(
        self, data: bytearray
    ) -> tuple[ImprovCommand, ...] | tuple[ImprovCommand, bytearray, bytearray]:
        """Boundschecks and Parses a raw bytearray into an RPC command

        Args:
            data: raw ble data

        Returns:
            tuple: First entry for the command, following entries are parameters
        """
        try:
            command = ImprovCommand(data[0])
        except ValueError:
            return (ImprovCommand.UNKNOWN,)

        logging.info(f"Command recieved: {command}")
        if len(data) == 1:
            if command == ImprovCommand.WIFI_SETTINGS:
                logger.warning("WIFI settings command without payload")
                return (ImprovCommand.UNKNOWN,)
            return (command,)
        length: int = data[1]

        if length != len(data) - 3:
            logging.warning(f"length mismatch: {length}  != {len(data) - 3}")
            return (ImprovCommand.UNKNOWN,)

        checksum: int = data[-1]
        calculated_checksum: int = self.calculateChecksum(data[:-1])

        if (calculated_checksum & 0xFF) != checksum:
            logging.warning(
                f"Checksums are {hex(checksum)} and {hex(calculated_checksum)}"
            )
            return (ImprovCommand.BAD_CHECKSUM,)

        if command == ImprovCommand.WIFI_SETTINGS:
            ssid_length: int = data[2]
            ssid_end: int = 3 + ssid_length
            # We need at least one byte for the pw length
            if ssid_end >= len(data) - 1:
                return (command,)
            ssid: bytearray = bytearray(data[3:ssid_end])

            password_length: int = data[ssid_end]
            password_start: int = ssid_end + 1
            if password_start + password_length >= len(data):
                return (command,)
            password: bytearray = bytearray(
                data[password_start : password_start + password_length]
            )

            return (command, ssid, password)

        return (command,)

    def build_rpc_response(
        self, command: ImprovCommand, data: Sequence[str | bytes]
    ) -> list[bytearray]:
        """Builds an bytearray from an command and data to be passed to the caller

        Args:
            command: The RPC command this is answering
            data: data to be passed to the caller (str or bytes entries)

        Returns:
            list of bytearrays with length and checksum fields
        """
        responses: list[bytearray] = []
        current_response: bytearray = bytearray()
        current_response += command.value.to_bytes(1, "little")
        # Leave space for length field
        current_response += b"\x00"
        for component in data:
            encoded_component: bytes = (
                component.encode("utf-8")
                if isinstance(component, str)
                else bytes(component)
            )
            encoded_length: int = len(encoded_component)

            if len(current_response) - 2 + 1 + encoded_length > self.max_response_bytes:
                current_response[1] = len(current_response) - 2
                current_response += self.calculateChecksum(current_response).to_bytes(
                    1, "little"
                )
                # Add finished response to answer field
                if len(current_response) <= self.max_response_bytes:
                    responses.append(current_response)
                # Create new response
                current_response = bytearray()
                current_response += command.value.to_bytes(1, "little")
                # Leave space for length field
                current_response += b"\x00"

            current_response += encoded_length.to_bytes(1, "little")
            current_response += encoded_component

        current_response[1] = len(current_response) - 2
        current_response += self.calculateChecksum(current_response).to_bytes(
            1, "little"
        )
        responses.append(current_response)
        return responses

    def handle_read(self, uuid: str) -> bytearray | bytes | list[bytearray]:
        match uuid:
            case ImprovUUID.STATUS_UUID.value:
                return bytearray(self.state.value.to_bytes(1, "little"))
            case ImprovUUID.CAPABILITIES_UUID.value:
                if self.identify_callback is not None:
                    return bytearray([0x01])
                return bytearray([0x01])
            case ImprovUUID.ERROR_UUID.value:
                return bytearray(self.last_error.value.to_bytes(1, "little"))
            case ImprovUUID.RPC_RESULT_UUID.value:
                return self.rpc_response
            case _:
                return bytearray()

    def handle_write(
        self, uuid: str, data: bytearray
    ) -> tuple[str | None, bytearray | bytes | list[bytearray] | None]:
        match uuid:
            case ImprovUUID.RPC_COMMAND_UUID.value:
                self.last_error = ImprovError.NONE
                parsed = self.parse_improv_data(data)
                command: ImprovCommand = parsed[0]

                match command:
                    case ImprovCommand.BAD_CHECKSUM:
                        self.last_error = ImprovError.INVALID_RPC
                    case ImprovCommand.WIFI_SETTINGS:
                        if self.state.value < ImprovState.AUTHORIZED.value:
                            self.last_error = ImprovError.NOT_AUTHORIZED
                        elif len(parsed) >= 3:
                            ssid = cast(bytearray, parsed[1])
                            password = cast(bytearray, parsed[2])

                            if self.wifi_connect_callback is None:
                                self.last_error = ImprovError.UNABLE_TO_CONNECT
                            else:
                                self.state = ImprovState.PROVISIONING
                                rpc_urls = self.wifi_connect_callback(ssid, password)
                                if rpc_urls is not None:
                                    self.state = ImprovState.PROVISIONED
                                    self.rpc_response = self.build_rpc_response(
                                        ImprovCommand.WIFI_SETTINGS, rpc_urls
                                    )
                                else:
                                    self.state = ImprovState.AUTHORIZED
                                    self.last_error = ImprovError.UNABLE_TO_CONNECT
                        else:
                            self.last_error = ImprovError.INVALID_RPC
                    case ImprovCommand.IDENTIFY:
                        if self.identify_callback is not None:
                            self.identify_callback()
                        else:
                            self.last_error = ImprovError.INVALID_RPC
                    case ImprovCommand.GET_CURRENT_STATE:
                        self.rpc_response = self.build_rpc_response(
                            ImprovCommand.GET_CURRENT_STATE,
                            [self.state.value.to_bytes(1, "little")],
                        )
                    case ImprovCommand.GET_DEVICE_INFO:
                        if self.device_info_callback is not None:
                            device_info = self.device_info_callback()
                            if device_info is not None:
                                self.rpc_response = self.build_rpc_response(
                                    ImprovCommand.GET_DEVICE_INFO, device_info
                                )
                            else:
                                self.last_error = ImprovError.UNKNOWN
                        else:
                            logger.warning(
                                "Client requested GET_DEVICE_INFO"
                                " but it is not implemented"
                            )
                            self.last_error = ImprovError.UNKNOWN_RPC
                    case ImprovCommand.GET_WIFI_NETWORKS:
                        if self.wifi_networks_callback is not None:
                            wifi_networks = self.wifi_networks_callback()
                            if wifi_networks is not None:
                                self.rpc_response = self.build_rpc_response(
                                    ImprovCommand.GET_WIFI_NETWORKS, wifi_networks
                                )
                            else:
                                self.last_error = ImprovError.UNKNOWN
                        else:
                            logger.warning(
                                "Client requested GET_WIFI_NETWORKS"
                                " but it is not implemented"
                            )
                            self.last_error = ImprovError.UNKNOWN_RPC
                    case _:
                        self.last_error = ImprovError.UNKNOWN_RPC
                if self.last_error != ImprovError.NONE:
                    logger.warning(
                        f"An error occured during execution: {self.last_error}"
                    )
                    return (
                        ImprovUUID.ERROR_UUID.value,
                        bytearray(self.last_error.value.to_bytes(1, "little")),
                    )
                logger.debug(f"RPC response: {self.rpc_response}")
                return (ImprovUUID.RPC_RESULT_UUID.value, self.rpc_response)
            # Not our UUID
            case _:
                return (None, None)
