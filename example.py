#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from improv import *
from bless import (  # type: ignore
    BlessServer,
    BlessGATTCharacteristic,
    GATTCharacteristicProperties,
    GATTAttributePermissions
)
from bless.backends.bluezdbus.server import BlessServerBlueZDBus
from typing import Any, Dict, Union, Optional
import sys
import threading
import asyncio
import logging

logging.basicConfig(level=logging.DEBUG)


logger = logging.getLogger(name=__name__)

# NOTE: Some systems require different synchronization methods.
trigger: Union[asyncio.Event, threading.Event]
if sys.platform in ["darwin", "win32"]:
    trigger = threading.Event()
else:
    trigger = asyncio.Event()


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(name=__name__)


def build_gatt():
    gatt: Dict = {
        ImprovUUID.SERVICE_UUID.value: {
            ImprovUUID.STATUS_UUID.value: {
                "Properties": (GATTCharacteristicProperties.read |
                               GATTCharacteristicProperties.notify),
                "Permissions": (GATTAttributePermissions.readable |
                                GATTAttributePermissions.writeable)
            },
            ImprovUUID.ERROR_UUID.value: {
                "Properties": (GATTCharacteristicProperties.read |
                               GATTCharacteristicProperties.notify),
                "Permissions": (GATTAttributePermissions.readable |
                                GATTAttributePermissions.writeable)
            },
            ImprovUUID.RPC_COMMAND_UUID.value: {
                "Properties": (GATTCharacteristicProperties.read |
                               GATTCharacteristicProperties.write |
                               GATTCharacteristicProperties.write_without_response),
                "Permissions": (GATTAttributePermissions.readable |
                                GATTAttributePermissions.writeable)
            },
            ImprovUUID.RPC_RESULT_UUID.value: {
                "Properties": (GATTCharacteristicProperties.read |
                               GATTCharacteristicProperties.notify),
                "Permissions": (GATTAttributePermissions.readable)
            },
            ImprovUUID.CAPABILITIES_UUID.value: {
                "Properties": (GATTCharacteristicProperties.read),
                "Permissions": (GATTAttributePermissions.readable)
            },
        }
    }
    return gatt

"""
 Names longer than 10 characters will result in bless
 only advertising the name without the UUIDs on macOS,
 leading to a break with the Improv spec:

 Bluetooth LE Advertisement
The device MUST advertise the Service UUID.
"""
SERVICE_NAME = "Improv"

loop = asyncio.get_event_loop()
server = BlessServer(name=SERVICE_NAME, loop=loop)


def wifi_connect(ssid: str, passwd: str) -> Optional[list[str]]:
    logger.warning("Pretending to connect to wifi")
    logger.warning(
        f"Connecting to '{ssid.decode('utf-8')}' with password: '{passwd.decode('utf-8')}'")
    logger.warning("Return None for the failure")
    localIP = "192.168.2.123"
    localServer = f"http://{localIP}"
    logger.warning(
        f"Asking the client to now connect to us under {localServer}")
    return [localServer]


improv_server = ImprovProtocol(wifi_connect_callback=wifi_connect)


def read_request(
        characteristic: BlessGATTCharacteristic,
        **kwargs
) -> bytearray:
    try:
        improv_char = ImprovUUID(characteristic.uuid)
        logger.info(f"Reading {improv_char} : {characteristic}")
    except Exception:
        logger.info(f"Reading {characteristic.uuid}")
        pass
    if characteristic.service_uuid == ImprovUUID.SERVICE_UUID.value:
        return improv_server.handle_read(characteristic.uuid)
    return characteristic.value


def write_request(
        characteristic: BlessGATTCharacteristic,
        value: bytearray,
        **kwargs
):

    if characteristic.service_uuid == ImprovUUID.SERVICE_UUID.value:
        (target_uuid, target_values) = improv_server.handle_write(
            characteristic.uuid, value)
        if target_uuid != None and target_values != None:
            for value in target_values:
                logger.debug(
                    f"Setting {ImprovUUID(target_uuid)} to {value}")
                server.get_characteristic(
                    target_uuid,
                ).value = value
                success = server.update_value(
                    ImprovUUID.SERVICE_UUID.value,
                    target_uuid
                )
                if not success:
                    logger.warning(
                        f"Updating characteristic return status={success}")

async def run(loop):

    server.read_request_func = read_request
    server.write_request_func = write_request

    if isinstance(server, BlessServerBlueZDBus):
        await server.setup_task
        interface = server.adapter.get_interface('org.bluez.Adapter1')
        powered = await interface.get_powered()
        if not powered:
            logger.info("bluetooth device is not powered, powering now!")
            await interface.set_powered(True)

    await server.add_gatt(build_gatt())
    await server.start()

    logger.info("Server started")

    try:
        trigger.clear()
        if trigger.__module__ == "threading":
            trigger.wait()
        else:
            await trigger.wait()
    except KeyboardInterrupt:
        logger.debug("Shutting Down")
        pass
    await server.stop()

# Actually start the server
try:
    loop.run_until_complete(run(loop))
except KeyboardInterrupt:
    logger.debug("Shutting Down")
    trigger.set()
    pass
