#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from improv import *
import logging

logging.basicConfig(level=logging.DEBUG)


logger = logging.getLogger(name=__name__)

improv_server = ImprovProtocol(wifi_connect_callback=None)


def selftest():
    # Some small tests
    ssid = "Beware, UTF-8 has arrived🤔"
    logging.debug(ssid)
    ssid = ssid.encode("utf-8")
    password = "123456789🌕🧛‍♂️🦇🏰🥷⚔️💀abcd"
    logging.debug(password)
    password = password.encode("utf-8")

    command = [ImprovCommand.WIFI_SETTINGS.value, 0,
               len(ssid),  ssid, len(password),  password]
    improv_data = bytearray()
    for component in command:
        try:
            improv_data += component
        except TypeError as e:
            improv_data += component.to_bytes()
    improv_data[1] = len(improv_data) - 2
    improv_data += ImprovProtocol.calculateChecksum(improv_data).to_bytes()
    logging.debug(improv_data)
    logging.debug(improv_server.handle_write(
        ImprovUUID.RPC_COMMAND_UUID.value, improv_data))

    rpc_urls = ["http://my-meticulous.local", "http://dummy"]
    logging.debug(ImprovProtocol.build_rpc_response(
        ImprovCommand.WIFI_SETTINGS, rpc_urls))

    ssid = b"1234"
    password = b"5678"
    command = [ImprovCommand.WIFI_SETTINGS.value, 0,
               len(ssid),  ssid, len(password) + 1,  password]
    improv_data = bytearray()
    for component in command:
        try:
            improv_data += component
        except TypeError as e:
            improv_data += component.to_bytes()
    improv_data[1] = len(improv_data) - 2
    improv_data += ImprovProtocol.calculateChecksum(improv_data).to_bytes()
    logging.debug(improv_data)
    failed_parse = ImprovProtocol.parse_improv_data(improv_data)
    logging.debug(failed_parse)
    assert (len(failed_parse) == 1)


selftest()
