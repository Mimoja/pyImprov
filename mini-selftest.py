#!/usr/bin/env python3


import logging

from improv import *

logging.basicConfig(level=logging.DEBUG)


logger = logging.getLogger(name=__name__)


def wifi_connect_callback(ssid: str, passwd: str) -> list[str] | None:
    return ["http://SucessfullConnect.com"]


improv_server = ImprovProtocol(
    wifi_connect_callback=wifi_connect_callback, max_response_bytes=50
)


def selftest():
    # Some small tests
    ssid = "Beware, UTF-8 has arrived🤔"
    logging.debug(ssid)
    ssid = ssid.encode("utf-8")
    password = "123456789🌕🧛‍♂️🦇🏰🥷⚔️💀abcd"
    logging.debug(password)
    password = password.encode("utf-8")

    command = [
        ImprovCommand.WIFI_SETTINGS.value,
        0,
        len(ssid),
        ssid,
        len(password),
        password,
    ]
    improv_data = bytearray()
    for component in command:
        try:
            improv_data += component
        except TypeError:
            improv_data += component.to_bytes()
    improv_data[1] = len(improv_data) - 2
    improv_data += improv_server.calculateChecksum(improv_data).to_bytes()
    logging.debug(improv_data)
    logging.debug(
        improv_server.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, improv_data)
    )

    rpc_urls = [
        "http://10.10.0.104",
        "http://fd71:d091:1219:d546:3b75:493:9940:cd98",
        "http://fe80::6ff3:4aa2:2e7:4d80",
    ]
    response = improv_server.build_rpc_response(
        ImprovCommand.WIFI_SETTINGS,
        rpc_urls,
    )
    logging.debug("Encoding RPC urls:")
    logging.debug(rpc_urls)
    logging.debug(response)

    ssid = b"1234"
    password = b"5678"
    command = [
        ImprovCommand.WIFI_SETTINGS.value,
        0,
        len(ssid),
        ssid,
        len(password) + 1,
        password,
    ]
    improv_data = bytearray()
    for component in command:
        try:
            improv_data += component
        except TypeError:
            improv_data += component.to_bytes()
    improv_data[1] = len(improv_data) - 2
    improv_data += improv_server.calculateChecksum(improv_data).to_bytes()
    logging.debug(improv_data)
    failed_parse = improv_server.parse_improv_data(improv_data)
    logging.debug(failed_parse)
    assert len(failed_parse) == 1


selftest()
