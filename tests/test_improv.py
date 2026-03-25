#!/usr/bin/env python3

from __future__ import annotations

from improv import (
    ImprovCommand,
    ImprovError,
    ImprovProtocol,
    ImprovState,
    ImprovUUID,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def build_wifi_packet(ssid: bytes, password: bytes) -> bytearray:
    """Build a valid WIFI_SETTINGS RPC packet from raw SSID/password bytes."""
    command = ImprovCommand.WIFI_SETTINGS.value
    payload = bytearray()
    payload.append(len(ssid))
    payload += ssid
    payload.append(len(password))
    payload += password

    data = bytearray()
    data.append(command)
    data.append(len(payload))
    data += payload

    checksum = sum(data) & 0xFF
    data.append(checksum)
    return data


def build_rpc_packet(
    command: ImprovCommand,
    *fields: bytes,
) -> bytearray:
    """Build a valid RPC packet: [command, length, ...fields, checksum]."""
    body = bytearray()
    for field in fields:
        body += len(field).to_bytes(1, "little")
        body += field
    packet = bytearray()
    packet += command.value.to_bytes(1, "little")
    packet += len(body).to_bytes(1, "little")
    packet += body
    packet += (sum(packet) & 0xFF).to_bytes(1, "little")
    return packet


def make_protocol(**kwargs) -> ImprovProtocol:
    """Create an ImprovProtocol with a dummy wifi callback."""
    defaults: dict = dict(
        wifi_connect_callback=lambda ssid, pwd: ["http://192.168.1.1:8080"],
        requires_authorization=False,
    )
    defaults.update(kwargs)
    return ImprovProtocol(**defaults)


def decode_rpc_components(resp: bytearray) -> list[bytes]:
    """Decode all TLV-style components from a single RPC response bytearray."""
    components: list[bytes] = []
    offset = 2  # skip command + length
    data_end = 2 + resp[1]
    while offset < data_end:
        comp_len = resp[offset]
        offset += 1
        components.append(bytes(resp[offset : offset + comp_len]))
        offset += comp_len
    return components


# ===========================================================================
# Checksum
# ===========================================================================


class TestChecksum:
    def test_simple(self) -> None:
        proto = make_protocol()
        assert proto.calculateChecksum(bytearray([0x01, 0x02, 0x03])) == 0x06

    def test_empty(self) -> None:
        proto = make_protocol()
        assert proto.calculateChecksum(bytearray()) == 0x00

    def test_accepts_bytes(self) -> None:
        proto = make_protocol()
        assert proto.calculateChecksum(b"\x10\x20") == 0x30


class TestParseImprovDataBasic:
    def test_ascii_ssid_and_password(self) -> None:
        pkt = build_wifi_packet(b"MyWiFi", b"secret123")
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert result[1] == bytearray(b"MyWiFi")
        assert result[2] == bytearray(b"secret123")

    def test_empty_password(self) -> None:
        """Open networks have an empty password."""
        pkt = build_wifi_packet(b"OpenNet", b"")
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert result[1] == bytearray(b"OpenNet")
        assert result[2] == bytearray(b"")

    def test_empty_ssid_and_password(self) -> None:
        pkt = build_wifi_packet(b"", b"")
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert result[1] == bytearray(b"")
        assert result[2] == bytearray(b"")

    def test_unknown_command_byte(self) -> None:
        proto = make_protocol()
        result = proto.parse_improv_data(bytearray([0xAA]))
        assert result[0] == ImprovCommand.UNKNOWN

    def test_wifi_settings_without_payload(self) -> None:
        proto = make_protocol()
        result = proto.parse_improv_data(bytearray([ImprovCommand.WIFI_SETTINGS.value]))
        assert result[0] == ImprovCommand.UNKNOWN

    def test_bad_checksum(self) -> None:
        pkt = build_wifi_packet(b"Net", b"pass")
        pkt[-1] ^= 0xFF  # corrupt checksum
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.BAD_CHECKSUM

    def test_length_mismatch(self) -> None:
        pkt = build_wifi_packet(b"Net", b"pass")
        pkt[1] = 0x00  # wrong length field
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.UNKNOWN

    def test_identify_command_no_payload(self) -> None:
        proto = make_protocol()
        result = proto.parse_improv_data(bytearray([ImprovCommand.IDENTIFY.value]))
        assert result[0] == ImprovCommand.IDENTIFY

    def test_get_wifi_networks_command(self) -> None:
        proto = make_protocol()
        result = proto.parse_improv_data(
            bytearray([ImprovCommand.GET_WIFI_NETWORKS.value])
        )
        assert result[0] == ImprovCommand.GET_WIFI_NETWORKS

    def test_get_device_info_with_packet(self) -> None:
        proto = make_protocol()
        packet = build_rpc_packet(ImprovCommand.GET_DEVICE_INFO)
        result = proto.parse_improv_data(packet)
        assert result[0] == ImprovCommand.GET_DEVICE_INFO

    def test_ssid_overflow_returns_command_only(self) -> None:
        """If ssid_length claims more bytes than available, return (command,)."""
        proto = make_protocol()
        body = bytearray([0xFF, 0xAA])
        packet = bytearray()
        packet += ImprovCommand.WIFI_SETTINGS.value.to_bytes(1, "little")
        packet += len(body).to_bytes(1, "little")
        packet += body
        packet += (sum(packet) & 0xFF).to_bytes(1, "little")
        result = proto.parse_improv_data(packet)
        assert result == (ImprovCommand.WIFI_SETTINGS,)

    def test_password_overflow_returns_command_only(self) -> None:
        """If password_length claims more bytes than available, return (command,)."""
        proto = make_protocol()
        ssid = b"1234"
        password = b"5678"
        body = bytearray()
        body += len(ssid).to_bytes(1, "little")
        body += ssid
        body += (len(password) + 1).to_bytes(1, "little")  # one too much
        body += password
        packet = bytearray()
        packet += ImprovCommand.WIFI_SETTINGS.value.to_bytes(1, "little")
        packet += len(body).to_bytes(1, "little")
        packet += body
        packet += (sum(packet) & 0xFF).to_bytes(1, "little")
        result = proto.parse_improv_data(packet)
        assert len(result) == 1
        assert result[0] == ImprovCommand.WIFI_SETTINGS


class TestParseImprovDataUTF8:
    def test_utf8_ssid_german_umlauts(self) -> None:
        ssid = "Ünïcödé-Wïfï".encode()
        pkt = build_wifi_packet(ssid, b"password")
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert bytes(result[1]) == ssid

    def test_utf8_ssid_chinese(self) -> None:
        ssid = "我的网络".encode()
        pkt = build_wifi_packet(ssid, b"password")
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert bytes(result[1]) == ssid
        assert result[1].decode("utf-8") == "我的网络"

    def test_utf8_ssid_japanese(self) -> None:
        ssid = "東京ワイファイ".encode()
        pkt = build_wifi_packet(ssid, b"pass")
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert result[1].decode("utf-8") == "東京ワイファイ"

    def test_utf8_ssid_korean(self) -> None:
        ssid = "와이파이".encode()
        pkt = build_wifi_packet(ssid, b"pass")
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert result[1].decode("utf-8") == "와이파이"

    def test_utf8_ssid_emoji(self) -> None:
        ssid = "☕🏠WiFi".encode()
        pkt = build_wifi_packet(ssid, b"password")
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert result[1].decode("utf-8") == "☕🏠WiFi"

    def test_utf8_password_with_special_chars(self) -> None:
        password = "pässwörd™€".encode()
        pkt = build_wifi_packet(b"Net", password)
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert result[2].decode("utf-8") == "pässwörd™€"

    def test_utf8_both_ssid_and_password(self) -> None:
        ssid = "カフェ".encode()
        password = "密码安全".encode()
        pkt = build_wifi_packet(ssid, password)
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert result[1].decode("utf-8") == "カフェ"
        assert result[2].decode("utf-8") == "密码安全"

    def test_utf8_arabic_ssid(self) -> None:
        ssid = "شبكة_واي_فاي".encode()
        pkt = build_wifi_packet(ssid, b"pass")
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert result[1].decode("utf-8") == "شبكة_واي_فاي"

    def test_mixed_ascii_and_multibyte(self) -> None:
        ssid = "Home-réseau-家".encode()
        password = "p@ss-wörk-密码!".encode()
        pkt = build_wifi_packet(ssid, password)
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert result[1].decode("utf-8") == "Home-réseau-家"
        assert result[2].decode("utf-8") == "p@ss-wörk-密码!"

    def test_emoji_heavy(self) -> None:
        ssid = "net\U0001f680".encode()
        password = (
            "123456789\U0001f315\U0001f9db\u200d\u2642\ufe0f"
            "\U0001f987\U0001f3f0\U0001f977\u2694\ufe0f\U0001f480abcd"
        ).encode()
        pkt = build_wifi_packet(ssid, password)
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert bytes(result[1]) == ssid
        assert bytes(result[2]) == password

    def test_ssid_max_32_bytes_utf8(self) -> None:
        """IEEE 802.11 SSIDs can be up to 32 bytes."""
        # 8 CJK chars x 3 bytes = 24 bytes, plus 8 ASCII = 32 bytes
        ssid = ("网络" * 4 + "ABCDEFGH").encode("utf-8")
        assert len(ssid) == 32
        pkt = build_wifi_packet(ssid, b"pw")
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert bytes(result[1]) == ssid

    def test_ssid_with_null_bytes(self) -> None:
        """SSIDs can technically contain null bytes."""
        ssid = b"Net\x00Work"
        pkt = build_wifi_packet(ssid, b"pass")
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert bytes(result[1]) == ssid

    def test_password_with_null_bytes(self) -> None:
        password = b"p\x00ss"
        pkt = build_wifi_packet(b"Net", password)
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert bytes(result[2]) == password

    def test_raw_latin1_bytes_not_valid_utf8(self) -> None:
        """If a client sends Latin-1, parse_improv_data extracts raw bytes."""
        ssid = "café".encode("latin-1")  # \x63\x61\x66\xe9
        pkt = build_wifi_packet(ssid, b"pass")
        proto = make_protocol()
        result = proto.parse_improv_data(pkt)
        assert result[0] == ImprovCommand.WIFI_SETTINGS
        assert bytes(result[1]) == ssid


class TestBuildRpcResponse:
    def test_ascii_single_url(self) -> None:
        proto = make_protocol()
        responses = proto.build_rpc_response(
            ImprovCommand.WIFI_SETTINGS, ["http://192.168.1.1"]
        )
        assert len(responses) == 1
        resp = responses[0]
        assert resp[0] == ImprovCommand.WIFI_SETTINGS.value
        component_length = resp[2]
        component_bytes = resp[3 : 3 + component_length]
        assert component_bytes.decode("utf-8") == "http://192.168.1.1"
        assert resp[-1] == (sum(resp[:-1]) & 0xFF)

    def test_response_length_field_correct(self) -> None:
        proto = make_protocol()
        responses = proto.build_rpc_response(
            ImprovCommand.WIFI_SETTINGS, ["http://192.168.1.1"]
        )
        resp = responses[0]
        data_length = resp[1]
        # Total = 2 (cmd+len) + data_length + 1 (checksum)
        assert len(resp) == 2 + data_length + 1

    def test_response_checksum_valid(self) -> None:
        proto = make_protocol()
        responses = proto.build_rpc_response(
            ImprovCommand.WIFI_SETTINGS, ["http://10.0.0.1:8080"]
        )
        for resp in responses:
            assert resp[-1] == (sum(resp[:-1]) & 0xFF)

    def test_utf8_url_length_is_byte_length(self) -> None:
        """The length byte must reflect byte count, not character count."""
        proto = make_protocol()
        # "café" is 4 chars but 5 bytes in UTF-8
        responses = proto.build_rpc_response(ImprovCommand.WIFI_SETTINGS, ["café"])
        resp = responses[0]
        component_length = resp[2]
        expected_bytes = "café".encode()
        assert component_length == len(expected_bytes)
        assert resp[3 : 3 + component_length] == expected_bytes

    def test_utf8_cjk_response_length(self) -> None:
        """CJK characters are 3 bytes each in UTF-8."""
        proto = make_protocol()
        text = "网络"  # 2 chars, 6 bytes
        responses = proto.build_rpc_response(ImprovCommand.WIFI_SETTINGS, [text])
        resp = responses[0]
        assert resp[2] == 6

    def test_utf8_emoji_response_length(self) -> None:
        proto = make_protocol()
        text = "☕"  # 3 bytes in UTF-8
        responses = proto.build_rpc_response(ImprovCommand.WIFI_SETTINGS, [text])
        resp = responses[0]
        assert resp[2] == len(text.encode("utf-8"))

    def test_multiple_components(self) -> None:
        proto = make_protocol()
        urls = ["http://192.168.1.1:8080", "http://10.0.0.1:8080"]
        responses = proto.build_rpc_response(ImprovCommand.WIFI_SETTINGS, urls)
        assert len(responses) >= 1
        for resp in responses:
            assert resp[-1] == (sum(resp[:-1]) & 0xFF)

    def test_empty_data_list(self) -> None:
        proto = make_protocol()
        responses = proto.build_rpc_response(ImprovCommand.WIFI_SETTINGS, [])
        assert len(responses) == 1
        resp = responses[0]
        assert resp[0] == ImprovCommand.WIFI_SETTINGS.value
        assert resp[1] == 0  # no data
        assert resp[-1] == (sum(resp[:-1]) & 0xFF)

    def test_response_splitting_on_large_data(self) -> None:
        """When data exceeds max_response_bytes, it should be split."""
        proto = make_protocol(max_response_bytes=50)
        urls = [
            "http://10.10.0.104",
            "http://fd71:d091:1219:d546:3b75:493:9940:cd98",
            "http://fe80::6ff3:4aa2:2e7:4d80",
        ]
        responses = proto.build_rpc_response(ImprovCommand.WIFI_SETTINGS, urls)
        assert len(responses) > 1
        for resp in responses:
            assert resp[-1] == (sum(resp[:-1]) & 0xFF)

    def test_each_split_response_has_command_byte(self) -> None:
        proto = make_protocol(max_response_bytes=30)
        urls = ["http://a.example.com", "http://b.example.com"]
        responses = proto.build_rpc_response(ImprovCommand.WIFI_SETTINGS, urls)
        for resp in responses:
            assert resp[0] == ImprovCommand.WIFI_SETTINGS.value

    def test_response_splitting_respects_utf8_byte_length(self) -> None:
        """Size check must use UTF-8 byte length, not character count."""
        proto = make_protocol(max_response_bytes=30)
        components = ["日本語テスト", "another"]
        responses = proto.build_rpc_response(ImprovCommand.WIFI_SETTINGS, components)
        for resp in responses:
            assert len(resp) <= proto.max_response_bytes + 3


class TestBuildRpcResponseBytes:
    def test_bytes_input_passes_through(self) -> None:
        """build_rpc_response must accept bytes entries without crashing."""
        proto = make_protocol()
        responses = proto.build_rpc_response(ImprovCommand.GET_CURRENT_STATE, [b"\x02"])
        assert len(responses) == 1
        resp = responses[0]
        assert resp[2] == 1  # length of the single byte
        assert resp[3] == 0x02
        assert resp[-1] == (sum(resp[:-1]) & 0xFF)

    def test_bytearray_input_passes_through(self) -> None:
        proto = make_protocol()
        responses = proto.build_rpc_response(
            ImprovCommand.GET_CURRENT_STATE, [bytearray(b"\x03")]
        )
        assert len(responses) == 1
        resp = responses[0]
        assert resp[2] == 1
        assert resp[3] == 0x03

    def test_mixed_str_and_bytes(self) -> None:
        """A response list with both str and bytes entries."""
        proto = make_protocol()
        responses = proto.build_rpc_response(
            ImprovCommand.GET_DEVICE_INFO, ["device-name", b"\x01\x02"]
        )
        assert len(responses) >= 1
        for resp in responses:
            assert resp[-1] == (sum(resp[:-1]) & 0xFF)
        # Verify the mixed content is decodable
        components = decode_rpc_components(responses[0])
        assert components[0] == b"device-name"
        assert components[1] == b"\x01\x02"

    def test_state_bytes_response(self) -> None:
        """GET_CURRENT_STATE passes state as bytes; verify encoding."""
        proto = make_protocol()
        state_bytes = ImprovState.AUTHORIZED.value.to_bytes(1, "little")
        responses = proto.build_rpc_response(
            ImprovCommand.GET_CURRENT_STATE, [state_bytes]
        )
        resp = responses[0]
        assert resp[0] == ImprovCommand.GET_CURRENT_STATE.value
        assert resp[2] == 1
        assert resp[3] == ImprovState.AUTHORIZED.value
        assert resp[-1] == (sum(resp[:-1]) & 0xFF)


class TestRpcResponseRoundTrip:
    def test_single_url_roundtrip(self) -> None:
        proto = make_protocol()
        url = "http://192.168.1.1"
        responses = proto.build_rpc_response(ImprovCommand.WIFI_SETTINGS, [url])
        components = decode_rpc_components(responses[0])
        assert len(components) == 1
        assert components[0] == url.encode("utf-8")

    def test_multiple_urls_roundtrip(self) -> None:
        proto = make_protocol(max_response_bytes=200)
        urls = [
            "http://10.10.0.104",
            "http://fd71:d091:1219:d546:3b75:493:9940:cd98",
            "http://fe80::6ff3:4aa2:2e7:4d80",
        ]
        responses = proto.build_rpc_response(ImprovCommand.WIFI_SETTINGS, urls)
        all_components: list[bytes] = []
        for resp in responses:
            all_components.extend(decode_rpc_components(resp))
        decoded_urls = [c.decode("utf-8") for c in all_components]
        assert decoded_urls == urls

    def test_split_urls_roundtrip(self) -> None:
        proto = make_protocol(max_response_bytes=50)
        urls = [
            "http://10.10.0.104",
            "http://fd71:d091:1219:d546:3b75:493:9940:cd98",
            "http://fe80::6ff3:4aa2:2e7:4d80",
        ]
        responses = proto.build_rpc_response(ImprovCommand.WIFI_SETTINGS, urls)
        assert len(responses) > 1
        all_components: list[bytes] = []
        for resp in responses:
            assert resp[-1] == (sum(resp[:-1]) & 0xFF)
            all_components.extend(decode_rpc_components(resp))
        decoded_urls = [c.decode("utf-8") for c in all_components]
        assert decoded_urls == urls

    def test_bytes_roundtrip(self) -> None:
        proto = make_protocol()
        raw_data: list[bytes] = [b"\x02"]
        responses = proto.build_rpc_response(ImprovCommand.GET_CURRENT_STATE, raw_data)
        components = decode_rpc_components(responses[0])
        assert components == [b"\x02"]

    def test_device_info_roundtrip(self) -> None:
        proto = make_protocol()
        info = ["DeviceName", "1.2.3", "hw-rev-2", "ACME Corp"]
        responses = proto.build_rpc_response(ImprovCommand.GET_DEVICE_INFO, info)
        all_components: list[bytes] = []
        for resp in responses:
            all_components.extend(decode_rpc_components(resp))
        decoded = [c.decode("utf-8") for c in all_components]
        assert decoded == info

    def test_utf8_network_names_roundtrip(self) -> None:
        """Simulate GET_WIFI_NETWORKS returning UTF-8 SSIDs."""
        proto = make_protocol()
        ssids = ["HomeNet", "café-réseau", "我的网络", "☕🏠"]
        responses = proto.build_rpc_response(ImprovCommand.GET_WIFI_NETWORKS, ssids)
        decoded: list[str] = []
        for resp in responses:
            for comp in decode_rpc_components(resp):
                decoded.append(comp.decode("utf-8"))
        assert decoded == ssids


class TestHandleWriteWifiSettings:
    def test_successful_connect_ascii(self) -> None:
        callback_args: dict = {}

        def capture_callback(ssid: bytearray, password: bytearray) -> list[str]:
            callback_args["ssid"] = ssid
            callback_args["password"] = password
            return ["http://192.168.1.1:8080"]

        proto = make_protocol(wifi_connect_callback=capture_callback)
        pkt = build_wifi_packet(b"TestNet", b"pass123")
        target_uuid, _target_values = proto.handle_write(
            ImprovUUID.RPC_COMMAND_UUID.value, pkt
        )
        assert target_uuid == ImprovUUID.RPC_RESULT_UUID.value
        assert proto.state == ImprovState.PROVISIONED
        assert proto.last_error == ImprovError.NONE
        assert callback_args["ssid"] == bytearray(b"TestNet")
        assert callback_args["password"] == bytearray(b"pass123")

    def test_successful_connect_utf8_ssid(self) -> None:
        callback_args: dict = {}

        def capture_callback(ssid: bytearray, password: bytearray) -> list[str]:
            callback_args["ssid"] = ssid
            callback_args["password"] = password
            return ["http://10.0.0.1"]

        proto = make_protocol(wifi_connect_callback=capture_callback)
        ssid = "我的网络".encode()
        passwd = "密码".encode()
        pkt = build_wifi_packet(ssid, passwd)
        target_uuid, _target_values = proto.handle_write(
            ImprovUUID.RPC_COMMAND_UUID.value, pkt
        )
        assert target_uuid == ImprovUUID.RPC_RESULT_UUID.value
        assert proto.state == ImprovState.PROVISIONED
        assert bytes(callback_args["ssid"]) == ssid
        assert bytes(callback_args["password"]) == passwd
        assert callback_args["ssid"].decode("utf-8") == "我的网络"
        assert callback_args["password"].decode("utf-8") == "密码"

    def test_connect_failure_returns_error(self) -> None:
        proto = make_protocol(wifi_connect_callback=lambda s, p: None)
        pkt = build_wifi_packet(b"BadNet", b"wrong")
        target_uuid, _ = proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, pkt)
        assert target_uuid == ImprovUUID.ERROR_UUID.value
        assert proto.last_error == ImprovError.UNABLE_TO_CONNECT

    def test_connect_failure_resets_state_to_authorized(self) -> None:
        """After a failed connect, state must go back to AUTHORIZED."""
        proto = make_protocol(wifi_connect_callback=lambda s, p: None)
        pkt = build_wifi_packet(b"BadNet", b"wrong")
        proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, pkt)
        assert proto.state == ImprovState.AUTHORIZED

    def test_bad_checksum_returns_invalid_rpc(self) -> None:
        proto = make_protocol()
        pkt = build_wifi_packet(b"Net", b"pass")
        pkt[-1] ^= 0xFF
        target_uuid, _ = proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, pkt)
        assert target_uuid == ImprovUUID.ERROR_UUID.value
        assert proto.last_error == ImprovError.INVALID_RPC

    def test_not_authorized_state(self) -> None:
        proto = make_protocol(requires_authorization=True)
        assert proto.state == ImprovState.AWAITING_AUTHORIZATION
        pkt = build_wifi_packet(b"Net", b"pass")
        target_uuid, _ = proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, pkt)
        assert target_uuid == ImprovUUID.ERROR_UUID.value
        assert proto.last_error == ImprovError.NOT_AUTHORIZED

    def test_wifi_settings_no_payload_returns_invalid_rpc(self) -> None:
        proto = make_protocol()
        data = bytearray([ImprovCommand.WIFI_SETTINGS.value, 0x00])
        data.append(sum(data) & 0xFF)
        target_uuid, _ = proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, data)
        assert target_uuid == ImprovUUID.ERROR_UUID.value
        assert proto.last_error == ImprovError.INVALID_RPC

    def test_rpc_response_checksums_after_provision(self) -> None:
        """After successful provisioning, rpc_response must have valid checksums."""
        proto = make_protocol()
        pkt = build_wifi_packet(b"Net", b"pass")
        proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, pkt)
        assert isinstance(proto.rpc_response, list)
        for resp in proto.rpc_response:
            assert resp[-1] == (sum(resp[:-1]) & 0xFF)


class TestHandleWriteOtherCommands:
    def test_get_wifi_networks(self) -> None:
        proto = make_protocol(
            wifi_networks_callback=lambda: ["Network1", "café-réseau", "网络"],
        )
        pkt = bytearray([ImprovCommand.GET_WIFI_NETWORKS.value])
        target_uuid, _target_values = proto.handle_write(
            ImprovUUID.RPC_COMMAND_UUID.value, pkt
        )
        assert target_uuid == ImprovUUID.RPC_RESULT_UUID.value

    def test_get_wifi_networks_no_callback(self) -> None:
        proto = make_protocol(wifi_networks_callback=None)
        pkt = bytearray([ImprovCommand.GET_WIFI_NETWORKS.value])
        target_uuid, _ = proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, pkt)
        assert target_uuid == ImprovUUID.ERROR_UUID.value
        assert proto.last_error == ImprovError.UNKNOWN_RPC

    def test_get_wifi_networks_callback_returns_none(self) -> None:
        proto = make_protocol(wifi_networks_callback=lambda: None)
        pkt = bytearray([ImprovCommand.GET_WIFI_NETWORKS.value])
        target_uuid, _ = proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, pkt)
        assert target_uuid == ImprovUUID.ERROR_UUID.value
        assert proto.last_error == ImprovError.UNKNOWN

    def test_get_device_info_callback_called_once(self) -> None:
        """device_info_callback must be called exactly once, not twice."""
        call_count = 0

        def counting_callback() -> list[str]:
            nonlocal call_count
            call_count += 1
            return ["DeviceName", "v1.0"]

        proto = make_protocol(device_info_callback=counting_callback)
        pkt = bytearray([ImprovCommand.GET_DEVICE_INFO.value])
        proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, pkt)
        assert call_count == 1

    def test_get_device_info_no_callback(self) -> None:
        proto = make_protocol()
        pkt = bytearray([ImprovCommand.GET_DEVICE_INFO.value])
        target_uuid, _ = proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, pkt)
        assert target_uuid == ImprovUUID.ERROR_UUID.value
        assert proto.last_error == ImprovError.UNKNOWN_RPC

    def test_get_device_info_callback_returns_none(self) -> None:
        proto = make_protocol(device_info_callback=lambda: None)
        pkt = bytearray([ImprovCommand.GET_DEVICE_INFO.value])
        target_uuid, _ = proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, pkt)
        assert target_uuid == ImprovUUID.ERROR_UUID.value
        assert proto.last_error == ImprovError.UNKNOWN

    def test_get_current_state_response(self) -> None:
        """GET_CURRENT_STATE shares value 0x02 with IDENTIFY.
        With no identify_callback, the IDENTIFY branch triggers INVALID_RPC.
        Provide an identify_callback so the IDENTIFY path succeeds silently,
        then verify state is still AUTHORIZED (the identify path doesn't error)."""
        identified = False

        def on_identify() -> None:
            nonlocal identified
            identified = True

        proto = make_protocol(identify_callback=on_identify)
        pkt = bytearray([ImprovCommand.GET_CURRENT_STATE.value])
        _target_uuid, _target_values = proto.handle_write(
            ImprovUUID.RPC_COMMAND_UUID.value, pkt
        )
        # Since IDENTIFY and GET_CURRENT_STATE share 0x02, the match
        # goes to whichever arm is first - IDENTIFY in this code.
        assert identified is True
        assert proto.state == ImprovState.AUTHORIZED

    def test_unknown_uuid_passthrough(self) -> None:
        proto = make_protocol()
        result_uuid, result_values = proto.handle_write(
            "00000000-0000-0000-0000-000000000000",
            bytearray([0x01]),
        )
        assert result_uuid is None
        assert result_values is None

    def test_error_clears_between_calls(self) -> None:
        proto = make_protocol()
        # First: trigger an error
        bad_pkt = build_wifi_packet(b"SSID", b"Pass")
        bad_pkt[-1] ^= 0xFF
        proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, bad_pkt)
        assert proto.last_error == ImprovError.INVALID_RPC

        # Second: valid command should clear the error
        good_pkt = build_wifi_packet(b"SSID", b"Pass")
        proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, good_pkt)
        assert proto.last_error == ImprovError.NONE


class TestHandleRead:
    def test_read_status(self) -> None:
        proto = make_protocol()
        result = proto.handle_read(ImprovUUID.STATUS_UUID.value)
        assert result == bytearray([ImprovState.AUTHORIZED.value])

    def test_read_status_awaiting_auth(self) -> None:
        proto = make_protocol(requires_authorization=True)
        result = proto.handle_read(ImprovUUID.STATUS_UUID.value)
        assert result == bytearray([ImprovState.AWAITING_AUTHORIZATION.value])

    def test_read_error(self) -> None:
        proto = make_protocol()
        result = proto.handle_read(ImprovUUID.ERROR_UUID.value)
        assert result == bytearray([ImprovError.NONE.value])

    def test_read_capabilities(self) -> None:
        proto = make_protocol()
        result = proto.handle_read(ImprovUUID.CAPABILITIES_UUID.value)
        assert result == bytearray([0x01])

    def test_read_unknown_uuid(self) -> None:
        proto = make_protocol()
        result = proto.handle_read("00000000-0000-0000-0000-000000000000")
        assert result == bytearray()

    def test_read_rpc_result_initial(self) -> None:
        proto = make_protocol()
        result = proto.handle_read(ImprovUUID.RPC_RESULT_UUID.value)
        assert result == b""

    def test_read_rpc_result_after_connect(self) -> None:
        proto = make_protocol()
        pkt = build_wifi_packet(b"Net", b"pass")
        proto.handle_write(ImprovUUID.RPC_COMMAND_UUID.value, pkt)
        result = proto.handle_read(ImprovUUID.RPC_RESULT_UUID.value)
        assert len(result) > 0
