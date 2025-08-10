from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.tls import tls
from .utils import dicts_equal



### TEST VARIABLES ###
device = {
    "name": "device-test",
    "mac":  "11:22:33:44:55:66",
    "ipv4": "192.168.1.2"
}
policy_dict = {
    "handshake-type": 1,
    "tls-version": 1.2,
}
policy_dict_handshakes = {
    "handshake-type": "11, 12, 14",
    "tls-version": 1.2,
}
policy_dict_session_id = {
    "handshake-type": 1,
    "tls-version": 1.2,
    "session-id": "1234567890abcdef"
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    tls_instance = Protocol.init_protocol("tls", policy_dict, device)
    assert isinstance(tls_instance, tls)
    assert tls_instance.protocol_name == "tls"
    assert tls_instance.protocol_data == policy_dict
    assert tls_instance.device == device


def test_parse() -> None:
    """
    Test the method `parse` from the tls class.
    """
    tls_instance = tls(policy_dict, device)

    expected = {
        "nft": [],
        "nfq": [
            {"template": "tls_packet != NULL && tls_packet->messages != NULL && tls_packet->messages->message.handshake_type == {}",
             "match": policy_dict["handshake-type"]},
            {"template": "tls_packet->messages->message.tls_version == {}",
             "match": "771"}  # 771 = 0x0303 for TLS 1.2
        ]
    }

    parsed = tls_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_handshakes() -> None:
    """
    Test the method `parse` from the tls class with multiple handshake types.
    """
    tls_instance = tls(policy_dict_handshakes, device)

    expected = {
        "nft": [],
        "nfq": [
            {"template": "tls_packet != NULL && tls_packet->messages != NULL && tls_packet->messages->message.handshake_type == 11 && tls_packet->messages->next != NULL && tls_packet->messages->next->message.handshake_type == 12 && tls_packet->messages->next->next != NULL && tls_packet->messages->next->next->message.handshake_type == 14",
             "match": "11, 12, 14"},
            {"template": "tls_packet->messages->message.tls_version == {}",
             "match": "771"}  # 771 = 0x0303 for TLS
        ]
    }

    parsed = tls_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_session_id() -> None:
    """
    Test the method `parse` from the tls class with session ID.
    """
    tls_instance = tls(policy_dict_session_id, device)

    expected = {
        "nft": [],
        "nfq": [
            {"template": "tls_packet != NULL && tls_packet->messages != NULL && tls_packet->messages->message.handshake_type == {}",
             "match": policy_dict_session_id["handshake-type"]},
            {"template": "tls_packet->messages->message.tls_version == {}",
             "match": "771"},  # 771 = 0x0303 for TLS 1.2
            {"template": "tls_packet->messages->message.session_id_present == {}",
             "match": policy_dict_session_id["session-id"]}
        ]
    }

    parsed = tls_instance.parse()
    assert dicts_equal(parsed, expected)
