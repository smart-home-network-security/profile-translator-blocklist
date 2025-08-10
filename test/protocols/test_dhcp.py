from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.dhcp import dhcp
from .utils import dicts_equal


### TEST VARIABLES ###
device = {
    "name": "device-test",
    "mac":  "11:22:33:44:55:66",
    "ipv4": "192.168.1.2"
}
policy_dict = {
    "type": "discover",
    "client-mac": device["mac"]
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    dhcp_instance = Protocol.init_protocol("dhcp", policy_dict, device)
    assert isinstance(dhcp_instance, dhcp)
    assert dhcp_instance.protocol_name == "dhcp"
    assert dhcp_instance.protocol_data == policy_dict
    assert dhcp_instance.device == device


def test_parse() -> None:
    """
    Test the method `parse` from the dhcp class.
    """
    dhcp_instance = dhcp(policy_dict, device)
    
    expected = {
        "nft": [],
        "nfq": [
            {"template": "dhcp_message.options.message_type == {}",
             "match": "DHCP_DISCOVER"},
            {"template": 'strcmp(mac_hex_to_str(dhcp_message.chaddr), "{}") == 0',
             "match": device["mac"]}
        ]
    }
    
    parsed = dhcp_instance.parse()
    assert dicts_equal(parsed, expected)
