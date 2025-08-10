from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.ssdp import ssdp
from .utils import dicts_equal


### TEST VARIABLES ###
device = {
    "name": "device-test",
    "mac":  "11:22:33:44:55:66",
    "ipv4": "192.168.1.2"
}
policy_dict = {
    "method": "M-SEARCH"
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    ssdp_instance = Protocol.init_protocol("ssdp", policy_dict, device)
    assert isinstance(ssdp_instance, ssdp)
    assert ssdp_instance.protocol_name == "ssdp"
    assert ssdp_instance.protocol_data == policy_dict
    assert ssdp_instance.device == device


def test_parse_forward() -> None:
    """
    Test the method `parse` from the ssdp class,
    in the forward direction.
    """
    ssdp_instance = ssdp(policy_dict, device)
    
    expected = {
        "nft": [],
        "nfq": [
            {"template": "{}ssdp_message.is_request", "match": ""},
            {"template": "ssdp_message.method == {}", "match": "SSDP_M_SEARCH"}
        ]
    }
    
    parsed = ssdp_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_backward() -> None:
    """
    Test the method `parse` from the ssdp class,
    in the backward direction.
    """
    ssdp_instance = ssdp(policy_dict, device)
    
    expected = {
        "nft": [],
        "nfq": [
            {"template": "{}ssdp_message.is_request", "match": "!"}
        ]
    }
    
    parsed = ssdp_instance.parse(is_backward=True)
    assert dicts_equal(parsed, expected)
