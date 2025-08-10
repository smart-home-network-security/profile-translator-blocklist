from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.udp import udp
from .utils import dicts_equal



### TEST VARIABLES ###
device = {
    "name": "device-test",
    "mac":  "11:22:33:44:55:66",
    "ipv4": "192.168.1.2"
}
policy_dict = {
    "src-port": 12345,
    "dst-port": 80
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    udp_instance = Protocol.init_protocol("udp", policy_dict, device)
    assert isinstance(udp_instance, udp)
    assert udp_instance.protocol_name == "udp"
    assert udp_instance.protocol_data == policy_dict
    assert udp_instance.device == device


def test_parse_forward() -> None:
    """
    Test the method `parse` from the udp class
    in the forward direction.
    """
    udp_instance = udp(policy_dict, device)
    
    expected = {
        "nft": [
            {"template": "meta l4proto {}", "match": "udp"},
            {"template": "udp sport {}", "match": 12345},
            {"template": "udp dport {}", "match": 80}
        ],
        "nfq": []
    }
    
    parsed = udp_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_backward() -> None:
    """
    Test the method `parse` from the udp class
    in the backward direction.
    """
    udp_instance = udp(policy_dict, device)
    
    expected = {
        "nft": [
            {"template": "meta l4proto {}", "match": "udp"},
            {"template": "udp dport {}", "match": 12345},
            {"template": "udp sport {}", "match": 80}
        ],
        "nfq": []
    }
    
    parsed = udp_instance.parse(is_backward=True)
    assert dicts_equal(parsed, expected)
