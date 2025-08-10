from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.icmp import icmp
from .utils import dicts_equal


### TEST VARIABLES ###
device = {
    "name": "device-test",
    "mac":  "11:22:33:44:55:66",
    "ipv4": "192.168.1.2"
}
policy_dict = {
    "type": "echo-request",
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    icmp_instance = Protocol.init_protocol("icmp", policy_dict, device)
    assert isinstance(icmp_instance, icmp)
    assert icmp_instance.protocol_name == "icmp"
    assert icmp_instance.protocol_data == policy_dict
    assert icmp_instance.device == device


def test_parse_forward() -> None:
        """
        Test the method `parse` from the icmp class.
        """
        icmp_instance = icmp(policy_dict, device)
        
        expected = {
            "nft": [
                {"template": "meta l4proto {}", "match": 1},
                {"template": "icmp type {}", "match": "echo-request"}
            ],
            "nfq": []
        }
        
        parsed = icmp_instance.parse()
        assert dicts_equal(parsed, expected)


def test_parse_backward() -> None:
    """
    Test the method `parse` from the icmp class,
    with backward parsing.
    """
    icmp_instance = icmp(policy_dict, device)

    expected = {
        "nft": [
            {"template": "meta l4proto {}", "match": 1},
            {"template": "icmp type {}", "match": "echo-reply"}
        ],
        "nfq": []
    }

    parsed = icmp_instance.parse(is_backward=True)
    assert dicts_equal(parsed, expected)
