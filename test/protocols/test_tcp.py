from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.tcp import tcp
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
    tcp_instance = Protocol.init_protocol("tcp", policy_dict, device)
    assert isinstance(tcp_instance, tcp)
    assert tcp_instance.protocol_name == "tcp"
    assert tcp_instance.protocol_data == policy_dict
    assert tcp_instance.device == device


def test_parse_forward() -> None:
    """
    Test the method `parse` from the tcp class
    in the forward direction.
    """
    tcp_instance = tcp(policy_dict, device)
    
    expected = {
        "nft": [
            {"template": "meta l4proto {}", "match": "tcp"},
            {"template": "tcp sport {}", "match": 12345},
            {"template": "tcp dport {}", "match": 80}
        ],
        "nfq": []
    }
    
    parsed = tcp_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_backward() -> None:
    """
    Test the method `parse` from the tcp class
    in the backward direction.
    """
    tcp_instance = tcp(policy_dict, device)
    
    expected = {
        "nft": [
            {"template": "meta l4proto {}", "match": "tcp"},
            {"template": "tcp dport {}", "match": 12345},
            {"template": "tcp sport {}", "match": 80}
        ],
        "nfq": []
    }
    
    parsed = tcp_instance.parse(is_backward=True)
    assert dicts_equal(parsed, expected)
