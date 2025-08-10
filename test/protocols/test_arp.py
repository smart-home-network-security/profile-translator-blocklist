from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.arp import arp
from .utils import dicts_equal


### TEST VARIABLES ###
device = {
    "name": "gateway",
    "mac":  "11:11:11:11:11:11",
    "ipv4": "192.168.1.1"
}
policy_dict = {
    "type": "request",
    "sha":  "11:11:11:11:11:11",
    "tha":  "22:22:22:22:22:22",
    "spa":  "192.168.1.1",
    "tpa":  "192.168.1.2"
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    arp_instance = Protocol.init_protocol("arp", policy_dict, device)
    assert isinstance(arp_instance, arp)
    assert arp_instance.protocol_name == "arp"
    assert arp_instance.protocol_data == policy_dict
    assert arp_instance.device == device


def test_explicit_address() -> None:
    """
    Test the method `explicit_address` from the arp class.
    """
    arp_instance = arp(policy_dict, device)

    # Keyword "self"
    assert arp_instance.explicit_address("self", "mac") == device["mac"]
    assert arp_instance.explicit_address("self", "ipv4") == device["ipv4"]
    assert arp_instance.explicit_address("self") == device["ipv4"]

    # Well-known MAC addresses
    assert arp_instance.explicit_address("gateway", "mac") == arp.mac_addrs["gateway"]
    assert arp_instance.explicit_address("default", "mac") == arp.mac_addrs["default"]
    assert arp_instance.explicit_address("broadcast", "mac") == arp.mac_addrs["broadcast"]
    assert arp_instance.explicit_address("phone", "mac") == arp.mac_addrs["phone"]

    # Well-known IPv4 addresses
    assert arp_instance.explicit_address("local", "ipv4") == arp.ip_addrs["local"]
    assert arp_instance.explicit_address("gateway", "ipv4") == arp.ip_addrs["gateway"]
    assert arp_instance.explicit_address("phone", "ipv4") == arp.ip_addrs["phone"]


def test_parse_forward() -> None:
    """
    Test the method `parse` from the arp class.
    """
    arp_instance = arp(policy_dict, device)

    expected = {
        "nft": [
            {"template": "arp operation {}", "match": "request"},
            {"template": "arp saddr ether {}", "match": "11:11:11:11:11:11"},
            {"template": "arp daddr ether {}", "match": "22:22:22:22:22:22"},
            {"template": "arp saddr ip {}", "match": "192.168.1.1"},
            {"template": "arp daddr ip {}", "match": "192.168.1.2"}
        ],
        "nfq": [],
    }

    parsed = arp_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_backward() -> None:
    """
    Test the method `parse` from the arp class,
    with the parameter backward.
    """
    arp_instance = arp(policy_dict, device)
    
    expected = {
        "nft": [
            {"template": "arp operation {}", "match": "reply"},
            {"template": "arp daddr ether {}", "match": "11:11:11:11:11:11"},
            {"template": "arp saddr ether {}", "match": "22:22:22:22:22:22"},
            {"template": "arp daddr ip {}", "match": "192.168.1.1"},
            {"template": "arp saddr ip {}", "match": "192.168.1.2"}
        ],
        "nfq": [],
    }

    parsed = arp_instance.parse(is_backward=True)
    assert dicts_equal(parsed, expected)
