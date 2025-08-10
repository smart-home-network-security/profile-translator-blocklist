import pytest
from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.ip import ip
from profile_translator_blocklist.protocols.ipv4 import ipv4
from .utils import dicts_equal


### TEST VARIABLES ###
device = {
    "name": "device-test",
    "mac":  "11:22:33:44:55:66",
    "ipv4": "192.168.1.2"
}
policy_dict = {
    "src": "192.168.1.2",
    "dst": "192.168.1.1"
}
policy_dict_aliases = {
    "src": "self",
    "dst": "www.example.com"
}
policy_dict_list = {
    "src": ["192.168.1.1", "192.168.1.2"],
    "dst": ["192.168.1.3", "192.168.1.4"]
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    ipv4_instance = Protocol.init_protocol("ipv4", policy_dict, device)
    assert isinstance(ipv4_instance, ipv4)
    assert ipv4_instance.protocol_name == "ipv4"
    assert ipv4_instance.protocol_data == policy_dict
    assert ipv4_instance.device == device


def test_is_ip_static() -> None:
    """
    Test the static method `is_ip_static` from the ipv4 class.
    """
    # Valid IPv4 address or subnet
    assert ipv4.is_ip_static("192.168.1.2")
    assert ipv4.is_ip_static("192.168.1.0/24")

    # Valid IPv4 aliases
    assert ipv4.is_ip_static("self")
    assert ipv4.is_ip_static("local")
    assert ipv4.is_ip_static("external")
    assert ipv4.is_ip_static("gateway")
    assert ipv4.is_ip_static("phone")
    assert ipv4.is_ip_static("broadcast")
    assert ipv4.is_ip_static("udp-broadcast")
    assert ipv4.is_ip_static("igmpv3")
    assert ipv4.is_ip_static("all")
    assert ipv4.is_ip_static("mdns")
    assert ipv4.is_ip_static("ssdp")
    assert ipv4.is_ip_static("coap")

    # List of addresses
    list_addresses = ["192.168.1.2", "self", "broadcast"]
    assert ipv4.is_ip_static(list_addresses)

    # Invalid IPv4 address
    assert not ipv4.is_ip_static("not_an_address")


def test_is_ip() -> None:
    """
    Test the method `is_ip` from the ipv4 class.
    """
    ipv4_instance = ipv4(policy_dict, device)
    
    # Valid IPv4 address or subnet
    assert ipv4_instance.is_ip("192.168.1.2")
    assert ipv4_instance.is_ip("192.168.1.0/24")

    # Valid IPv4 aliases
    assert ipv4_instance.is_ip("self")
    assert ipv4_instance.is_ip("local")
    assert ipv4_instance.is_ip("external")
    assert ipv4_instance.is_ip("gateway")
    assert ipv4_instance.is_ip("phone")
    assert ipv4_instance.is_ip("broadcast")
    assert ipv4_instance.is_ip("udp-broadcast")
    assert ipv4_instance.is_ip("igmpv3")
    assert ipv4_instance.is_ip("all")
    assert ipv4_instance.is_ip("mdns")
    assert ipv4_instance.is_ip("ssdp")
    assert ipv4_instance.is_ip("coap")

    # List of addresses
    list_addresses = ["192.168.1.2", "self", "broadcast"]
    assert ipv4_instance.is_ip(list_addresses)

    # Invalid IPv4 address
    assert not ipv4_instance.is_ip("not_an_address")


def test_explicit_address() -> None:
    """
    Test the method `explicit_address` from the ipv4 class.
    """
    ipv4_instance = ipv4(policy_dict, device)

    # Keyword "self"
    assert ipv4_instance.explicit_address("self") == device["ipv4"]

    ## Well-known IPv4 addresses
    addrs_well_known = ip.addrs["ipv4"]
    assert ipv4_instance.explicit_address("local") == addrs_well_known["local"]
    assert ipv4_instance.explicit_address("external") == addrs_well_known["external"]
    assert ipv4_instance.explicit_address("gateway") == addrs_well_known["gateway"]
    assert ipv4_instance.explicit_address("phone") == addrs_well_known["phone"]
    assert ipv4_instance.explicit_address("broadcast") == addrs_well_known["broadcast"]
    assert ipv4_instance.explicit_address("udp-broadcast") == addrs_well_known["udp-broadcast"]
    assert ipv4_instance.explicit_address("igmpv3") == addrs_well_known["igmpv3"]
    # IGMPv3 well-known groups
    assert ipv4_instance.explicit_address("all") == addrs_well_known["all"]
    assert ipv4_instance.explicit_address("mdns") == addrs_well_known["mdns"]
    assert ipv4_instance.explicit_address("ssdp") == addrs_well_known["ssdp"]
    assert ipv4_instance.explicit_address("coap") == addrs_well_known["coap"]

    # List of addresses
    list_addresses = ["local", "external", "gateway"]
    output_expected = f"{{ {', '.join([addrs_well_known['local'], addrs_well_known['external'], addrs_well_known['gateway']])} }}"
    assert ipv4_instance.explicit_address(list_addresses) == output_expected

    # Invalid address
    with pytest.raises(ValueError):
        ipv4_instance.explicit_address("not_an_address")


def test_parse_forward() -> None:
    """
    Test the method `parse` from the ipv4 class.
    """
    ipv4_instance = ipv4(policy_dict, device)

    expected = {
        "nft": [
            {"template": "ip saddr {}", "match": "192.168.1.2"},
            {"template": "ip daddr {}", "match": "192.168.1.1"}
        ],
        "nfq": [],
    }

    parsed = ipv4_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_backward() -> None:
    """
    Test the method `parse` from the ipv4 class,
    with the parameter backward.
    """
    ipv4_instance = ipv4(policy_dict, device)
    
    expected = {
        "nft": [
            {"template": "ip saddr {}", "match": "192.168.1.1"},
            {"template": "ip daddr {}", "match": "192.168.1.2"}
        ],
        "nfq": [],
    }

    parsed = ipv4_instance.parse(is_backward=True)
    assert dicts_equal(parsed, expected)


def test_parse_forward_aliases() -> None:
    """
    Test the method `parse` from the ipv4 class,
    with aliases as hosts.
    """
    ipv4_instance = ipv4(policy_dict_aliases, device)

    expected = {
        "nft": [
            {"template": "ip saddr {}", "match": "192.168.1.2"}
        ],
        "nfq": [
            {
                "template": '( dns_entry_contains(dns_map_get(dns_map, "{}"), (ip_addr_t) {{.version = 4, .value.ipv4 = dst_addr}}) )',
                "match": "example.com"
            }
        ]
    }

    parsed = ipv4_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_backward_aliases() -> None:
    """
    Test the method `parse` from the ipv4 class,
    with aliases as hosts,
    and the parameter backward.
    """
    ipv4_instance = ipv4(policy_dict_aliases, device)

    expected = {
        "nft": [
            {"template": "ip daddr {}", "match": "192.168.1.2"}
        ],
        "nfq": [
            {
                "template": '( dns_entry_contains(dns_map_get(dns_map, "{}"), (ip_addr_t) {{.version = 4, .value.ipv4 = src_addr}}) )',
                "match": "example.com"
            }
        ]
    }

    parsed = ipv4_instance.parse(is_backward=True)
    assert dicts_equal(parsed, expected)


def test_parse_list() -> None:
    """
    Test the method `parse` from the ipv4 class,
    with a list of addresses.
    """
    ipv4_instance = ipv4(policy_dict_list, device)

    expected = {
        "nft": [
            {"template": "ip saddr {}", "match": "{ 192.168.1.1, 192.168.1.2 }"},
            {"template": "ip daddr {}", "match": "{ 192.168.1.3, 192.168.1.4 }"}
        ],
        "nfq": []
    }

    parsed = ipv4_instance.parse()
    assert dicts_equal(parsed, expected)
