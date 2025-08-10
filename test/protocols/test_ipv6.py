import pytest
from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.ip import ip
from profile_translator_blocklist.protocols.ipv6 import ipv6
from .utils import dicts_equal


### TEST VARIABLES ###
device = {
    "name": "device-test",
    "mac":  "11:22:33:44:55:66",
    "ipv6": "fd00::1"
}
policy_dict = {
    "src": "fd00::1",
    "dst": "fd00::2"
}
policy_dict_aliases = {
    "src": "self",
    "dst": "www.example.com"
}
policy_dict_list = {
    "src": ["fd00::1", "fd00::2"],
    "dst": ["fd00::3", "fd00::4"]
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    ipv6_instance = Protocol.init_protocol("ipv6", policy_dict, device)
    assert isinstance(ipv6_instance, ipv6)
    assert ipv6_instance.protocol_name == "ipv6"
    assert ipv6_instance.protocol_data == policy_dict
    assert ipv6_instance.device == device


def test_is_ip_static() -> None:
    """
    Test the static method `is_ip_static` from the ipv6 class.
    """
    # Valid IPv6 address or subnet
    assert ipv6.is_ip_static("fd00::1", version="ipv6")
    assert ipv6.is_ip_static("fd00::/64", version="ipv6")

    ## Well-known IPv6 aliases
    assert ipv6.is_ip_static("self", version="ipv6")
    assert ipv6.is_ip_static("default", version="ipv6")
    assert ipv6.is_ip_static("local", version="ipv6")
    assert ipv6.is_ip_static("gateway", version="ipv6")
    assert ipv6.is_ip_static("gateway-local", version="ipv6")
    assert ipv6.is_ip_static("phone", version="ipv6")
    # ICMPv6 groups
    assert ipv6.is_ip_static("multicast", version="ipv6")
    assert ipv6.is_ip_static("all-nodes", version="ipv6")
    assert ipv6.is_ip_static("all-routers", version="ipv6")
    assert ipv6.is_ip_static("all-mldv2-routers", version="ipv6")
    assert ipv6.is_ip_static("mdns", version="ipv6")
    assert ipv6.is_ip_static("coap", version="ipv6")

    # List of addresses
    list_addresses = ["fd00::1", "self", "multicast"]
    assert ipv6.is_ip_static(list_addresses, version="ipv6")

    # Invalid IPv6 address
    assert not ipv6.is_ip_static("not_an_address", version="ipv6")


def test_is_ip() -> None:
    """
    Test the method `is_ip` from the ipv6 class.
    """
    ipv6_instance = ipv6(policy_dict, device)

    # Valid IPv6 address or subnet
    assert ipv6_instance.is_ip("fd00::1")
    assert ipv6_instance.is_ip("fd00::/64")

    # Well-known IPv6 aliases
    assert ipv6_instance.is_ip("self")
    assert ipv6_instance.is_ip("default")
    assert ipv6_instance.is_ip("local")
    assert ipv6_instance.is_ip("gateway")
    assert ipv6_instance.is_ip("gateway-local")
    assert ipv6_instance.is_ip("phone")
    # ICMPv6 groups
    assert ipv6_instance.is_ip("multicast")
    assert ipv6_instance.is_ip("all-nodes")
    assert ipv6_instance.is_ip("all-routers")
    assert ipv6_instance.is_ip("all-mldv2-routers")
    assert ipv6_instance.is_ip("mdns")
    assert ipv6_instance.is_ip("coap")

    # List of addresses
    list_addresses = ["fd00::1", "self", "multicast"]
    assert ipv6_instance.is_ip(list_addresses)

    # Invalid IPv6 address
    assert not ipv6_instance.is_ip("not_an_address")


def test_explicit_address() -> None:
    """
    Test the method `explicit_address` from the ipv6 class.
    """
    ipv6_instance = ipv6(policy_dict, device)

    # Keyword "self"
    assert ipv6_instance.explicit_address("self") == device["ipv6"]

    # Well-known IPv6 addresses
    addrs_well_known = ip.addrs["ipv6"]
    assert ipv6_instance.explicit_address("default") == addrs_well_known["default"]
    assert ipv6_instance.explicit_address("local") == f"{{ {", ".join(addrs_well_known["local"])} }}"
    assert ipv6_instance.explicit_address("gateway") == addrs_well_known["gateway"]
    assert ipv6_instance.explicit_address("gateway-local") == addrs_well_known["gateway-local"]
    assert ipv6_instance.explicit_address("phone") == addrs_well_known["phone"]
    # ICMPv6 groups
    assert ipv6_instance.explicit_address("multicast") == addrs_well_known["multicast"]
    assert ipv6_instance.explicit_address("all-nodes") == addrs_well_known["all-nodes"]
    assert ipv6_instance.explicit_address("all-routers") == addrs_well_known["all-routers"]
    assert ipv6_instance.explicit_address("all-mldv2-routers") == addrs_well_known["all-mldv2-routers"]
    assert ipv6_instance.explicit_address("mdns") == addrs_well_known["mdns"]
    assert ipv6_instance.explicit_address("coap") == addrs_well_known["coap"]

    # List of addresses
    list_addresses = ["default", "gateway"]
    output_expected = f"{{ {', '.join([addrs_well_known['default'], addrs_well_known['gateway']])} }}"
    assert ipv6_instance.explicit_address(list_addresses) == output_expected

    # Invalid address
    with pytest.raises(ValueError):
        ipv6_instance.explicit_address("not_an_address")


def test_parse_forward() -> None:
    """
    Test the method `parse` from the ipv6 class.
    """
    ipv6_instance = ipv6(policy_dict, device)

    expected = {
        "nft": [
            {"template": "ip6 saddr {}", "match": "fd00::1"},
            {"template": "ip6 daddr {}", "match": "fd00::2"}
        ],
        "nfq": []
    }

    parsed = ipv6_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_backward() -> None:
    """
    Test the method `parse` from the ipv6 class,
    with a backward rule.
    """
    ipv6_instance = ipv6(policy_dict, device)

    expected = {
        "nft": [
            {"template": "ip6 daddr {}", "match": "fd00::1"},
            {"template": "ip6 saddr {}", "match": "fd00::2"}
        ],
        "nfq": []
    }

    parsed = ipv6_instance.parse(is_backward=True)
    assert dicts_equal(parsed, expected)


def test_parse_forward_aliases() -> None:
    """
    Test the method `parse` from the ipv6 class,
    with aliases.
    """
    ipv6_instance = ipv6(policy_dict_aliases, device)

    expected = {
        "nft": [
            {"template": "ip6 saddr {}", "match": "fd00::1"}
        ],
        "nfq": [
            {
                "template": '( dns_entry_contains(dns_map_get(dns_map, "{}"), (ip_addr_t) {{.version = 6, .value.ipv6 = dst_addr}}) )',
                "match": "example.com"
            }
        ]
    }

    parsed = ipv6_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_backward_aliases() -> None:
    """
    Test the method `parse` from the ipv6 class,
    with aliases and a backward rule.
    """
    ipv6_instance = ipv6(policy_dict_aliases, device)

    expected = {
        "nft": [
            {"template": "ip6 daddr {}", "match": "fd00::1"}
        ],
        "nfq": [
            {
                "template": '( dns_entry_contains(dns_map_get(dns_map, "{}"), (ip_addr_t) {{.version = 6, .value.ipv6 = src_addr}}) )',
                "match": "example.com"
            }
        ]
    }

    parsed = ipv6_instance.parse(is_backward=True)
    assert dicts_equal(parsed, expected)


def test_parse_forward_list() -> None:
    """
    Test the method `parse` from the ipv6 class,
    with a list of addresses.
    """
    ipv6_instance = ipv6(policy_dict_list, device)

    expected = {
        "nft": [
            {"template": "ip6 saddr {}", "match": "{ fd00::1, fd00::2 }"},
            {"template": "ip6 daddr {}", "match": "{ fd00::3, fd00::4 }"}
        ],
        "nfq": []
    }

    parsed = ipv6_instance.parse()
    assert dicts_equal(parsed, expected)
