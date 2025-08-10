from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.http import http
from .utils import dicts_equal


### TEST VARIABLES ###
device = {
    "name": "device-test",
    "mac":  "11:22:33:44:55:66",
    "ipv4": "192.168.1.2"
}
policy_dict = {
    "method": "GET",
    "uri": "/index.html"
}
policy_dict_prefix = {
    "method": "GET",
    "uri": "/resources/*"
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    http_instance = Protocol.init_protocol("http", policy_dict, device)
    assert isinstance(http_instance, http)
    assert http_instance.protocol_name == "http"
    assert http_instance.protocol_data == policy_dict
    assert http_instance.device == device


def test_parse_forward() -> None:
    """
    Test the method `parse` from the http class,
    in the forward direction.
    """
    http_instance = http(policy_dict, device)
    
    uri = policy_dict["uri"]
    expected = {
        "nft": [],
        "nfq": [
            {"template": "{}http_message.is_request", "match": ""},
            {"template": "http_message.method == {}", "match": "HTTP_GET"},
            {"template": f'strncmp(http_message.uri, "{{}}", {len(uri) + 1}) == 0',
             "match": uri}
        ]
    }
    
    parsed = http_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_backward() -> None:
    """
    Test the method `parse` from the http class,
    in the backward direction.
    """
    http_instance = http(policy_dict, device)
    
    expected = {
        "nft": [],
        "nfq": [
            {"template": "{}http_message.is_request", "match": "!"}
        ]
    }
    
    parsed = http_instance.parse(is_backward=True)
    assert dicts_equal(parsed, expected)


def test_parse_prefix() -> None:
    """
    Test the method `parse` from the http class,
    with a URI prefix.
    """
    http_instance = http(policy_dict_prefix, device)
    
    uri_prefix = policy_dict_prefix["uri"]
    expected = {
        "nft": [],
        "nfq": [
            {"template": "{}http_message.is_request", "match": ""},
            {"template": "http_message.method == {}", "match": "HTTP_GET"},
            {"template": f'strncmp(http_message.uri, "{{}}", {len(uri_prefix) - 1}) == 0',
             "match": uri_prefix}
        ]
    }
    
    parsed = http_instance.parse()
    assert dicts_equal(parsed, expected)
