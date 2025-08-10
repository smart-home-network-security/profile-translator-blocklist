from profile_translator_blocklist.protocols.Protocol import Protocol


def test_convert_value() -> None:
    """
    Test the static method `convert_value` from the Protocol class.
    """
    assert Protocol.convert_value("42") == 42
    assert Protocol.convert_value("not_a_number") == "not_a_number"
