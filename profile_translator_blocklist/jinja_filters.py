"""
Custom Jinja2 filters for the `profile-translator` package.
"""

def is_list(value: any) -> bool:
    """
    Custom filter for Jinja2, to check whether a value is a list.

    :param value: value to check
    :return: True if value is a list, False otherwise
    """
    return isinstance(value, list)


def debug(value: any) -> str:
    """
    Custom filter for Jinja2, to print a value.

    :param value: value to print
    :return: an empty string
    """
    print(str(value))
    return ""
