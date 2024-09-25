"""
Jinja2-related functions.
"""

import jinja2


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


def create_jinja_env(package: str) -> jinja2.Environment:
    """
    Create a Jinja2 environment with custom filters.

    Args:
        package (str): package name
    Returns:
        Jinja2 environment
    """
    # Create Jinja2 environment
    loader = jinja2.PackageLoader(package, "templates")
    env = jinja2.Environment(loader=loader, trim_blocks=True, lstrip_blocks=True)

    # Add custom Jinja2 filters
    env.filters["debug"] = debug
    env.filters["is_list"] = is_list
    env.filters["any"] = any
    env.filters["all"] = all
    
    return env
