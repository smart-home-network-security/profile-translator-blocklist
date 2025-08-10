def dicts_equal(d1: dict, d2: dict) -> bool:
    """
    Recursively compare two dictionaries (and lists) ignoring key order.

    Args:
        d1 (dict): First dictionary to compare.
        d2 (dict): Second dictionary to compare.
    Returns:
        bool: True if the dictionaries are equal, False otherwise.
    """
    if isinstance(d1, dict) and isinstance(d2, dict):
        if set(d1.keys()) != set(d2.keys()):
            return False
        return all(dicts_equal(d1[k], d2[k]) for k in d1)
    
    elif isinstance(d1, list) and isinstance(d2, list):
        # Compare lists regardless of order
        if len(d1) != len(d2):
            return False
        return all(any(dicts_equal(i, j) for j in d2) for i in d1)
    
    else:
        return d1 == d2
