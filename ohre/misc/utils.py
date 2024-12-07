def is_uppercase_or_underscore(s: str):
    return all(c.isupper() or c.isdigit() or c == "_" for c in s)
