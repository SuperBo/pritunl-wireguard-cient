import secrets
import base64


def rand_str(n: int) -> str:
    """Generate simple random string
    Args:
        - n: number of characters
    """
    string = ''
    while len(string) < n:
        string = secrets.token_urlsafe(n)
    return string[:n]


def rand_str_complex(n: int) -> str:
    """Generate complex random string
    Args:
        - n: number of characters
    """
    string = ''
    while len(string) < n:
        b = secrets.token_bytes(n)
        string = base64.a85encode(b).decode('ascii')
    return string[:n]
