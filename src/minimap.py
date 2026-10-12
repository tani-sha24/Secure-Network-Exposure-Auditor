import argparse
import errno
import ipaddress
import socket

PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    631: "IPP/CUPS",
    5000: "Development web app",
}


def validate_target(target):
    """Accept only one loopback or private IPv4 address."""
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 address.") from exc

    if address.version != 4:
        raise ValueError("This version supports IPv4 only.")

    if not (address.is_loopback or address.is_private):
        raise ValueError(
            "For this version, use a loopback or private IPv4 address."
        )

    return str(address)


def check_port(target, port, timeout=0.8):
    """Check whether one TCP connection can be established."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))

        if result == 0:
            return "OPEN"
        if result == errno.ECONNREFUSED:
            return "CLOSED"
        return "NO RESPONSE / ERROR"

    except socket.timeout:
        return "NO RESPONSE / TIMEOUT"
    except OSError:
        return "NO RESPONSE / ERROR"


def main():
    parser = argparse.ArgumentParser(
        description="MiniMap: a small TCP exposure checker for authorized labs."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="127.0.0.1",
        help="one loopback or private IPv4 address (default: 127.0.0.1)",
    )
    args = parser.parse_args()

    try:
        target = validate_target(args.target)
    except ValueError as error:
        parser.error(str(error))

    print("MiniMap - TCP Exposure Checker")
    print(f"Target: {target}")
    print("-" * 48)
    print(f"{'PORT':<8}{'SERVICE':<24}STATUS")
    print("-" * 48)

    for port, service in PORTS.items():
        status = check_port(target, port)
        print(f"{port:<8}{service:<24}{status}")

    print("-" * 48)
    print("Note: results show TCP reachability, not vulnerability.")


if __name__ == "__main__":
    main() 
