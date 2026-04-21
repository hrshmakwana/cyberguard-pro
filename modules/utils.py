import socket
import ipaddress
def is_safe_target(host: str) -> bool:
    try:
        ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved:
            return False
        return True
    except socket.gaierror:
        return False
