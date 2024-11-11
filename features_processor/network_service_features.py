import requests
import socket
from ipwhois import IPWhois, IPDefinedError

class NetworkServiceFeatures:
    def __init__(self, domain):
        self.domain = domain

    def get_common_ports(self):
        common_ports = [80, 443, 21, 22, 25]
        open_ports = []
        
        try:
            ip = socket.gethostbyname(self.domain)
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # timeout de 1 segundo por porta
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
        except Exception:
            return "Null"

        return open_ports if open_ports else "Null"

    def get_http_response_code(self):
        try:
            response = requests.get(f"http://{self.domain}", timeout=5)  # timeout de 5 segundos
            return response.status_code
        except requests.exceptions.RequestException:
            return "Null"

    def get_asn(self):
        try:
            ip = socket.gethostbyname(self.domain)
            obj = IPWhois(ip)
            # Tentativa de limitar o tempo das requisições Whois
            results = obj.lookup_rdap(asn_methods=["whois", "http"], timeout=5)  # timeout de 5 segundos
            return results['asn']
        except (Exception, IPDefinedError):  # IPDefinedError cobre o caso de IP reservado
            return "Null"
