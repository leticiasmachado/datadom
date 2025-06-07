import requests
import socket
import dns.resolver

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
                sock.settimeout(3) 
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
        except Exception:
            return "null"

        return open_ports if open_ports else "null"

    def get_http_response_code(self):
        try:
            response = requests.get(f"http://{self.domain}", timeout=3) 
            return response.status_code
        except requests.exceptions.RequestException:
            return "null"

    def get_asn(self):
        try:
            result = dns.resolver.resolve(self.domain, 'A')
            ip = result[0].to_string()
            response = requests.get(f"https://ipinfo.io/{ip}/org", timeout=3)
            if response.status_code == 200:
                asn_info = response.text.strip()
                return asn_info.split(' ')[0]  # retorna número do ASN
            else:
                return "null"
        except Exception:
            return "null"
