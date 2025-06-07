import dns.resolver
import requests

class IPFeatures:
    def __init__(self, domain):
        self.domain = domain

    def get_dns_server_ips(self):
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            ns_ips = []
            for ns_record in ns_records:
                try:
                    ns_name = str(ns_record.target).rstrip('.')
                    a_records = dns.resolver.resolve(ns_name, 'A')
                    ns_ips.extend([str(a_record.address) for a_record in a_records])
                except Exception:
                    continue
            return ns_ips
        except Exception:
            return []

    def get_host_ips(self):
        try:
            a_records = dns.resolver.resolve(self.domain, 'A')
            return [str(a_record.address) for a_record in a_records]
        except Exception:
            return []

    def get_dns_server_countries(self):
        dns_server_ips = self.get_dns_server_ips()
        return [self.get_ip_location(ip).get('country', 'Unknown') for ip in dns_server_ips]

    def get_host_countries(self):
        host_ips = self.get_host_ips()
        return [self.get_ip_location(ip).get('country', 'Unknown') for ip in host_ips]

    def get_ip_location(self, ip):
        try:
            # Fazendo requisição para a API de geolocalização
            response = requests.get(f"https://ipapi.co/{ip}/json/")
            # Verificando se a resposta foi bem-sucedida
            if response.status_code == 200:
                data = response.json()
                # Verifica se a resposta contém o campo 'country'
                if 'country' in data:
                    return data
                else:
                    return {'country': 'Unknown'}  # Retorna 'Unknown' se não tiver 'country'
            else:
                return {'country': 'Unknown'}
        except requests.RequestException as e: #erro
            return {'country': 'Unknown'}
