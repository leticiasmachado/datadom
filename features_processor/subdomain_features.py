import requests
from collections import Counter
import math

class SubdomainFeatures:
    
    def __init__(self, domain, api_key):
        self.domain = domain
        self.API_KEY = api_key
        self.subdomains = self.get_subdomains() 

    def get_subdomains(self):
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        headers = {"x-apikey": self.API_KEY}
        try:
            response = requests.get(url, headers=headers)
            subdomains_data = response.json().get('data', [])
            return [subdomain['id'] for subdomain in subdomains_data] 
        except Exception as e: #erro
            return []

    def get_subdomain_count(self):
        return len(self.subdomains) 

    def calculate_entropy(self, domain):
        char_count = Counter(domain)
        total_chars = len(domain)
        entropy = 0.0
        for count in char_count.values():
            p_x = count / total_chars
            entropy += -p_x * math.log2(p_x)
        return entropy

    def calculate_entropy_of_subdomains(self):
        if not self.subdomains:
            return 0
        return self.calculate_entropy(''.join(self.subdomains))  
