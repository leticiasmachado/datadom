import requests
from pydnsbl import DNSBLChecker

class ToolFeatures:
    
    def __init__(self, domain, api_key):
        self.domain = domain
        self.API_KEY = api_key
    
    def calculate_malicious_score(self, ips):
        if not ips:
            return 0
    
        checker = DNSBLChecker()
    
        results = checker.check_ips(ips)
    
        scores = []
    
        for result in results:
            if result:
                score = int(str(result).split('/')[0].split('(')[-1].strip())
                scores.append(score)
    
        return sum(scores) / len(scores) if scores else 0

    def get_domain_reputation(self):
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
        headers = {"x-apikey": self.API_KEY}
        try:
            response = requests.get(url, headers=headers)
            return response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        except Exception:
            return {}
