import whois
import re

class WhoisFeatures:
    def __init__(self, domain):
        self.domain = self.clean_domain(domain)
        self.whois_data = self.get_whois_info()

    def clean_domain(self, domain):
        # Verifica se o domínio é um IP e remove o ponto final, se houver
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}\.$', domain):
            return domain.rstrip('.') 
        return domain

    def get_whois_info(self):
        try:
            w = whois.whois(self.domain)
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = [dt.replace(tzinfo=None) for dt in creation_date]
                creation_date = min(creation_date)
            elif creation_date is not None:
                creation_date = creation_date.replace(tzinfo=None)
        
            if creation_date:
                creation_date = creation_date.strftime('%Y-%m-%d')

            expiration_date = w.expiration_date

            if isinstance(expiration_date, list):
                expiration_date = [dt.replace(tzinfo=None) for dt in expiration_date]
                expiration_date = min(expiration_date)
            elif expiration_date is not None:
                expiration_date = expiration_date.replace(tzinfo=None)
        
            if expiration_date:
                expiration_date = expiration_date.strftime('%Y-%m-%d')

            updated_date = w.updated_date

            if isinstance(updated_date, list):
                updated_date = [dt.replace(tzinfo=None) for dt in updated_date]
                updated_date = min(updated_date)
            elif updated_date is not None:
                updated_date = updated_date.replace(tzinfo=None)
        
            if updated_date:
                updated_date = updated_date.strftime('%Y-%m-%d')
            return {
                'RegisteredOrg': w.registrar,
                'CreationDate': creation_date,
                'ExpirationDate': expiration_date,
                'UpdatedDate': updated_date,
                'RegisteredCountry': w.country,
                'NameServers': w.name_servers
            }
        except Exception as e:
            return {
                'RegisteredOrg': "Null",
                'CreationDate': "Null",
                'ExpirationDate': "Null",
                'UpdatedDate': "Null",
                'RegisteredCountry': "Null",
                'NameServers': "Null",
                'error': str(e)
            }

    def get_registered_org(self):
        return self.whois_data['RegisteredOrg']

    def get_creation_date(self):
        return self.whois_data['CreationDate']

    def get_expiration_date(self):
        return self.whois_data['ExpirationDate']

    def get_last_update_date(self):
        return self.whois_data['UpdatedDate']

    def get_registered_country(self):
        return self.whois_data['RegisteredCountry']

    def get_name_servers(self):
        return self.whois_data['NameServers']