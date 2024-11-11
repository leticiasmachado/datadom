import dns.resolver
import tldextract
import pycountry

class DomainFeatures:    

    def __init__(self, domain):
        self.domain = domain
        self.tld = tldextract.extract(domain).suffix

    def get_country_code(self):
        try:
            country = pycountry.countries.get(alpha_2=self.tld.upper())
            return country.alpha_2 if country else "Null"
        except Exception:
            return "Null"

    def get_mx_records(self):
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            return [rdata.exchange.to_text() for rdata in mx_records]
        except Exception:
            return "Null"

    def get_txt_records(self):
        result = {
            'TXTDnsResponse': [],
            'HasSPFInfo': False,
            'HasDkimInfo': False,
            'HasDmarcInfo': False,
        }
        
        try:
            txt_records = dns.resolver.resolve(self.domain, 'TXT')
            for rdata in txt_records:
                txt_record_str = rdata.to_text()
                result['TXTDnsResponse'].append(txt_record_str)
                result['HasSPFInfo'] = result['HasSPFInfo'] or 'v=spf1' in txt_record_str
                result['HasDkimInfo'] = result['HasDkimInfo'] or 'dkim' in txt_record_str
                result['HasDmarcInfo'] = result['HasDmarcInfo'] or '_dmarc' in txt_record_str
        except Exception:
            result['TXTDnsResponse'] = "Null"
        
        return result

    def get_dns_records(self):
        mx_response = self.get_mx_records()
        txt_response = self.get_txt_records()

        return {
            'DNSRecordType': ['MX' if mx_response != "Null" else 'Null', 'TXT' if txt_response['TXTDnsResponse'] else 'Null'],
            'MXDnsResponse': mx_response,
            'TXTDnsResponse': txt_response['TXTDnsResponse'],
            'HasSPFInfo': txt_response['HasSPFInfo'],
            'HasDkimInfo': txt_response['HasDkimInfo'],
            'HasDmarcInfo': txt_response['HasDmarcInfo'],
        }
