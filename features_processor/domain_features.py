import dns.resolver
import tldextract
import pycountry
import dns.exception

class DomainFeatures:    

    def __init__(self, domain):
        self.domain = domain
        self.tld = tldextract.extract(domain).suffix

    def get_country_code(self):
        try:
            country = pycountry.countries.get(alpha_2=self.tld.upper())
            return country.alpha_2 if country else "null"
        except Exception:
            return "null"

    def get_mx_records(self):
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            return [rdata.exchange.to_text() for rdata in mx_records]
        except Exception:
            return "null"

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
            result['TXTDnsResponse'] = "null"
        
        return result

    def get_dns_records(self):
        mx_response = self.get_mx_records()
        txt_response = self.get_txt_records()
        dns_record_type = 'null'
        
        try:
            answer = dns.resolver.resolve(self.domain)
            if answer.rdtype == 1:
                dns_record_type = 'A'
            elif answer.rdtype == 2:
                dns_record_type = 'NS'
            elif answer.rdtype == 5:
                dns_record_type = 'CNAME'
            elif answer.rdtype == 6:
                dns_record_type = 'SOA'
            elif answer.rdtype == 12:
                dns_record_type = 'PTR'
            elif answer.rdtype == 15:
                dns_record_type = 'MX'
            elif answer.rdtype == 16:
                dns_record_type = 'TXT'
            elif answer.rdtype == 28:
                dns_record_type = 'AAAA'
            elif answer.rdtype == 33:
                dns_record_type = 'SRV'
            elif answer.rdtype == 35:
                dns_record_type = 'NAPTR'
            elif answer.rdtype == 39:
                dns_record_type = 'DNAME'
            elif answer.rdtype == 44:
                dns_record_type = 'SSHFP'
            elif answer.rdtype == 48:
                dns_record_type = 'DNSKEY'
            elif answer.rdtype == 49:
                dns_record_type = 'DS'
            elif answer.rdtype == 52:
                dns_record_type = 'TLSA'
            elif answer.rdtype == 257:
                dns_record_type = 'CAA'
        except dns.resolver.NXDOMAIN:
            dns_record_type = 'NXDOMAIN' 
        except dns.exception.DNSException as e:
            print('Error: ', e)
            dns_record_type = 'DNS_ERROR'

        return {
            'DNSRecordType': dns_record_type,
            'MXDnsResponse': mx_response,
            'TXTDnsResponse': txt_response['TXTDnsResponse'],
            'HasSPFInfo': txt_response['HasSPFInfo'],
            'HasDkimInfo': txt_response['HasDkimInfo'],
            'HasDmarcInfo': txt_response['HasDmarcInfo'],
        }