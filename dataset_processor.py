import tldextract
import pandas as pd
from features_processor.domain_features import DomainFeatures
from features_processor.ip_features import IPFeatures
from features_processor.lexical_features import LexicalFeatures
from features_processor.subdomain_features import SubdomainFeatures
from features_processor.tool_features import ToolFeatures
from features_processor.whois_features import WhoisFeatures
from features_processor.network_service_features import NetworkServiceFeatures
import time

class DomainDatasetProcessor:
    def __init__(self, domain_checker_allowlists, domain_checker_blocklists_domain, domain_checker_blocklists_ip, selected_features):
        self.domain_checker_allowlists = domain_checker_allowlists
        self.domain_checker_blocklists_domain = domain_checker_blocklists_domain
        self.domain_checker_blocklists_ip = domain_checker_blocklists_ip
        self.selected_features = selected_features  

    def create_combined_csv(self, input_csv_path, output_csv_path):
        df = pd.read_csv(input_csv_path, header=None) 
        df = df.iloc[1:].reset_index(drop=True)
        df = df.sample(frac=1).reset_index(drop=True)
        data = []
        
        for index, row in df.iterrows():
            extracted_domain = tldextract.extract(row[0]) 
            
            domain = f"{extracted_domain.domain}.{extracted_domain.suffix}"
            ip_features = IPFeatures(domain)  
            host_ips = ip_features.get_host_ips()             
            row_data = {'Domain': domain}

            class_label = 1  

            if self.domain_checker_allowlists.check_domain_in_majestic(domain) or self.domain_checker_allowlists.check_domain_in_cisco_umbrella(domain):
                class_label = 0  
            
            if self.selected_features.get("domain", False):
                domain_features = DomainFeatures(domain)
                dns_records = domain_features.get_dns_records()
                row_data.update({
                    'CountryCode': domain_features.get_country_code(),
                    'MXDnsResponse': dns_records['MXDnsResponse'],
                    'TXTDnsResponse': dns_records['TXTDnsResponse'],
                    'HasSPFInfo': dns_records['HasSPFInfo'],
                    'HasDkimInfo': dns_records['HasDkimInfo'],
                    'HasDmarcInfo': dns_records['HasDmarcInfo']
                })

            if self.selected_features.get("whois", False):
                whois_features = WhoisFeatures(domain)
                row_data.update({
                    'RegisteredOrg': whois_features.get_registered_org(),
                    'CreationDate': whois_features.get_creation_date(),
                    'ExpirationDate': whois_features.get_expiration_date(),
                    'UpdatedDate': whois_features.get_last_update_date(),
                    'RegisteredCountry': whois_features.get_registered_country(),
                    'NameServers': whois_features.get_name_servers()
                })

            if self.selected_features.get("subdomains", False):
                subdomain_features = SubdomainFeatures(domain)
                row_data.update({
                    'SubdomainCount': subdomain_features.get_subdomain_count(),
                    'EntropyOfSubDomains': subdomain_features.calculate_entropy_of_subdomains()
                })
                
            if self.selected_features.get("ipAddresses", False):
                row_data.update({
                    'HostIPs': host_ips, 
                    'DNSServersIPs': ip_features.get_dns_server_ips(),
                    'DNSServersCountries': ip_features.get_dns_server_countries(),
                    'HostIPsCountries': ip_features.get_host_countries()
                })

            if self.selected_features.get("tools", False):
                tool_features = ToolFeatures(domain)
                row_data.update({
                    'IpReputationDnsblInfo': tool_features.calculate_malicious_score(host_ips),
                    'DomainReputationVirusTotal': tool_features.get_domain_reputation()
                })
                

            if self.selected_features.get("network", False):
                network_service_features = NetworkServiceFeatures(domain)
                row_data.update({
                    'CommonPorts': network_service_features.get_common_ports(),
                    'HttpResponseCode': network_service_features.get_http_response_code(),
                    'ASN': network_service_features.get_asn()
                })

            if self.selected_features.get("lexical", False):
                lexical_features = LexicalFeatures(domain)
                row_data.update({
                    'StrangeCharacters': lexical_features.get_strange_characters(),
                    'ConsonantRatio': lexical_features.get_consonant_ratio(),
                    'VowelRatio': lexical_features.get_vowel_ratio(),
                    'NumericRatio': lexical_features.get_numeric_ratio(),
                    'SpecialCharRatio': lexical_features.get_special_char_ratio(),
                    'ConsonantSequence': lexical_features.get_consonant_sequence(),
                    'VowelSequence': lexical_features.get_vowel_sequence(),
                    'NumericSequence': lexical_features.get_numeric_sequence(),
                    'SpecialCharSequence': lexical_features.get_special_char_sequence(),
                    'Entropy': lexical_features.calculate_entropy(),
                    'DomainLength': lexical_features.get_domain_length()
                })

            if self.selected_features.get("DomainInOpenPhish", False):
                domain_openphish = self.domain_checker_blocklists_domain.check_domain_in_openphish(domain)
                row_data.update({'DomainInOpenPhish': domain_openphish})

            if self.selected_features.get("DomainInHagezi", False):
                domain_hagezi = self.domain_checker_blocklists_domain.check_domain_in_hagezi(domain)
                row_data.update({'DomainInHagezi': domain_hagezi})                

            if self.selected_features.get("DomainInUrlAbuse", False):
                domain_urlabuse = self.domain_checker_blocklists_domain.check_domain_in_urlabuse(domain)
                row_data.update({'DomainInUrlAbuse': domain_urlabuse})

            if self.selected_features.get("DomainInBambenekDomains", False):
                domain_bambenek = self.domain_checker_blocklists_domain.check_domain_in_bambenek(domain)
                row_data.update({'DomainInBambenekDomains': domain_bambenek})                

            if self.selected_features.get("DomainInPhishTank", False):
                domain_phishtank = self.domain_checker_blocklists_domain.check_domain_in_phishtank(domain)
                row_data.update({'DomainInPhishTank': domain_phishtank})

            if self.selected_features.get("DomainInAbuseCh", False):
                domain_abusech = self.domain_checker_blocklists_domain.check_domain_in_abusech(domain)
                row_data.update({'DomainInAbuseCh': domain_abusech})

            if self.selected_features.get("IpInBlocklistDe", False):
                ip_blocklistde = self.domain_checker_blocklists_ip.check_ips_in_blocklist_de(host_ips)
                row_data.update({'IpInBlocklistDe': ip_blocklistde})

            if self.selected_features.get("IpInBambenek", False):
                ip_bambenek = self.domain_checker_blocklists_ip.check_ips_in_bambenek(host_ips)
                row_data.update({'IpInBambenek': ip_bambenek})

            if self.selected_features.get("DomainInMajesticMillion", False):
                majestic_rank = self.domain_checker_allowlists.check_domain_in_majestic(domain)
                row_data.update({
                    'DomainInMajesticMillion': majestic_rank
                })                
            
            if self.selected_features.get("DomainInCiscoUmbrella", False):
                cisco_umbrella_rank = self.domain_checker_allowlists.check_domain_in_cisco_umbrella(domain)
                row_data.update({
                    'DomainInCiscoUmbrella': cisco_umbrella_rank
                })

            row_data['Class'] = class_label
            data.append(row_data)
            time.sleep(0.2)

        combined_df = pd.DataFrame(data)
        combined_df.to_csv(output_csv_path, index=False)
        print(f"Combined CSV file created successfully: {output_csv_path}")
