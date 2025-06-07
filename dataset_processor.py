import tldextract
import pandas as pd
import csv
import os
import threading
import time
from features_processor.domain_features import DomainFeatures
from features_processor.ip_features import IPFeatures
from features_processor.lexical_features import LexicalFeatures
from features_processor.subdomain_features import SubdomainFeatures
from features_processor.tool_features import ToolFeatures
from features_processor.whois_features import WhoisFeatures
from features_processor.network_service_features import NetworkServiceFeatures

class DomainDatasetProcessor:
    def __init__(self, domain_checker_allowlists, domain_checker_blocklists_domain, domain_checker_blocklists_ip, selected_features, virus_total_APIKEY):
        self.domain_checker_allowlists = domain_checker_allowlists
        self.domain_checker_blocklists_domain = domain_checker_blocklists_domain
        self.domain_checker_blocklists_ip = domain_checker_blocklists_ip
        self.selected_features = selected_features  
        self.quit = threading.Event() 
        self.exit_event = threading.Event()
        self.lock = threading.Lock()
        self.threads = []
        self.num_threads_alive = 0
        self.virus_total_APIKEY = virus_total_APIKEY

    def process_domain(self, domain):
        """
        processa um domínio e retorna os dados (dicionário)
        """
        row_data = {'Domain': domain}
        class_label = 1  # inicializa como malicioso
        ip_features = IPFeatures(domain)  
        host_ips = ip_features.get_host_ips()             

        # verifica se o domínio está em allowlist
        if self.domain_checker_allowlists.check_domain_in_majestic(domain) or \
           self.domain_checker_allowlists.check_domain_in_cisco_umbrella(domain):
            class_label = 0  
        row_data['Class'] = class_label

        # extração de características selecionadas
        if self.selected_features.get("domain", False):
            domain_features = DomainFeatures(domain)
            dns_records = domain_features.get_dns_records()
            row_data.update({
                'CountryCode': domain_features.get_country_code(),
                'DNSRecordType': dns_records['DNSRecordType'],
                'MXDnsResponse': dns_records['MXDnsResponse'],
                'TXTDnsResponse': dns_records['TXTDnsResponse'],
                'HasSPFInfo': dns_records['HasSPFInfo'],
                'HasDkimInfo': dns_records['HasDkimInfo'],
                'HasDmarcInfo': dns_records['HasDmarcInfo']
            })

        if self.selected_features.get("whois", False):
            whois_features = WhoisFeatures(domain)

            whois_data = {
                'RegisteredOrg': whois_features.get_registered_org(),
                'CreationDate': whois_features.get_creation_date(),
                'ExpirationDate': whois_features.get_expiration_date(),
                'LastUpdateDate': whois_features.get_last_update_date(),
                'RegisteredCountry': whois_features.get_registered_country(),
                'NameServers': whois_features.get_name_servers()
            }
            whois_data = {key: (value if value is not None else "Null") for key, value in whois_data.items()}
                    
            row_data.update(whois_data)

        if self.selected_features.get("subdomains", False):
            subdomain_features = SubdomainFeatures(domain, self.virus_total_APIKEY)
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
            tool_features = ToolFeatures(domain, self.virus_total_APIKEY)
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

        # Verificação de blocklists
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

        # Verificação de allowlists
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

        return row_data

    def process_chunk(self, chunk, output_csv_path, header):
        """
        processa um chunk de domínios e grava os resultados no arquivo CSV
        """
        with open(output_csv_path, mode='a', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header)
    
            index = 0
            while index < len(chunk) and not self.quit.is_set():
                row = chunk.iloc[index]
                extracted_domain = tldextract.extract(row['Domain'])
                if extracted_domain.suffix != '':
                    domain = f"{extracted_domain.domain}.{extracted_domain.suffix}"
                else:
                    domain = row['Domain']
                row_data = self.process_domain(domain)
                # evitar concorrência ao atualizar o arquivo 'input.csv'
                with self.lock:
                    if os.path.exists('input.csv') and os.path.getsize('input.csv') > 0:
                        writer.writerow(row_data)
                        df_input = pd.read_csv('input.csv')
                        df_input.loc[df_input['Domain'] == row['Domain'], 'OK'] = True
                        df_input.to_csv('input.csv', index=False)
                        
                    else:
                        print("The 'input.csv' file is empty or does not exist. No updates were made.")

                index += 1
    
    def wait_for_exit(self):
        # thread separada para monitorar a entrada do usuário
        def input_listener(quit_event, exit_event):
            while not exit_event.is_set():
                input("PRESS ENTER TO EXIT...\n")
                quit_event.set()  # sinal para encerrar 
            exit_event.set()

        
        listener_thread = threading.Thread(target=input_listener, args=(self.quit, self.exit_event))
        listener_thread.daemon = True  # daemon: encerra sozinha quando o programa principal finalizar
        listener_thread.start()

        while not self.exit_event.is_set():
            if not self.quit.is_set():
                print("Execution in progress... Press ENTER to exit.")
                time.sleep(15) 
            else: 
                print('Shutting down threads (this may take a few minutes.)')
                time.sleep(15) 

        if not self.exit_event.is_set():
            # Finaliza threads
            for thread in self.threads:
                thread.join()
                self.num_threads_alive =-1
                print(f"Thread {thread.name} terminated.")

        if self.num_threads_alive == 0:
            print("All threads have been shut down.")

    def create_combined_csv(self, input_csv_path, output_csv_path, num_threads, num_domains):
        """
        cria o CSV, usa processando paralelo com threads
        """
        start = time.time()
        df = pd.read_csv(input_csv_path) 
        df = df.sample(frac=1).reset_index(drop=True) #embaralhar domínios

        # definindo cabeçalho
        header = ['Domain']
        if self.selected_features.get("domain", False):
            header.extend(['CountryCode', 'DNSRecordType', 'MXDnsResponse', 'TXTDnsResponse',
                'HasSPFInfo', 'HasDkimInfo', 'HasDmarcInfo'])
        if self.selected_features.get("whois", False):
            header.extend(['RegisteredOrg', 'CreationDate', 'ExpirationDate', 'LastUpdateDate',
                'RegisteredCountry', 'NameServers'])
        if self.selected_features.get("subdomains", False):
            header.extend(['SubdomainCount', 'EntropyOfSubDomains'])
        if self.selected_features.get("ipAddresses", False):
            header.extend(['HostIPs', 'DNSServersIPs', 'DNSServersCountries', 'HostIPsCountries'])
        if self.selected_features.get("tools", False):
            header.extend(['IpReputationDnsblInfo', 'DomainReputationVirusTotal'])
        if self.selected_features.get("network", False):
            header.extend(['CommonPorts', 'HttpResponseCode', 'ASN'])
        if self.selected_features.get("lexical", False):
            header.extend(['StrangeCharacters', 'ConsonantRatio', 'VowelRatio', 'NumericRatio',
                'SpecialCharRatio', 'ConsonantSequence', 'VowelSequence', 'NumericSequence', 
                'SpecialCharSequence', 'Entropy', 'DomainLength'])
        if self.selected_features.get("DomainInOpenPhish", False):
            header.extend(['DomainInOpenPhish'])
        if self.selected_features.get("DomainInHagezi", False):
            header.extend(['DomainInHagezi'])
        if self.selected_features.get("DomainInUrlAbuse", False):
            header.extend(['DomainInUrlAbuse'])
        if self.selected_features.get("DomainInBambenekDomains", False):
            header.extend(['DomainInBambenekDomains'])
        if self.selected_features.get("DomainInPhishTank", False):
            header.extend(['DomainInPhishTank'])
        if self.selected_features.get("DomainInAbuseCh", False):
            header.extend(['DomainInAbuseCh'])
        if self.selected_features.get("IpInBlocklistDe", False):
            header.extend(['IpInBlocklistDe'])
        if self.selected_features.get("IpInBambenek", False):
            header.extend(['IpInBambenek'])
        if self.selected_features.get("DomainInMajesticMillion", False):
            header.extend(['DomainInMajesticMillion'])
        if self.selected_features.get("DomainInCiscoUmbrella", False):
            header.extend(['DomainInCiscoUmbrella'])
        header.extend(['Class'])

        # criar arquivo CSV e escrever o cabeçalho
        with open(output_csv_path, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header)
            writer.writeheader()

        # dividir dataframe em pedaços para cada thread
        chunk_size = len(df) // num_threads
        chunks = [df[i:i + chunk_size] for i in range(0, len(df), chunk_size)]

        exit_thread = threading.Thread(target=self.wait_for_exit, args=())
        exit_thread.start()

        for chunk in chunks:
            thread = threading.Thread(target=self.process_chunk, args=(chunk, output_csv_path, header))
            self.threads.append(thread)
            thread.start()
            self.num_threads_alive +=1
    
        # Aguardar a conclusão de todas as threads de processamento
        for thread in self.threads:
            thread.join()  # Espera cada thread terminar
            print(f'Thread {thread.name} terminated.')
            self.num_threads_alive -= 1            

        # Se a thread de espera não foi encerrada, ela pode ser finalizada
        if self.num_threads_alive == 0:
            self.exit_event.set()
            exit_thread.join()

        if not self.quit.is_set() and self.num_threads_alive == 0:
            print(f"Combined CSV file successfully created: {output_csv_path}")
            end = time.time()
            elapsed_time_seconds = end - start

            # Calculando horas, minutos e segundos
            hours = int(elapsed_time_seconds // 3600)
            minutes = int((elapsed_time_seconds % 3600) // 60)
            seconds = int(elapsed_time_seconds % 60)

            print(f"Processing complete!")
            print(f"{elapsed_time_seconds:.2f} seconds to process {num_domains} domains with {num_threads} threads. ({hours} hours, {minutes} minutes, and {seconds} seconds)")
        
            try:
                os.remove('input.csv')
                print("'input.csv' file successfully removed.")
            except FileNotFoundError:
                print("The 'input.csv' file was not found.")
            except Exception as e:
                print(f"Error trying to remove the file: {e}")

