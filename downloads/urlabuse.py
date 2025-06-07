import requests
import pandas as pd
import re

class UrlabuseDownloader:
    def __init__(self, url, output_path):
        self.url = url
        self.output_path = output_path

    def download(self):
        try: 
            response = requests.get(self.url, timeout=10)    
            with open(self.output_path, 'wb') as file:
                file.write(response.content)
            print(f"File successfully downloaded: {self.output_path}")
        except requests.exceptions.RequestException as e:
            print(f"Error downloading the file: {e}")
        except Exception as e:
            print(f"Error processing the file: {e}")

    def clean_file(self):
        try:
            df = pd.read_csv(self.output_path, skiprows=8, header=None)
            df_second_column = df[[2]]  # Mantém apenas a segunda coluna
            df_second_column.to_csv(self.output_path, index=False, header=False)
            print(f"File cleaned and overwritten: {self.output_path}")
        except Exception as e:
            print(f"Error processing the file: {e}")

    def extract_domain(self):
        try:
            with open(self.output_path, 'r', encoding='utf-8') as file:
                urls = file.readlines()

            domains = set()  # Usando um conjunto para evitar duplicatas
            for url in urls:
                domain = self.clean_domain(url.strip())
                if domain:  # Adiciona o domínio se não for vazio
                    domains.add(domain)

            # Sobrescreve o arquivo com os domínios únicos
            with open(self.output_path, 'w') as file:
                for domain in domains:
                    file.write(domain + '\n')

            print(f"Domains extracted and overwritten: {self.output_path}")
        except Exception as e:
            print(f"Error processing the domains: {e}")

    @staticmethod
    def clean_domain(url):
        # Remove 'http://', 'https://', 'www.', e extrai o domínio
        domain = re.sub(r'^(https?://)?(www\.)?', '', url)  
        domain = domain.split('/')[0] 
        domain = domain.split(':')[0] 
        return domain
