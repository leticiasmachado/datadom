import requests
import pandas as pd
import re

class AbusechDownloader:
    def __init__(self, url, output_path):
        self.url = url
        self.output_path = output_path

    def download(self):
        try:
            response = requests.get(self.url, timeout=10)
            response.raise_for_status() 
            with open(self.output_path, 'wb') as file:
                file.write(response.content)
            print(f"File downloaded successfully: {self.output_path}")
        except requests.exceptions.RequestException as e:
            print(f"Error downloading: {e}")

    def clean_file(self):
        try:
            df = pd.read_csv(self.output_path, skiprows=8, header=None)

            if 2 in df.columns:
                df_third_column = df[[2]] 
                df_third_column.to_csv(self.output_path, index=False, header=False)
                print(f"File cleaned and overwritten: {self.output_path}")
            else:
                print(f"Third column not found in the file: {self.output_path}")
        except pd.errors.EmptyDataError:
            print(f"The file is empty or could not be read: {self.output_path}")
        except Exception as e:
            print(f"Error processing the file: {e}")

    def extract_domain(self):
        try:
            with open(self.output_path, 'r', encoding='utf-8') as file:
                urls = file.readlines()

            domains = set() 
            for url in urls:
                domain = self.clean_domain(url.strip())
                if domain: 
                    domains.add(domain)

            with open(self.output_path, 'w') as file:
                for domain in domains:
                    file.write(domain + '\n')

            print(f"Domains extracted and overwritten: {self.output_path}")
        except Exception as e:
            print(f"Error processing the domains: {e}")

    @staticmethod
    def clean_domain(url):
        domain = re.sub(r'^(https?://)?(www\.)?', '', url) 
        domain = domain.split('/')[0] 
        domain = domain.split(':')[0] 
        return domain