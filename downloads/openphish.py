import requests
import re

class OpenPhishDownloader:
    def __init__(self, url, output_path):
        self.url = url
        self.output_path = output_path

    def download(self):
        response = requests.get(self.url)    
        if response.status_code == 200:
            with open(self.output_path, 'wb') as file:
                file.write(response.content)
            print(f"File downloaded successfully and saved to: {self.output_path}")
        else:
            print(f"Failed to download the file. Status code: {response.status_code}")

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
            print(f"Error processing domains: {e}")

    @staticmethod
    def clean_domain(url):
        domain = re.sub(r'^(https?://)?(www\.)?', '', url)  
        domain = domain.split('/')[0] 
        return domain