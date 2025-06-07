import requests
import pandas as pd

class BambenekIPsDownloader: 
    def __init__(self, username, password):
        self.url = f'https://{username}:{password}@faf.bambenekconsulting.com/feeds/dga/c2-ipmasterlist-high.txt'
        self.output_path = './data/bambenek_ips.csv'

    def download(self):
        try:
            response = requests.get(self.url, timeout=10)
            response.raise_for_status()
            with open(self.output_path, 'wb') as file:
                file.write(response.content)
            print(f"File successfully downloaded: {self.output_path}")
        except requests.exceptions.RequestException as e:
            print(f"Error downloading the file: {e}")

    def clean_file(self):
        try:
            df = pd.read_csv(self.output_path, skiprows=18, header=None)
            if 0 in df.columns:
                df_first_column = df[[0]]
                df_first_column.to_csv(self.output_path, index=False, header=False)
                print(f"File cleaned and overwritten: {self.output_path}")
            else:
                print(f"First column not found in the file: {self.output_path}")
        except pd.errors.EmptyDataError:
            print(f"The file is empty or could not be read: {self.output_path}")
        except Exception as e:
            print(f"Error processing the file: {e}")

 