import requests
import pandas as pd

class HageziDownloader:
    def __init__(self, url, output_path):
        self.url = url
        self.output_path = output_path

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
            df = pd.read_csv(self.output_path, skiprows=11, header=None)
            df.to_csv(self.output_path, index=False, header=False)
            print(f"File cleaned and overwritten: {self.output_path}")
        except pd.errors.EmptyDataError:
            print(f"The file is empty or could not be read: {self.output_path}")
        except Exception as e:
            print(f"Error processing the file: {e}")
