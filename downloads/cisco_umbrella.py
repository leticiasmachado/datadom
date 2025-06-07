import requests
import zipfile
import io

class CiscoUmbrellaDownloader:
    def __init__(self, url, output_path):
        self.url = url
        self.output_path = output_path

    def download(self):
        response = requests.get(self.url)
        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
            with open(self.output_path, 'wb') as file:
                file.write(zip_ref.read('top-1m.csv'))
                print(f"File successfully downloaded: {self.output_path}")
