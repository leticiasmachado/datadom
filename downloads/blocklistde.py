import requests

class BlocklistDeDownloader:
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


