from downloads.abusech import AbusechDownloader
from downloads.bambenek_domains import BambenekDomainsDownloader
from downloads.bambenek_ips import BambenekIPsDownloader
from downloads.blocklistde import BlocklistDeDownloader
from downloads.cisco_umbrella import CiscoUmbrellaDownloader
from downloads.hagezi import HageziDownloader
from downloads.majestic_million import MajesticMillionDownloader
from downloads.openphish import OpenPhishDownloader
from downloads.phishtank import PhishtankDownloader
from downloads.urlabuse import UrlabuseDownloader

class DownloadFiles:
    def __init__(self, datasets_download, username_bambenek, password_bambenek):
        self.datasets = datasets_download
        self.username_bambenek = username_bambenek
        self.password_bambenek = password_bambenek

    def download(self):
        #ABUSECH
        if 'Abuse.ch' in self.datasets:
            print('DOWNLOADING ABUSE.CH')
            abusech_url = 'https://urlhaus.abuse.ch/downloads/csv_online/'
            abusech_output_file = './data/abusech.csv'
            downloader = AbusechDownloader(abusech_url, abusech_output_file)
            downloader.download()
            downloader.clean_file() 
            downloader.extract_domain()
            
        #BAMBENEK - DOMAINS
        if 'BambenekDomains' in self.datasets:
            print('DOWNLOADING BAMBENEK DOMAINS')
            downloader = BambenekDomainsDownloader(self.username_bambenek, self.password_bambenek)
            downloader.download()
            downloader.clean_file()  
            
        #BAMBENEK - IPs
        if 'BambenekIPs' in self.datasets:
            print('DOWNLOADING BAMBENEK IPs')
            downloader = BambenekIPsDownloader()
            downloader.download()
            downloader.clean_file() 
        
        #BLOCKLISTDE
        if 'BlocklistDE' in self.datasets:
            print('DOWNLOADING BLOCKLIST.DE')
            blocklistde_url = 'https://lists.blocklist.de/lists/all.txt'
            blocklistde_output_file = './data/blocklistde.csv'
            downloader = BlocklistDeDownloader(blocklistde_url, blocklistde_output_file)
            downloader.download()

        #CISCO UMBRELLA
        if 'CiscoUmbrella' in self.datasets:
            print('DOWNLOADING CISCO UMBRELLA')
            cisco_umbrella_url = 'http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip'
            cisco_umbrella_output_file = './data/cisco_umbrella.csv'
            downloader = CiscoUmbrellaDownloader(cisco_umbrella_url, cisco_umbrella_output_file)
            downloader.download()

        #HAGEZI
        if 'Hagezi' in self.datasets:
            print('DOWNLOADING HAGEZI')
            hagezi_url = 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/pro.txt'
            hagezi_output_file = './data/hagezi.csv'
            downloader = HageziDownloader(hagezi_url, hagezi_output_file)
            downloader.download()
            downloader.clean_file() 
        
        #MAJESTIC MILLION
        if 'MajesticMillion' in self.datasets:
            print('DOWNLOADING MAJESTIC MILLION')
            majestic_million_url = 'https://downloads.majestic.com/majestic_million.csv'
            majestic_million_output_file = './data/majestic_million.csv'
            downloader = MajesticMillionDownloader(majestic_million_url, majestic_million_output_file)
            downloader.download()
            downloader.clean_file() 

        #OPENPHISH
        if 'OpenPhish' in self.datasets:
            print('DOWNLOADING OPEN PHISH')
            openphish_url = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'
            openphish_output_file = './data/openphish.csv'
            downloader = OpenPhishDownloader(openphish_url, openphish_output_file)
            downloader.download()
            downloader.extract_domain()

        #PHISHTANK
        if 'PhishTank' in self.datasets:
            print('DOWNLOADING PHISH TANK')
            phishtank_url = 'http://data.phishtank.com/data/online-valid.csv'
            phishtank_output_file = './data/phishtank.csv'
            downloader = PhishtankDownloader(phishtank_url, phishtank_output_file)
            downloader.download()
            downloader.clean_file() 
            downloader.extract_domain()
        
        #URLABUSE
        if 'UrlAbuse' in self.datasets:
            print('DOWNLOADING URL ABUSE')
            urlabuse_url = 'https://urlhaus.abuse.ch/downloads/csv_online/'
            urlabuse_output_file = './data/urlabuse.csv'
            downloader = UrlabuseDownloader(urlabuse_url, urlabuse_output_file)
            downloader.download()
            downloader.clean_file() 
            downloader.extract_domain()
