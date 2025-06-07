import pandas as pd

class DomainCheckerBlocklistIP:
    def __init__(self, blocklist_de_csv, bambenek_csv):
        if blocklist_de_csv!= None:
            self.blocklist_de_df = pd.read_csv(blocklist_de_csv, header=None)
        if bambenek_csv != None:
            self.bambenek_df = pd.read_csv(bambenek_csv, header=None)

    def check_ips_in_blocklist_de(self, ips):
        if isinstance(ips, str):
            ips = [ips]  # converte IP único para lista
        results = {ip: "True" if str(ip) in self.blocklist_de_df[0].astype(str).values else "False" for ip in ips}
        return results

    def check_ips_in_bambenek(self, ips):
        if isinstance(ips, str):
            ips = [ips]
        results = {ip: "True" if str(ip) in self.bambenek_df[0].astype(str).values else "False" for ip in ips}
        return results
