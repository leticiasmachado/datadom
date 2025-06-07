import pandas as pd

class DomainCheckerBlocklistDomain:
    def __init__(self, openphish_csv, hagezi_csv, urlabuse_csv, bambenek_csv, phishtank_csv, abusech_csv):
        if openphish_csv != None: 
            self.openphish_df = pd.read_csv(openphish_csv, header=None)
        if hagezi_csv != None: 
            self.hagezi_df = pd.read_csv(hagezi_csv, header=None)
        if urlabuse_csv != None:
            self.urlabuse_df = pd.read_csv(urlabuse_csv, header=None)
        if bambenek_csv != None:
            self.bambenek_df = pd.read_csv(bambenek_csv, header=None)
        if phishtank_csv != None: 
            self.phishtank_df = pd.read_csv(phishtank_csv, header=None)
        if abusech_csv != None: 
            self.abusech_df = pd.read_csv(abusech_csv, header=None)

    def check_domain_in_openphish(self, domain):
        return "True" if str(domain) in self.openphish_df[0].astype(str).values else "False"

    def check_domain_in_hagezi(self, domain):
        return "True" if str(domain) in self.hagezi_df[0].astype(str).values else "False"

    def check_domain_in_urlabuse(self, domain):
        return "True" if str(domain) in self.urlabuse_df[0].astype(str).values else "False"

    def check_domain_in_bambenek(self, domain):
        return "True" if str(domain) in self.bambenek_df[0].astype(str).values else "False"

    def check_domain_in_phishtank(self, domain):
        return "True" if str(domain) in self.phishtank_df[0].astype(str).values else "False"

    def check_domain_in_abusech(self, domain):
        return "True" if str(domain) in self.abusech_df[0].astype(str).values else "False"

