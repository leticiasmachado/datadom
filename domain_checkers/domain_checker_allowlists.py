import pandas as pd

class DomainCheckerAllowlist:
    def __init__(self, majestic_csv_path, cisco_umbrella_csv_path):
        if majestic_csv_path != None:
            self.majestic_df = pd.read_csv(majestic_csv_path)
        if cisco_umbrella_csv_path != None: 
            self.cisco_umbrella_df = pd.read_csv(cisco_umbrella_csv_path, header=None, names=['Rank', 'Domain'], delimiter=',')
    
    # Verifica se o domínio está na Majestic Million
    def check_domain_in_majestic(self, domain):
        if domain in self.majestic_df['Domain'].values:
            global_rank = self.majestic_df.loc[self.majestic_df['Domain'] == domain, 'GlobalRank'].values[0]
            return global_rank
        else:
            return 0
    
    # Verifica se o domínio está na Cisco Umbrella
    def check_domain_in_cisco_umbrella(self, domain):
        if domain in self.cisco_umbrella_df['Domain'].values:
            rank = self.cisco_umbrella_df.loc[self.cisco_umbrella_df['Domain'] == domain, 'Rank'].values[0]
            return rank
        else:
            return 0
