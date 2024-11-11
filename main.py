from domain_checkers.domain_checker_allowlists import DomainCheckerAllowlist
from domain_checkers.domain_checker_blocklists_domain import DomainCheckerBlocklistDomain
from domain_checkers.domain_checker_blocklists_ip import DomainCheckerBlocklistIP
from dataset_processor import DomainDatasetProcessor
from downloads.download import DownloadFiles
from json_processor.json_validate import load_schema, load_config, validate_json
from utils.dataset_utils import get_datasets_to_download
from utils.feature_validation import get_selected_features
import time
import random
import pandas as pd
import os

def read_single_column_domains(file_path):
    df = pd.read_csv(file_path, header=None)
    return df[0].tolist() 

def read_second_column_domains(file_path):
    df = pd.read_csv(file_path, header=None, usecols=[1])  
    return df[1].tolist() 

schema = load_schema('./json_processor/schema.json')
config_data = load_config('./json_processor/configs.json')
is_valid, message = validate_json(config_data, schema)
print(message)

if is_valid:
    
    features = config_data['datasetConfig'].get('features', {})
    allowlist_sources = config_data['datasetConfig'].get('allowlistSources', [])
    blocklist_sources = config_data['datasetConfig'].get('blocklistSources', [])

    selected_features = get_selected_features(features, allowlist_sources)
    
    datasets = get_datasets_to_download(config_data, selected_features)
    download = DownloadFiles(list(set(datasets)))
    download.download() 
    
    cisco_umbrella_path = './data/cisco_umbrella.csv' if os.path.exists('./data/cisco_umbrella.csv') else None
    majestic_million_path = './data/majestic_million.csv' if os.path.exists('./data/majestic_million.csv') else None
    abusech_path = './data/abusech.csv' if os.path.exists('./data/abusech.csv') else None
    bambenek_domains_path = './data/bambenek_domains.csv' if os.path.exists('./data/bambenek_domains.csv') else None
    bambenek_ips_path = './data/bambenek_ips.csv' if os.path.exists('./data/bambenek_ips.csv') else None
    blocklistde_path = './data/blocklistde.csv' if os.path.exists('./data/blocklistde.csv') else None
    hagezi_path = './data/hagezi.csv' if os.path.exists('./data/hagezi.csv') else None
    openphish = './data/openphish.csv' if os.path.exists('./data/openphish.csv') else None
    phishtank = './data/phishtank.csv' if os.path.exists('./data/phishtank.csv') else None
    urlabuse = './data/urlabuse.csv' if os.path.exists('./data/urlabuse.csv') else None

    start  = time.time()

    domain_checker_allowlists = DomainCheckerAllowlist(majestic_million_path, cisco_umbrella_path)
    domain_checker_blocklists_domain = DomainCheckerBlocklistDomain(openphish, hagezi_path, urlabuse, bambenek_domains_path, phishtank, abusech_path)
    domain_checker_blocklists_ip = DomainCheckerBlocklistIP(blocklistde_path, bambenek_ips_path)

    allowlist_domains = []
    if config_data['datasetConfig'].get('allowlistSources', []):
        for allowlist_source in config_data['datasetConfig']['allowlistSources']:
            if allowlist_source == 'MajesticMillion':
                allowlist_domains.extend(read_second_column_domains(majestic_million_path))
            else:
                allowlist_domains.extend(read_second_column_domains(cisco_umbrella_path))

    blocklist_domains = []
    if config_data['datasetConfig'].get('blocklistSources', []):
        for blocklist_source in config_data['datasetConfig']['blocklistSources']:
            if blocklist_source == 'Hagezi':
                blocklist_domains.extend(read_single_column_domains(hagezi_path))
            elif blocklist_source == 'BambenekDomains':
                blocklist_domains.extend(read_single_column_domains(bambenek_domains_path))
            elif blocklist_source == 'PhishTank':
                blocklist_domains.extend(read_single_column_domains(phishtank))
    
    num_domains = config_data['datasetConfig'].get('size', 100) 
    half_size = num_domains // 2

    selected_allowlist_domains = random.sample(allowlist_domains, half_size)
    selected_blocklist_domains = random.sample(blocklist_domains, half_size)

    combined_domains = selected_allowlist_domains + selected_blocklist_domains

    combined_domains_df = pd.DataFrame(combined_domains, columns=['Domain'])
    combined_domains_df.to_csv('input.csv', index=False, header=True)

    input_csv_path = 'input.csv'
    output_csv_path = 'output.csv'
    num_domains = config_data['datasetConfig'].get('size', {})
   
    processor = DomainDatasetProcessor(domain_checker_allowlists, domain_checker_blocklists_domain, domain_checker_blocklists_ip, selected_features)
    processor.create_combined_csv(input_csv_path, output_csv_path)

    end = time.time()
    print(end-start, 'seconds to process.')
