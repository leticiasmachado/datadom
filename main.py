from domain_checkers.domain_checker_allowlists import DomainCheckerAllowlist
from domain_checkers.domain_checker_blocklists_domain import DomainCheckerBlocklistDomain
from domain_checkers.domain_checker_blocklists_ip import DomainCheckerBlocklistIP
from dataset_processor import DomainDatasetProcessor
from downloads.download import DownloadFiles
from json_processor.json_validate import load_schema, load_config, validate_json
from utils.dataset_utils import get_datasets_to_download
from utils.feature_validation import get_selected_features
from utils.read_csv import read_second_column_domains
from utils.read_csv import read_single_column_domains
import time
import random
import pandas as pd
import os

schema = load_schema('./json_processor/schema.json')
config_data = load_config('./json_processor/configs.json')
is_valid, message = validate_json(config_data, schema)
print(message)

if is_valid:
    start = time.time()
    
    features = config_data['datasetConfig'].get('features', {})
    allowlist_sources = config_data['datasetConfig'].get('allowlistSources', [])
    blocklist_sources = config_data['datasetConfig'].get('blocklistSources', [])
    virus_total_APIKEY = config_data['datasetConfig'].get('VirusTotalAPIKEY', '')
    bambenek_username = config_data['datasetConfig'].get('usernameBambenek', '')
    bambenek_password = config_data['datasetConfig'].get('passwordBambenek', '')

    selected_features = get_selected_features(features, allowlist_sources)
    
    # lista de datasets para download
    datasets = get_datasets_to_download(config_data, selected_features)

    download = DownloadFiles(list(set(datasets), bambenek_username, bambenek_password)) 
    download.download()
    end = time.time()
    print(end-start, 'seconds to download')

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


    domain_checker_allowlists = DomainCheckerAllowlist(majestic_million_path, cisco_umbrella_path)
    domain_checker_blocklists_domain = DomainCheckerBlocklistDomain(openphish, hagezi_path, urlabuse, bambenek_domains_path, phishtank, abusech_path)
    domain_checker_blocklists_ip = DomainCheckerBlocklistIP(blocklistde_path, bambenek_ips_path)

    # carregando os domínios das listas de permissão
    allowlist_domains = []
    if config_data['datasetConfig'].get('allowlistSources', []):
        for allowlist_source in config_data['datasetConfig']['allowlistSources']:
            if allowlist_source == 'MajesticMillion':
                allowlist_domains.extend(read_second_column_domains(majestic_million_path))
            else:
                allowlist_domains.extend(read_second_column_domains(cisco_umbrella_path))

    # carregando os domínios das listas de bloqueio
    blocklist_domains = []
    if config_data['datasetConfig'].get('blocklistSources', []):
        for blocklist_source in config_data['datasetConfig']['blocklistSources']:
            if blocklist_source == 'Hagezi':
                blocklist_domains.extend(read_single_column_domains(hagezi_path))
            elif blocklist_source == 'BambenekDomains':
                blocklist_domains.extend(read_single_column_domains(bambenek_domains_path))
            elif blocklist_source == 'PhishTank':
                blocklist_domains.extend(read_single_column_domains(phishtank))
    
    # garantindo 50% de domínios de cada lista
    num_domains = config_data['datasetConfig'].get('size', 100) 
    half_size = num_domains // 2

    selected_allowlist_domains = random.sample(allowlist_domains, half_size)
    selected_blocklist_domains = random.sample(blocklist_domains, half_size)

    combined_domains = selected_allowlist_domains + selected_blocklist_domains

    if os.path.exists('input.csv'):
        user_choice = input(
            "An 'input.csv' file was found. Do you want to continue processing? [Y/N]: "
        ).strip().lower()

        if user_choice == 'n':
            print('Restarting the processing.')
            os.remove('input.csv')
        elif user_choice == 's':
            # Carregar e filtrar os domínios não processados
            df_input = pd.read_csv('input.csv')
            df_input = df_input[df_input['OK'].isnull()]  # Seleciona apenas domínios não processados
            df_input.to_csv('input.csv', index=False)
        else:
            print("Invalid choice. Terminating execution.")
            exit()
    else:
        print("No 'input.csv' file was found, processing will start.")

    if not os.path.exists('input.csv'):
        combined_domains_df = pd.DataFrame(combined_domains, columns=['Domain'])
        combined_domains_df['OK'] = None 
        combined_domains_df.to_csv('input.csv', index=False, header=True)

    input_csv_path = 'input.csv'
    output_csv_path = 'output.csv'
    num_domains = config_data['datasetConfig'].get('size', {})
    num_threads = config_data['datasetConfig'].get('numThreads', 10)

    processor = DomainDatasetProcessor(
        domain_checker_allowlists,
        domain_checker_blocklists_domain,
        domain_checker_blocklists_ip,
        selected_features, 
        virus_total_APIKEY
    )

    processor.create_combined_csv(input_csv_path, output_csv_path, num_threads, num_domains)
