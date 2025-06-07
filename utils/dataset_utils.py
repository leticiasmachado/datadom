def add_datasets_based_on_features(selected_features, datasets):
    
    if selected_features.get("DomainInOpenPhish"):
        datasets.append("OpenPhish")
    if selected_features.get("DomainInHagezi"):
        datasets.append("Hagezi")
    if selected_features.get("DomainInUrlAbuse"):
        datasets.append("UrlAbuse")
    if selected_features.get("DomainInBambenekDomains"):
        datasets.append("BambenekDomains")
    if selected_features.get("DomainInPhishTank"):
        datasets.append("PhishTank")
    if selected_features.get("DomainInAbuseCh"):
        datasets.append("Abuse.ch")
    if selected_features.get("IpInBlocklistDe"):
        datasets.append("BlocklistDE")
    if selected_features.get("IpInBambenek"):
        datasets.append("BambenekIPs")
    if selected_features.get("DomainInMajesticMillion"):
        datasets.append("MajesticMillion")
    if selected_features.get("DomainInCiscoUmbrella"):
        datasets.append("CiscoUmbrella")

def get_datasets_to_download(config_data, selected_features):
    
    datasets = []

    # allowlist e blocklist com base nas sources
    if config_data['datasetConfig'].get('allowlistSources', []):
        datasets.extend(config_data['datasetConfig']['allowlistSources'])
    
    if config_data['datasetConfig'].get('blocklistSources', []):
        for source in config_data['datasetConfig']['blocklistSources']:
            if source == 'BambenekDomains':
                datasets.append('BambenekDomains')
            elif source == 'Hagezi':
                datasets.append('Hagezi')
            elif source == 'PhishTank':
                datasets.append('PhishTank')

    # datasets com base nas features selecionadas
    add_datasets_based_on_features(selected_features, datasets)
    return list(set(datasets))  # Remove duplicatas
