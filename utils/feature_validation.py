def validate_allowlist_features(features, allowlist_sources):
    
    if 'MajesticMillion' in allowlist_sources:
        features["DomainInMajesticMillion"] = False
    
    if 'CiscoUmbrella' in allowlist_sources:
        features["DomainInCiscoUmbrella"] = False

def get_selected_features(features, allowlist_sources):
    
    selected_features = {}
    
    for feature in [
        "DomainInOpenPhish", "DomainInHagezi", "DomainInUrlAbuse",
        "DomainInBambenekDomains", "DomainInPhishTank", "DomainInAbuseCh",
        "IpInBlocklistDe", "IpInBambenek", "DomainInMajesticMillion", "DomainInCiscoUmbrella"
    ]:
        selected_features[feature] = features.get(feature, False)
    
    validate_allowlist_features(selected_features, allowlist_sources)
    
    additional_features = [
        'domain', 'whois', 'subdomains', 'ipAddresses',
        'tools', 'network', 'lexical'
    ]
    
    for feature in additional_features:
        if features.get(feature, False):
            selected_features[feature] = True

    return selected_features
