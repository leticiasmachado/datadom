# DATADOM
### Dataset Automation Tool for Analysis of Domains

This project was developed as part of the final undergraduate thesis for a Bachelor’s degree in Computer Science, with the goal of creating a specialized tool for building a dataset for the detection of malicious domains. The tool is designed to automate the creation of datasets focused on the detection of malicious domains, based on existing sources. It collects domains from allowlists and blocklists, and complements this data with additional information as defined by the user's needs. The features that the tool can extract from these domains are organized into different types, available in the 'features' table. The final dataset is rich in information and can be used for training machine learning models dedicated to identifying malicious domains.

The main databases used include:
- **Whitelists**: Majestic Million and Cisco Umbrella.
- **Domain blacklists**: Abuse.ch, Bambenek, Hagezi, OpenPhish, PhishTank, and UrlAbuse.
- **IP blacklists**: Blocklist.de and Bambenek.
- **Tools**: VirusTotal to check domains and pydnsbl to check IP addresses.

Each database is processed individually, with cleaning and filtering of relevant information to avoid duplications. The tool allows the user to specify which attributes and sources will be used in the final dataset, configured through a `configs.json` file validated by JSON Schema.

The project structure includes:
- **Data Acquisition and Cleaning Classes**: Organized by database, which eliminate unnecessary information and format data for domain extraction.
- **`dataset_utils.py` Class**: Responsible for determining and downloading the necessary data sources based on user configurations.
- **`feature_validation.py` Class**: Handles the verification and validation of the attributes defined in `configs.json`, ensuring data consistency.
- **`dataset_processor.py` File**: Performs the aggregation of the final data according to the selected attributes.
- **`main.py` File**: Orchestrates the entire process, from validating `configs.json` to creating the dataset.

## Features
**Type:** Category or classification of the resource (e.g., domain, subdomain, DNS record).

**Resource:** Specific name of the resource or information (e.g., TLD, MX, TXT).

**Meaning:** Description of what the resource represents or how it is used.

| Type                                | Resource                    | Meaning                                                                                          |
|-------------------------------------|-----------------------------|--------------------------------------------------------------------------------------------------|
| Domain                              | Domain                      | Domain name                                                                               |
| Domain                              | TLD                         | Top Level Domain                                                                          |
| Domain                              | DNSRecordType               | Types of DNS records found for the domain                                                 |
| Domain                              | MXDnsResponse               | MX (Mail Exchange) records for the domain                                                 |
| Domain                              | TXTDnsResponse              | TXT records to verify the presence of SPF, DKIM, and DMARC                                |
| Domain                              | HasSPFInfo                  | Checks if the SPF (Sender Policy Framework) record is present in the TXT records          |
| Domain                              | HasDkimInfo                 | Checks if there is information about DKIM (DomainKeys Identified Mail) in the TXT records |
| Domain                              | HasDmarcInfo                | Checks if the DMARC (Domain-based Message Authentication, Reporting, and Conformance) record is present in the TXT records |
| Domain                              | CountryCode                 | Country code related to the domain, for example .br, .co, .uk.                            |
| Whois                               | RegisteredCountry           | Country where the domain was registered                                                   |
| Whois                               | RegisteredOrg               | Company that registered the domain                                                        |
| Whois                               | LastUpdateDate              | Date of the last update to the domain registration                                        |
| Whois                               | CreationDate                | Date of domain creation                                                                   |
| Whois                               | ExpirationDate              | Domain expiration date                                                                    |
| Whois                               | NameServers                 | List of name servers associated with the domain                                           |
| Subdomains                          | SubdomainCount              | Number of subdomains                                                                      |
| Subdomains                          | EntropyOfSubDomains         | Entropy of subdomains                                                                     |
| IP Addresses                        | DNSServersIps               | IP addresses of associated DNS servers                                                    |
| IP Addresses                        | HostIPs                     | IP addresses of the domain                                                                |
| IP Addresses                        | DNSServersCountries         | Countries of the IP addresses of the DNS servers                                          |
| IP Addresses                        | HostIPsCountries            | Countries of the IP addresses of the domain                                               |
| Allowlists                          | DomainInMajesticMillion     | Position of the domain in the whitelist                                                   |
| Allowlists                          | DomainInCiscoUmbrella       | Position of the domain in the whitelist                                                   |
| Domain Blocklists                   | DomainInOpenPhish           | Indicates if the domain is present in the blacklist                                       |
| Domain Blocklists                   | DomainInHagezi              | Indicates if the domain is present in the blacklist                                       |
| Domain Blocklists                   | DomainInUrlAbuse            | Indicates if the domain is present in the blacklist                                       |
| Domain Blocklists                   | DomainInBambenek            | Indicates if the domain is present in the blacklist                                       |
| Domain Blocklists                   | DomainInPhishTank           | Indicates if the domain is present in the blacklist                                       |
| Domain Blocklists                   | DomainInAbuseCh             | Indicates if the domain is present in the blacklist                                       |
| IP Blocklists                       | IpInBlocklistDe             | Indicates if the host's IP address is present in the blacklist                            |
| IP Blocklists                       | IpInBambenek                | Indicates if the host's IP address is present in the blacklist                            |
| Tools                               | IpReputationDnsblInfo       | Indicates the reputation of the host's IPs, according to the DNSBLInfo tool               |
| Tools                               | DomainReputationVirusTotal | Indicates the reputation of the domain, according to the VirusTotal tool                   |
| Network Protocols and Services      | CommonPorts                | Commonly open ports on the domain's server                                                 |
| Network Protocols and Services      | HttpResponseCode           | HTTP response code returned by the server when attempting to access the domain             |
| Network Protocols and Services      | ASN                        | Indicates the organization that controls the block of IPs                                  |
| Lexical                             | StrangeCharacters          | Indicates the presence of unusual characters in the domain                                 |
| Lexical                             | ConsonantRatio             | Ratio of consonants in the domain name                                                     |
| Lexical                             | VowelRatio                 | Ratio of vowels in the domain name                                                         |
| Lexical                             | NumericRatio               | Ratio of numbers in the domain name                                                        |
| Lexical                             | SpecialCharRatio           | Ratio of special characters in the domain name                                             |
| Lexical                             | ConsonantSequence          | Number of continuous sequences of consonants                                               |
| Lexical                             | VowelSequence              | Number of continuous sequences of vowels                                                   |
| Lexical                             | NumericSequence            | Number of continuous sequences of numbers                                                  |
| Lexical                             | SpecialCharSequence        | Number of continuous sequences of special characters                                       |
| Lexical                             | Entropy                    | Randomness of the characters in the domain name                                            |
| Lexical                             | DomainLength               | Total number of characters in the domain name                                              |
| Classification                      | Class                      | Classification of the domain as malicious or non-malicious                                 |
