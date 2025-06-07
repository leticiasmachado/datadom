# Dataset Automation Tool for Analysis of Domains - DATADOM

Tool developed for a Computer Science final project that generates datasets for training machine learning models to detect malicious domains.

## 🔍 Overview

Python solution that:
- Collects domains from blocklists (malicious) and allowlists (legitimate)
- Standardizes and enriches data with relevant features
- Generates balanced datasets for ML models
- Offers parallel processing with safe interruption and resume capabilities

## ⚙️ Operation

### Main Workflow

1. **Initial Validation**  
   - Loads and validates `configs.json` using JSON Schema  
   - If invalid: displays error message and terminates  
   - If valid: checks for existence of `input.csv`

2. **Continuity Control**  
   - If `input.csv` **doesn't exist**:  
     - Identifies active data sources in `configs.json`  
     - Collects domains from selected lists  
     - Saves raw data to `input.csv` (with `"OK"` column for tracking)  
   - If `input.csv` **exists**:  
     - Asks user whether to continue previous processing  
     - If **no**: recreates file from scratch  
     - If **yes**: removes only already processed domains (marked as `"OK" = True`)

3. **Parallel Processing**  
   - Divides domains into chunks based on defined thread count  
   - Each thread executes:  
     - Extraction of user-selected features (e.g., domain length, TLD, etc.)  
     - Verification against blocklists/allowlists  
     - Status updates in `input.csv`  

4. **Final Consolidation**  
   - Aggregates all processed results  
   - Generates `output.csv` with:  
     - Domains  
     - Extracted features  
     - Classification (malicious/legitimate)  
   - Maintains half the dataset for each class (automatic balancing)

5. **Failure Recovery**  
   - Safe interruption via `ENTER` key  
   - State saved in `input.csv` allows resuming from exact stopping point  

![Tool Flowchart](link_to_flowchart_on_github)

### Data Sources
| Type           | Included Sources                                                                 |
|----------------|----------------------------------------------------------------------------------|
| **Allowlist**  | Majestic Million, Cisco Umbrella                                                 |
| **Domain Blocklist** | Abuse.ch, Bambenek (domains/IPs), Hagezi, OpenPhish, PhishTank, UrlAbuse        |
| **IP Blocklist** | Blocklist.de, Bambenek (DGA)                                          |

## 🛠 Configuration

Edit `configs.json` to select:
- Desired data sources
- Final domain count (half malicious, half legitimate)
- Number of threads for parallel processing
- Features to include

## 📊 Data Processing

### Key Steps:
1. **Standardization**:
   - Clean domain extraction (removes HTTP/HTTPS, ports)
   - Format unification

2. **Deduplication**:
   - Automatic removal of duplicate entries
   - Preservation of relevant metadata

3. **Parallel Processing**:
   - Chunk division per thread
   - Pause/resume mechanism (ENTER key)

## 📁 File Structure

```
datadom/
├── data/                    # Source data
├── domain_checkers/         # List verifiers
├── downloads/               # Download management
├── features_processor/      # Feature processing
├── json_processor/          # JSON Schema validation
├── utils/                   # Shared utilities
├── dataset_processor.py     # Core processing
├── features.txt             # Available features list
└── main.py                  # Entry point
```

## 🚀 How to Use
1. Clone the repository:
   ```bash
   git clone https://github.com/leticiasmachado/datadom
   ```
2. Configure `configs.json`
3. Run the main module:
   ```bash
   python main.py
   ```
4. To resume interrupted processing, keep `input.csv` and run again

## ✨ Technical Features
- **Robust Validation**: JSON Schema for configurations
- **Modular**: Easy to add new sources
- **Resilient**: Recoverable processing after interruptions
- **Scalable**: Thread-based parallelization

## 📌 Roadmap
- [ ] Add more data sources (Domain Rankings for allowlist, SANS Internet Storm Center for blocklist)
- [ ] Include TTL (time-to-live) metrics
- [ ] Explore alternatives for the Whois library
- [ ] Implement caching for repetitive queries
