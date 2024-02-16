import os
import subprocess
import nvdlib
import requests
import json
import json

path_to_add = os.path.expanduser('~/go/bin')
os.environ['PATH'] += os.pathsep + path_to_add
enumeration_dir = 'Enumeration/'
with open('RiskRegister.md', 'a') as register_file:
    register_file.write("| Asset | Technology | CVE | EPSS Score | Description |\n")
    register_file.write("|-------|------------|-----|------------|-----|\n")

def find_details_before(lines, index):
    for i in range(index, -1, -1):  # Search backwards from the current index
        if '**Details**' in lines[i]:
            details = lines[i].split('**')[2]  # Assuming format is consistent as provided
            return details
    return '' 

def fetch_cve_details(cve_id):
    cve_details = nvdlib.searchCVE(cveId=cve_id, key='{KEY}', delay=10)
    descriptions = cve_details[0].descriptions
    print(descriptions)
    cwe_info = ''
    for description in descriptions:
        if description.lang == 'en':
            cwe_info = description.value
            break
    return cwe_info

def fetch_epss_score(cve_id):
    epssurl = "https://api.first.org/data/v1/epss?cve="
    response = requests.get(epssurl + cve_id)
    if response.status_code == 200:
        return response.json()['data'][0]['epss']
    else:
        return "Error fetching EPSS score"

def find_cve_and_process_technology(asset, Technology):
    print(asset)
    Technology = Technology.replace('-', ' ').replace('_', ' ')
    print(Technology)
    
    r = nvdlib.searchCVE_V2(keywordSearch=Technology, key='{KEY}', delay=10, limit=5)
    oneCVE = next(r)
    
    print(oneCVE.id)
    CVE = (oneCVE.id)
    try:
        
        cwe_info = fetch_cve_details(CVE)
        epssscore = fetch_epss_score(CVE)
        with open('RiskRegister.md', 'a') as register_file:
            register_file.write(f"| {asset} | {Technology} | {CVE} | {epssscore}  | {cwe_info}|\n")
    except StopIteration:
        print(f"No CVE found for {Technology}")


subprocess.run(['subfinder', '-dL', 'domains.txt', '-all', '-active', '-o', 'subdomains.txt'])
subprocess.run(['nuclei', '-l', 'subdomains.txt', '-config', 'techdetect_config.yaml', '-sa', '-nc', '-or', '-j', '-o', 'techfindings.json'])
        

with open(os.path.join('techfindings.json'), 'r') as file:
    for line in file:
        data = json.loads(line)
        asset = data['host']
        if 'matcher-name' in data:
            Technology = data['matcher-name']
            find_cve_and_process_technology(asset, Technology)
        elif 'info' in data and 'description' in data['info']:
            Technology = data['info']['description'].replace('login', '').replace('panel', '').replace('was', '').replace('detected', '').replace('.', '')
            find_cve_and_process_technology(asset, Technology)
            
        else:
            print(f"No technology found for {asset}")
        