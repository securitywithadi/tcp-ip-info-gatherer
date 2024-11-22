import psutil
import requests
from tabulate import tabulate

# API Keys
VIRUS_TOTAL_API_KEY = " *** "
SHODAN_API_KEY = " *** "

# VirusTotal API function
def fetch_virustotal_score(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUS_TOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", "N/A")
    return "N/A"

# Shodan API function
def fetch_shodan_score(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data.get("vulns", [])
    return "N/A"

# List established connections, filter out loopback, and fetch VirusTotal & Shodan scores
def list_established_connections():
    connections = []
    sl_no = 1
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.status == 'ESTABLISHED':
            remote_address = conn.raddr.ip
            # Filter out loopback IPs (127.0.0.0/8 for IPv4 and ::1 for IPv6)
            if remote_address.startswith("127.") or remote_address == "::1":
                continue
            
            process = psutil.Process(conn.pid) if conn.pid else None
            pid = conn.pid
            file_path = process.exe() if process else "N/A"
            local_port = conn.laddr.port
            remote_port = conn.raddr.port
            vt_score = fetch_virustotal_score(remote_address)
            shodan_score = fetch_shodan_score(remote_address)
            
            connections.append([
                sl_no,
                pid,
                file_path,
                local_port,
                remote_port,
                remote_address,
                vt_score,
                shodan_score
            ])
            sl_no += 1
    return connections

# Save to text file in table format
def save_to_text_file(connections, filename="established_connections.txt"):
    headers = ["SL No.", "PID", "File Path", "Local Port", "Remote Port", "Remote Address", "VirusTotal Score", "Shodan Score"]
    with open(filename, 'w') as file:
        file.write(
            tabulate(connections, headers=headers, tablefmt="grid", colalign=("center", "center", "left", "center", "center", "center", "center", "center"))
        )
    print(f"Output saved to {filename}")

def main():
    connections = list_established_connections()
    save_to_text_file(connections)

if __name__ == '__main__':
    main()
