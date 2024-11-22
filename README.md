**#TCP-IP Info Gathering Script**
**Introduction**
This Python script is designed to fetch and display essential details about the TCP/IP connections on a Windows system. It collects the following information:
Process ID (PID)
File Path
Local Port
Remote Port
Remote Address
VirusTotal Score
Shodan Vulnerability Score
The script execution time typically ranges between 50 seconds to 180 seconds, depending on your system's bandwidth and available resources.

**Pre-requisites**
Before running the script, ensure the following requirements are met:
1. Python Version
Python >= 3.11.9 must be installed.

![image](https://github.com/user-attachments/assets/87cb9dfb-9782-4647-85dd-4c7409c44ee0)

2. Install Required Libraries
Use pip to install the required dependencies:
pip install psutil requests

3.API Keys
Update the following API keys in the script:
VirusTotal API Key: Replace *** with your API key on line 5
Shodan API Key: Replace *** with your API key on line 6:

4.Custom Output File Name
Modify line 56 of the script to specify a custom output text file name if required.

**Executing the script**
1. Navigate to the project directory and execute the script:
cd <repository-folder>
python3 tcp-ip_info_gathering.py

**Output**
Note: Open the Text File in WordWrap Mode for better readability.

![image](https://github.com/user-attachments/assets/d45c54c5-4a17-4392-abce-74372e375125)

![image](https://github.com/user-attachments/assets/080f93a0-43c9-46c2-aa65-cc4396152f76)

