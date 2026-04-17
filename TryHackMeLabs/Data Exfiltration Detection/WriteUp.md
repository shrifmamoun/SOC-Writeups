# WARNING : This write-up is created strictly for educational purposes within controlled lab environments.

**Do NOT attempt to access, scan, or interact with any IP addresses, domains, or systems mentioned here outside of their intended lab context. These targets are part of simulated or authorized environments only.**
**Any unauthorized use against real-world systems is illegal and unethical, and I do not take responsibility for misuse of the information provided.**
**Always ensure you have proper authorization before testing or interacting with any network or system.**
**in this writeup i'm solving the Data Exfiliration Detection Lab in tryhack me. it's a Premium room so i'm gonna try to cover it**
**after connecting to the lab we'll see a folder named  "data_exfil" this is where we'll start our lab .**


# Starting with Task 3 : Data Exfil: Overview, techniques, and indicators
## The question : Exfiltrating the data through HTTP comes under which technique?
**Answer : Network-based** <br>
this is becasuse as we see in the lab in Network- Based Attacks , Threat Actors can exfiltrate data with (HTTP/HTTPS uploads to S3/Azure Blob/webmail, FTP/SFTP/SCP, DNS tunnelling, ICMP/covert protocols, custom TCP/UDP.) and it's basically when an attacker abuses a file upload feature on a website or API to send malicious files instead of legitimate ones


# Task 4: Detection: Data Exfil through DNS tunneling
here we're gonna start our lab 
after opining the dns_exfil.pcap file with wireshark
<img width="1090" height="827" alt="image" src="https://github.com/user-attachments/assets/693543bf-f822-419b-ad24-6b0e6de84aee" />
we can see a 2000 displayed packet 
we wanna detect DNS Tunneling so we're gonna filter dns.flags.response == 0 
<img width="1391" height="386" alt="image" src="https://github.com/user-attachments/assets/e73a1a84-380e-4bcb-9b8d-f48775d88334" />
and we're gonna notice that there's some suspicious domain names with a large query length
and i want to get more info about it so i'm gonna put a filter that filters the frame length and it's gonna be frame.len > 70 because usually the unusually long full query names > 60–100 characters
<img width="1899" height="936" alt="image" src="https://github.com/user-attachments/assets/4405a7bc-af75-41a1-b263-526b03521c5e" />

And BINGO i noticed a weird long queries and Many DNS queries are sent to a single external domain 
in splunk we can filter "index="data_exfil" sourcetype="DNS_logs" | where len(query) > 30" 
to identify the data exfiltration attempts through DNS tunneling
<img width="1918" height="932" alt="image" src="https://github.com/user-attachments/assets/64be1493-46b8-4b28-940b-ed59cfe6c74f" />

## Question 1 :What is the suspicious domain receiving the DNS traffic?
**Answer: tunnelcorp.net** <br>
we can see the domain in wireshark and splunka

## Question 2 :How many suspicious traffic/logs related to dns tunneling were observed?
**Answer: 315** <br>
we can see the number of events after applying the filter on splunk

## Question 3:Which local IP sent the maximum number of suspicious requests?
**Answer: 192.168.1.103** <br>
<img width="1224" height="638" alt="image" src="https://github.com/user-attachments/assets/b361416b-b415-499c-bf92-784539164d50" />
After Applying the Filter if we clicked on the Src_ip we'll see which local ip sent the maximum number of suspicious requests


# Task 5: detection: Data Exfil through FTP

So After opining the ftp-lab.pcap file in the lab we we'll see a lot of ftp packets. We only want to filter the anomalies 

<img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/f7409ffe-3add-4d1a-bbda-b51b4e36951b" />
