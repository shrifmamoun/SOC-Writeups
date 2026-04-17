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
<img width="800" height="827" alt="image" src="https://github.com/user-attachments/assets/693543bf-f822-419b-ad24-6b0e6de84aee" />
we can see a 2000 displayed packet 
we wanna detect DNS Tunneling so we're gonna filter dns.flags.response == 0 
<img width="800" height="386" alt="image" src="https://github.com/user-attachments/assets/e73a1a84-380e-4bcb-9b8d-f48775d88334" />
and we're gonna notice that there's some suspicious domain names with a large query length
and i want to get more info about it so i'm gonna put a filter that filters the frame length and it's gonna be frame.len > 70 because usually the unusually long full query names > 60–100 characters
<img width="800" height="936" alt="image" src="https://github.com/user-attachments/assets/4405a7bc-af75-41a1-b263-526b03521c5e" />

And BINGO i noticed a weird long queries and Many DNS queries are sent to a single external domain 
in splunk we can filter "index="data_exfil" sourcetype="DNS_logs" | where len(query) > 30" 
to identify the data exfiltration attempts through DNS tunneling
<img width="800" height="932" alt="image" src="https://github.com/user-attachments/assets/64be1493-46b8-4b28-940b-ed59cfe6c74f" />

## Question 1 :What is the suspicious domain receiving the DNS traffic?
**Answer: tunnelcorp.net** <br>
we can see the domain in wireshark and splunka

## Question 2 :How many suspicious traffic/logs related to dns tunneling were observed?
**Answer: 315** <br>
we can see the number of events after applying the filter on splunk

## Question 3:Which local IP sent the maximum number of suspicious requests?
**Answer: 192.168.1.103** <br>
<img width="800" height="638" alt="image" src="https://github.com/user-attachments/assets/b361416b-b415-499c-bf92-784539164d50" />
After Applying the Filter if we clicked on the Src_ip we'll see which local ip sent the maximum number of suspicious requests


# Task 5: detection: Data Exfil through FTP

So After opining the ftp-lab.pcap file in the lab we we'll see a lot of ftp packets. We only want to filter the anomalies and for the Indicators of attack we should look for commands like "USER" , "PASS" , "STOR" and "RETR"
so i tried to filter  ftp.request.command == "USER" || ftp.request.command == "PASS"
and i noticed a weird behaviour with a weak user and password 
<img width="800" height="866" alt="image" src="https://github.com/user-attachments/assets/f2124ee4-c479-44e5-a93c-cc22d42152ab" />

and it's for the best to make sure by using ftp contains "STOR" as a filter as STOR for uploading and we might see if the attacked uploaded anything suspisious .
In real-world incidents, CSV files are commonly used to export:
User databases <br>
Financial records <br>
Employee data <br>
system logs <br>
so we're gonna filter for csv files <br>

<img width="800" height="761" alt="image" src="https://github.com/user-attachments/assets/622dca55-5750-4a73-90ce-cda7845c3414" />

we notice a huge traffic length in the second packed as we see in the picture so that's definitely not normal 

<img width="800" height="880" alt="image" src="https://github.com/user-attachments/assets/30880cdb-7b48-4c7f-a6d7-6db6a6d45ce9" />
so if we looked at the tcp stream we'll find our answer 

## Question 1 : How many connections were observed from the guest account?
Answer: 5
<img width="800" height="586" alt="image" src="https://github.com/user-attachments/assets/bb72cdb0-ee0c-4c44-9e38-c45a388668e3" />
by applying the ftp.contains "guest"


## Question 2: Apply the filter; what is the name of the customer-related file exfiltrated from the root account?
Answer: customer_data.xlsx

<img width="800" height="295" alt="image" src="https://github.com/user-attachments/assets/98ff7a54-18f9-4d17-af4e-805afedc6ea0" />
if we followed the tcp stream for the root user we'll see the name of the file


## Question 3 : Which internal IP was found to be sending the largest payload to an external IP?
Answer: 192.168.1.105
for this question we applied "ftp && frame.len > 90" filter to see the largest payload
<img width="800" height="319" alt="image" src="https://github.com/user-attachments/assets/6b79c0c6-272e-4cf7-992e-20bb990e3931" />


## Question 4: What is the flag hidden inside the ftp stream transferring the CSV file to the suspicious IP?
Answer: THM{ftp_exfil_hidden_flag}

it's found in the csv file after following the tcp stream ( you can find the answer upove while analysing the ftp file in the task)


# Task 6: Detection: Data Exfil via HTTP
I'm gonna try to summarize this section . in this specific Lab the attack happened using the Post method 
so we're gonna open splunk and after applying "index="data_exfil" sourcetype="http_logs" method=POST bytes_sent > 600 | table _time src_ip uri domain dst_ip bytes_sent | sort - bytes_sent"
we're gonna notice the anomaly 
the filter for only showing the Packets with POST method and have a large bytes size
<img width="800" height="413" alt="image" src="https://github.com/user-attachments/assets/0c1018eb-6f76-4aec-bb40-0a80cb65b91a" />
so it's confirmed that there's a suspicious activity that is going in the network
so ofc i had to open wireshark to deeply investigate the anomaly
and as i sayed the attack in this Lab happened using the POST method 
so i filtered using " http.request.method == "POST" and frame.len > 750"
<img width="800" height="725" alt="image" src="https://github.com/user-attachments/assets/c9ddf5db-fd13-45e1-b30b-ca83aa01a551" />
<img width="1291" height="858" alt="image" src="https://github.com/user-attachments/assets/d5331b2e-dd6b-4285-ba6f-aafb2caaf1d9" />

## Quesiton 1 : Which internal compromised host was used to exfiltrate this sensitive data?
Answer :192.168.1.103
we can obv see that during our investigation in wireshark

## Question 2 : What's the flag hidden inside the exfiltrated data?
Answer: THM{http_raw_3xf1ltr4t10n_succ3ss}
we also can see that after looking at the tcp stream 




# Task 7 : Detection: Data exfiltration via ICMP

during this section we're gonna use wireshark so i filtered " icmp.type == 8 and frame.len > 100" and the code is  8 because we wanna see the data being sent in our network and i wanted to make sure to show only the large frame length  because  Normal pings are ~74 bytes total. Anything over 100 is suspicious.
<img width="800" height="245" alt="image" src="https://github.com/user-attachments/assets/1a9c2ba8-7832-4c14-86ac-cf43f82e4689" />
and that's it the icmp anomaly can be seen through lare payloads size


## quesion 1: What is the flag found in the exfiltrated data through ICMP?
Answer:THM{1cmp_3ch0_3xf1ltr4t10n_succ3ss}

by exploring every packet you'll notice the flag
<img width="800" height="675" alt="image" src="https://github.com/user-attachments/assets/bf43e79a-2ab9-4d05-a312-6d4ad0d83c93" />


# THE END
