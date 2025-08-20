# Hi im Jack Doyle 

## Objective


Investigated and documented the Conti ransomware attack chain by analyzing logs, artifacts, and network activity to identify initial access, persistence, lateral movement, and ransomware deployment techniques, while extracting Indicators of Compromise (IOCs) for detection and defense

### Skills Learned


🕵️‍♂️ Incident Response & Threat Hunting – Investigated a real-world ransomware scenario
📊 Log Analysis – Parsed and reviewed system, security, and application logs for attack patterns
🌐 Network Traffic Analysis – Identified C2 communications and lateral movement activity
🔐 Malware & Ransomware Tactics – Studied Conti’s attack chain from initial access to encryption
⚡ Persistence & Privilege Escalation – Tracked techniques used to maintain and expand access
🛡 Indicators of Compromise (IOCs) – Collected, documented, and validated IOCs for detection
🧰 Practical SOC Skills – Applied investigation methods used in real Security Operations Centers


### Tools Used


🔍 Splunk (SIEM) – Queried and correlated logs for attacker activity


- ## Steps

 ### Q1: Can you identify the location of the ransomware?

Answer: C:\Users\Administrator\Documents\cmd.exe

<img width="769" height="643" alt="Screenshot 2025-08-19 195457" src="https://github.com/user-attachments/assets/edfcc30b-6881-4e30-a70c-66ccf8d19289" />

Reason: since we know that this ransomware has created a number of ReadMe.txt files, we can start by searching for event code 11, which is the file creation event code. We also know to look for this code based on question 2. By examining the important fields for this search, we can see that there are only 10 results in the image field. When looking into this image field, we can see that a cmd executable is located in a suspicious directory: C:\Users\Administrators\Documents\cmd.exe. 

### Q2: What is the Sysmon event ID for the related file creation event?

Answer: 11

Reason: Sysmon Event ID 11: This event is logged by Sysmon (System Monitor) when a file is created or overwritten. It's useful for monitoring critical locations like the Startup folder, temporary directories, and download directories, which are common targets for malware

### Q3: Can you find the MD5 hash of the ransomware?

Answer: 290c7dfb01e50cea9e19da81a781af2c

<img width="341" height="113" alt="Screenshot 2025-08-19 195725" src="https://github.com/user-attachments/assets/11a2a5e4-4f81-4b96-81fd-87d16607ef42" />

Reason: got to the ransomware location click on view events & select field type (filter for) 'Hash', I simply searched by the image file from question 1 and included the MD5 string, which yielded results containing the MD5 for the specified image file.

### Q4: What file was saved to multiple folder locations?

Answer: readme.txt

<img width="780" height="614" alt="Screenshot 2025-08-19 200018" src="https://github.com/user-attachments/assets/1bafe5be-0796-4803-b778-6c2ec00debd7" />

Reason: By searching for the file creation event code related to the ransomware in our query, we can examine the TargetFileName field and see readme.txt stored in multiple locations.

### Q5: What was the command the attacker used to add a new user to the compromised system?

Answer: net user /add securityninja hardToHack123$

<img width="727" height="305" alt="Screenshot 2025-08-19 200054" src="https://github.com/user-attachments/assets/07270342-fdaa-47d5-99d4-a9d2fccc87c4" />

Reason: To find this answer we can search for any cases of the net user command in Splunk as it is the command line tool to create new users. After searching for this and looking under the CommandLine field we found the command that the attacker used.

### Q6: The attacker migrated the process for better persistence. What is the migrated process image (executable), and what is the original process image (executable) when the attacker got on the system?

Answer: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,C:\Windows\System32\wbem\unsecapp.exe

<img width="437" height="132" alt="Screenshot 2025-08-19 200210" src="https://github.com/user-attachments/assets/96622c36-ce30-46cc-81c4-1df6e51184b8" />

Reason:  I knew I would most likely be searching by an event code, but I was unsure which event code I needed to search. The hint provided me with Sysmon event code 8, which is CreateRemoteThread. After some research, I found that this is used by malware to inject code and hide in another process. By searching for this event code, I found two logs, the first of which indicated that

### Q7: The attacker also retrieved the system hashes. What is the process image used for getting the system hashes?

Answer: C:\Windows\System32\lsass.exe

Reason: Try Sysmon event code 8 & check Target Image. 

### Q8: What is the web shell the exploit deployed to the system?

Answer: i3gfPctK1c2x.aspx

<img width="718" height="444" alt="Screenshot 2025-08-19 200238" src="https://github.com/user-attachments/assets/ca01fab1-8d4b-4060-931e-7d1fb794d9e3" />

Reason: I searched for anything containing the .aspx extension, as this is a common web shell extension. One field that popped up was the cs_uri_stem field, which shows the path of the request made over HTTP or HTTPS. In this field, we can see a suspicious-looking file, which is our answer.

### Q9: What is the command line that executed this web shell?

Answer: attrib.exe -r \\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx

<img width="775" height="141" alt="Screenshot 2025-08-19 200418" src="https://github.com/user-attachments/assets/57aa9388-17cc-4868-9709-03429fbfd37e" />

Reason: I searched the CommandLine field for anything containing the malicious web shell. During my search, I found one log that had the answer.

### Q10: What three CVEs did this exploit leverage? Provide the answer in ascending order.

Answer: CVE-2018-13374,CVE-2018-13379,CVE-2020-0796

Reason: After researching, I found a website that listed the vulnerabilities that the Conti ransomware uses.





























