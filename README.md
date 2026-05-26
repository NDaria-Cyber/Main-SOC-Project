# Fileless Malware Detection using Sysmon &amp; PowerShell

# Objective
- The objective of this project was to simulate and detect fileless malware using Sysmon telemetry & custom PowerShell based detections. This project spotlights fileless malware that real-time traditional security tools often fail to detect by using custom detection scripts that search constantly for such malware by using custom detection logic.

# Technologies used
- Custom detection scripts
- Windows Event Viewer
- Windows 10 Virtual Machine
- Sysmon
- Sysinternals
- PowerShell
- Word VBA
  
**Note** : Sysmon Telemetry is important given what it offers in addition to the normal windows logs ( Process creation, Command Lines, Parent-child relationships, Network telemetry, etc)

  # Attack simulation & Detection Logic
  - **Simulated behaviours** : Hidden PowerShell execution, macro word abuse (word spawning Command Prompt and PowerShell), PowerShell suspicious command line (No P, W hidden, Exec Bypass, irm, iex, etc), legitimate services being abused (mshta, certutil, etc).
  - **Detection Logic** : The scripts work based on real-world malware patterns used in customized detection rules:

    **Word VBA** : Running a macro command by entering VBA (alt+F11) and creating a PowerShell suspicious line ( No P, W hidden, etc), both the customized real-time script monitor for Word Macro Attacks and Event Viewer were able to view the parent-child process relationship (WINWORD.exe --> PowerShell). The customized real-time script monitor included  keywords (powershell.exe, cmd.exe), Event IDs and Logic Update in order to find the malicious attack.

    **PowerShell Script** : By using 'Bad Keywords' (No P, Exec, IEX, from Base64 String), Event IDs ( 1 - process creation), the script matched the bad keywords in the command line and detected the suspicious PowerShell command.

    **LOLBin Script** : By using 'Bad Tools' section (certutil.exe, mshta.exe, etc), 'Bad Actions' (urlcache, scriptlet, vbscript, etc) and a special check for mstha (often usesc .sct files), the LOLBin monitor was able to match the attacks.

    **Event Viewer** : In order to find the PowerShell command lines and suspicious parent-child process relationship,  filter the Event IDs ( Event ID 1 : Process Creation and Event ID 3 : Network) to see both network connections and what was created. Furthermore, Sysmon-Sysinternals was added to offer better telemetry to the logs.

# Detection Rules & Indicators

| Technique                  | Detection                    |
| -------------------------- | ---------------------------- |
| Hidden PowerShell          | `-W hidden`                  |
| PowerShell bypass          | `-Exec Bypass`                       |
| Download execution         | `DownloadString`             |
| Script execution           | `IEX`                        |
| Script download | `IRM`
| Suspicious Office activity | `WINWORD.exe → powershell.exe` |
| Suspicious legitimate services | `mshta.exe → vbscript` |


# Demo / Video
https://github.com/user-attachments/assets/f7220d15-600d-4c27-b1fc-ed5290968f63

# What I learned
- How to correlate multiple Event IDs to identify a single attack chain
- The importance of a real-time detection monitor
- The power of native Windows tools for detection without third-party agents
- How to manage multiple alerts in the same time
- How filtering Event IDs makes time more efficient

# MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name | Detection Method |
| --- | --- | --- |----|
| Execution | T1059.001 | PowerShell | Detecting powershell.exe with flags: -NoP, -W Hidden, -Exec Bypass, IEX, DownloadString, IRM. |
| Execution | T1059.005 | Visual Basic for Applications (VBA) | Detecting macro execution via WINWORD.exe spawning cmd.exe or powershell.exe. |
| Execution | T1204.002 | User Execution: Malicious File | Malicious Word file enables user interaction. |
| Defense Evasion | T1218 | System Binary Proxy Execution (LOLBins) | Detecting abuse of mshta.exe (e.g. mshta.exe executing vbscript) | 
| Command and Control | T1105 | Ingress Tool Transfer | Detecting IRM downloading payloads. | 


# Future Improvements 
- Sigma rule integration
- Real-time notifications
- SIEM integration
- Wazuh/Splunk integration

# Conclusion

- By creating customized detection scripts and launching fileless malware attacks, the project shows how easy malware can run without any evidence in the background and how traditonal security tools (Windows Security) often fail to detect such attacks. The project emphasizes how fileless malware is often missed and with the help of customized PowerShell scripts can be detected real-time.






