# loxs-optimized

# Project from https://github.com/coffinxp/loxs

# CSP-Bypass-xss.txt 

Note: It mainly bypasses the CSP payload

# 2024-11-06

Add CSP-Bypass-xss.txt to xss.txt

# 2024-11-07


loxs.py Added message notification
```
subprocess.run(["echo", payload_url, "|", "notify"], shell=True)
```
