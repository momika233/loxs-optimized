# loxs-optimized

# Project from https://github.com/coffinxp/loxs

# CSP-Bypass-xss.txt 

Note: It mainly bypasses the CSP payload

# 2024-11-06

Add CSP-Bypass-xss.txt to xss.txt


# 2024-11-07

Removing interfering information
Only the vulnerable information is displayed


# 2024-11-11

Solves the problem that the program does not automatically exit when running to 100%

# 2024-12-12

cat live_domain_url.txt | gf sqli | tee -a sqlisqli.txt
bash sqlmap-batch-detection.sh
### Notes
Batch detection via sqlmap,If a bug is found, suspend the program and execute it -dbs gets the information
