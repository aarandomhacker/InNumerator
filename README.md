# InNumerator

Scrapes employees for a company from LinkedIn.
The script can mangle the output to what fits your needs. Currently there are 3 options, ***First.Last*, *F.Last*, and *First.L***.
The script cleans up the output, removing special characters and other things that people put in their LinkedIn.
Output can be in 2 formats, just the username or with a domain name, creating a list of email addresses.

# Options
| Option | Required | Description |
| ------ | ------ | ------ |
| -c | True | Company to search for in Linkedin |
| -id | False | Company ID to search for | 
| -s | False | Time to sleep between requests | 
| -mr | False | Max number of requests per for querying LinkedIn (Default 500) | 
| -ua | False | User-agent for requests | 
| -user | True | Linkedin.com authenticated username to use | 
| -pass | True | Linkedin.com authenticated password to use | 
| -t | False | HTTP request timeout | 
| -disable-ssl | False | Disable SSL validation checks | 
| -o | True | Write output to file | 
| -d | False | Domain to add to end of users, creating emails | 
| -m | False | Mode to mangle: 1 = First.Last (default) 2 = F.Last 3 = First.L | 

# Notes

An issue has been found when running from MacOS where python certificates are not trusted. To fix this, navigate to the python install folder and run the "Install Certificates.command" file. (Defaults to Applications -> Python3.# -> Install Certificates.command)

The old version had OWA spraying functionality, but it was unreliable at best. I will be working on reimplementing OWA password spraying once I find a reliable method. 
