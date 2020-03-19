# UserVooDoo
Company Linkedin user enumeration and cleanup. Includes functionality for OWA password spraying.

An issue has been found when running from MacOS where python certificates are not trusted. To fix this, navigate to the python install folder and run the "Install Certificates.command" file.
(Defaults to Applications -> Python3.# -> Install Certificates.command)

Scrapes employees for a company from linkedin, cleans up and mangles the names into email addresses with the specified domain. Includes OWA password spraying functionality for the created user list.

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
| -o | False | Write output to file | 
| -d | False | Domain to add to end of users, creating emails | 
| -m | False | Mode to mangle: 1 = First.Last (default) 2 = F.Last 3 = First.L | 
| -owa | False | Use output file for password spraying against OWA | 
| -owapass | False | Password to use when OWA password spraying | 
| -owathreads | False | Number of threads to use during OWA password spraying. | 
