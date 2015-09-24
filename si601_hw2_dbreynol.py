import re
import csv
from urlparse import urlparse

# function to make sure no field of the query string exceeds 80 characters
def urlcheck(sample):
    good = 1
    url = re.search("(?P<url>https?://[^\s]+)", sample).group("url")
    query = urlparse(url)[4]
    if len(query) > 80:
        elements = re.findall(r'=[\w\.-/:%]+',query)
        for i in range(len(elements)):
            if len(elements[i]) > 80:
                good = 0
    if good == 0:
        return False
    else:
        return True

# function to check if the log is valid - returns true if so; false if not
# checks status code and checks that the url being accessed begins with http:// or https://
# also calls the function above, urlcheck
def is_valid(sample):
    good = 0
    request_code = re.search(r'[GET|POST|HEAD]',sample)
    access_url = re.search(r'https?\:\//', sample)
    status_code = re.search(r'"\s+[23]\d\d\s', sample)
    if (request_code and access_url and status_code and urlcheck(sample) and (access_url.start()<status_code.start())):
        good= 1
    connected = re.search(r'CONNECT',sample)
    if (connected and status_code):
        good = 1
    if (good == 1):
        return True
    else:
        return False
        
        
# call isvalid on each line of the log data
# send the valid logs to a valid log file and invalid to an invalid log file
access_log = open('access_log.txt', 'rU')

valid = []
invalid = []
for line in access_log:
    if (is_valid(str(line.split('\n')))==True):
        valid.append(line)
    else:
        invalid.append(line)
outfile = open('valid_access_log_dbreynol.txt', 'w')
for line in valid:
    outfile.write(line)
outfile.close()
outfile = open('invalid_access_log_dbreynol.txt', 'w')
for line in invalid:
    outfile.write(line)
outfile.close()

access_log.close()

# create a summary of the IP addresses in the invalid log file and the count of their frequency
def extract_ip(line):
    ip_address = re.search(r'\d+\.\d+\.\d+\.\d+', line)
    return ip_address.group()

ip_addresses = {}

for line in invalid:
    if extract_ip(line) in ip_addresses:
        ip_addresses[extract_ip(line)] += 1
    else:
        ip_addresses[extract_ip(line)] = 1
        
ip = sorted(ip_addresses.items(), key = lambda x: (-x[1]))

out_file = open('suspicious_ip_summary_dbreynol.csv', 'w')
csvwriter = csv.writer(out_file)
csvwriter.writerow(['IP Address', 'Attempts'])
csvwriter.writerows(ip)
out_file.close()
