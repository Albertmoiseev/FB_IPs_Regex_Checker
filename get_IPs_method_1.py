from netaddr import IPNetwork
import re

#### Functions
#### Regex string adaption for union. Usage lots of regexes in a single big regex.
def regex_string_adaption(regex_str):
    regex_str = regex_str[1:-1]
    return regex_str

### Open file with the ist of CIDR ips
with open('./txts/CIDR_IPS_LIST.txt') as f:
    lines = f.readlines()

### Creating the list of objects to work with IPNetwork function
ipnetwork_objects_list = [line.strip() for line in lines]

### Erasing the previous entries in the output file
open('./txts/Unpacked_ips.txt', 'w').close()

### Writing the unpacked bulk IPs
for ipnetwork_object in ipnetwork_objects_list:
    for ip in IPNetwork(ipnetwork_object):
        with open('./txts/Unpacked_ips.txt', 'a') as f:
            f.write(str(ip) + '\n')

### Open file with REGEX rules for Apache Mode Rewrite Cloacking
with open('./txts/regex_from_apache_conf.txt') as f:
    regex_list = f.readlines()
## The list REGEx rules
regex_list = [regex_single.strip() for regex_single in regex_list]

### Union in ONE BIG REGEX
unioned_regex_list = []
for regex_single in regex_list:
    regex_single = regex_string_adaption(regex_single)
    unioned_regex_list.append(regex_single)

unioned_regex_str = '|'.join(unioned_regex_list)
unioned_regex_str = '(' + (unioned_regex_str) + ')'
# print(unioned_regex_str)

### Open file with facebook ips
with open('./txts/Unpacked_ips.txt') as f:
    facebook_ips_list = f.readlines()

### The list of Facebook Bots IPs
facebook_ips_list = [line.strip() for line in facebook_ips_list]

##### Checking FB ips in Unioned Regex list for umnatched
unmatched_list = []
for ip_fb in facebook_ips_list:
    match = re.search(r'{}'.format(unioned_regex_str), ip_fb)
    try:
        if match.group(0) == '' or None:
            print('*' * 20 + 'Unmatched' + '*' * 20)
            print('No match for IP: ' + str(ip_fb))
            unmatched_list.append(ip_fb)
        else:
            print('*' * 20 + 'Matched' + '*' * 20)
            print(str(ip_fb) + ' matched by regex')
            print(match.group(0))
    except AttributeError:
            print('*' * 20 + 'Unmatched' + '*' * 20)
            print('No match for IP: ' + str(ip_fb))
            unmatched_list.append(ip_fb)

##### Write the unmatched IPs into the file
open('./txts/IPs_not_in_REGEX.txt', 'w').close()
with open('./txts/IPs_not_in_REGEX.txt', 'a') as f:
    for ip in unmatched_list:
        f.write(str(ip) + '\n')

print('The quantity of non-mathced IPs: ' + str(len(unmatched_list)))