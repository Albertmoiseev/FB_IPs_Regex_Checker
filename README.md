# Simple REGEX checker

Checks if all instagram bots are covered by regexs

## Getting Started

1) Get all FB IPs id CIDR format:
```
whois -h whois.radb.net — '-i origin AS32934' | grep ^route'
```
2) Put the IPS into /txts/CIDR_IPS_LIST.txt

3) Put the REGEX from your Apache conf:
```
/txts/regex_from_apache_conf.txt
### format:
^185\.60\.216\..*$
^185\.60\.217\..*$
^185\.60\.218\..*$
```

4) Run either 
```
get_IPs_method_1.py
```
or
```
get_IPs_method_2.py
```
5) Get the unmatched IPs, open:
```
/txts/IPs_not_in_REGEX.txt
```
6) Update your Apache conf

### Prerequisites

1) Python3
2) Netaddr 

```
pip3 install netaddr 
```
