# Nmap-XML-to-CSV-converter
A python3.6+ script to convert Nmap XML outputs to CSV. Useful for writing OSCP or any kind of pentesting report.

I was getting annoyed having to manually create a table of detected open ports for the OSCP report. So I threw together this script. It is largely based on my [CTF-Note-Template-Generator](https://github.com/tera-si/CTF-Note-Template-Generator).

# Usage

If you ever need to create a table of open ports in your OSCP or any kind of pentest report, just use this script to convert your scans to csv, open the csv with excel or libre calc, ctrl+c, and then ctrl+v on your report. That's it. No more manual labour.

```
$ python3 convert.py -h
usage: convert.py [-h] [tcp_xml] [udp_xml]

Generate a CSV output from Nmap XML scan outputs.

positional arguments:
  tcp_xml     nmap TCP scan XML output
  udp_xml     nmap UDP scan XML output

options:
  -h, --help  show this help message and exit
```

At the moment it suppoorts at most one TCP and one UDP scan, meaning you can use it with:
- one TCP scan
- one UDP scan
- pnce TCP + one UDP scan

```
$ python3 convert.py tcp-scan.xml udp-scan.xml 
##################################################
# Nmap XML to CSV converter v 1.0                #
# By terasi                                      #
# https://github.com/tera-si                     #
##################################################
[i] Parsing XML file(s)...
[i] Writing output csv file to '127.0.0.1-Microsoft Windows Server 2008 SP1 or Windows Server 2008 R2.csv'...
```

The resulting CSV would then look like this:
```
protocol,number,service,product,version
TCP,21,FTP,Microsoft ftpd,
TCP,80,HTTP,Microsoft IIS httpd,10.0
TCP,135,MSRPC,Microsoft Windows RPC,
TCP,139,NETBIOS-SSN,Microsoft Windows netbios-ssn,
TCP,445,MICROSOFT-DS,,
```
