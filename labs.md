# Lab 1.2

### (A)

```
tshark -n -r  lab-1.2_capture.pcap -Y "http.host contains google"
```


# Lab 2.1

### (1A)

-C no_desegment_tcp

```
tshark -n -C no_desegment_tcp -r 10_3_59_127.pcap -T fields -e frame.time -e http.request.method -e http.host -e http.request.uri -e http.user_agent > useragent_derived.log
```

### (2a)

```
cat useragent_derived.log | awk -F "\t" '{ print $5 }'
cat useragent_derived.log | awk -F "\t" '{ print $5 }' | sort | uniq -c | sort -nr
```

```
$ cat useragent_derived.log | awk -F'\t' '{ print $5 }' | sort | uniq -c | sort -nr
 112822 
   3419 Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20100101 Firefox/15.0
   1014 Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Media Center PC 6.0; OfficeLiveConnector.1.5; OfficeLivePatch.1.3; Win7AntivirExtreme)
      3 Microsoft-CryptoAPI/6.1
      2 Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) G
      2 Mo
      1 Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20100101 Firef
      1 Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20100101 Fir
      1 Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20100101 
      1 Mozilla/5.0 (Windows NT 6.1; WOW64; rv:
      1 Mozilla/5.0 (Windows NT 6.1; WOW
      1 Mozilla/5.0 (Windows NT 6
      1 Mozilla/5.0 (Window
      1 Mozilla/5.0 (W
      1 Mozi
      1 Immunet Updater
```


### (2b)

```
grep "Firefox/15.0" useragent_derived.log | awk -F"\t" '{ print $2, $3 }' | sort | uniq -c | sort -nr
```

```
grep "Firefox/15.0" useragent_derived.log | awk -F"\t" '{ print $4 }' | sort | uniq -c | sort -nr
```

Interesting results using the following - 50 hits to /blank and /

```
grep "MSIE 8.0" useragent_derived.log | awk -F"\t" '{ print $4 }' | sort | uniq -c | sort -nr | more
```

### (3a)

-q 
-z statistics
-z io,phs[,filter]

```
tshark -n -C no_desegment_tcp -r 10_3_59_127.pcap -q -z io,phs
```


### (3c)

```
tshark -n -C no_desegment_tcp -r 10_3_59_127.pcap -T fields -e frame.time -Y 'http.user_agent contains "Firefox/15.0"' | head -n 1
```

### (3d)

```
tshark -n -C no_desegment_tcp -r 10_3_59_127.pcap -T fields -e frame.time_delta_displayed -e http.request.uri -Y 'http.user_agent contains "MSIE 8.0" and http.request.uri contains "sugexp"'
```

### (3e)

Not consistent with human behaviour
It looks like it could be blackhat SEO malware strain


# Lab 2.2

### (1a) (1b)

/etc/sysconfig/
-- iptables
-- iptables.conf

/etc/rsyslog.d/*

/etc/rsyslog.conf

/var/log:
-- boot.log
-- dmesg
-- 

/opt/bro/*


### (2a)

iptables

```
-i  Input Interface
-p  Layer 4 protocol - allows us to specify TCP traffic
-d  Destination IP - which IP to observe, etc - 184.32.3.55
--dport  Layer 4 port - e.g. 1951
--syn  Match packegs with the Syn flag set only - effective way to control the amount of log data generated since only one packet per fonnection will meet this

-j LOG  take the log action with any matched traffic.  This is non terminal 
```

##### Example

```
-A FORWARD -i enp0s8 -d 184.82.188.7/32 -p tcp -m tcp --dport 1951 --syn -j LOG --log-prefix "FW potential C2 general: "
-A FORWARD -i enp0s9 -d 184.82.188.7/32 -p tcp -m tcp --dport 1951 --syn -j LOG --log-prefix "FW potential C2 key: "
-A FORWARD -i enp0s10 -d 184.82.188.7/32 -p tcp -m tcp --dport 1951 --syn -j LOG --log-prefix "FW potential C2 floor: "
```


### (2b)

```
grep "potential C2" messages | awk '{ print $9,$13}' | sort | uniq | awk '{ print $1 }' | uniq -c


 10 floor:
 128 general:
 21 key:
```

### (2c)


```
grep "potential C2 general" messages | less
```
Chosen IP = 10.3.57.103

```
grep "potential C2" messages | grep "SRC=10.3.57.103"
```

#### Interval is every 20 minutes

```
grep "potential C2 key" messages | less
```
Chosen IP = 10.3.58.3

```
grep "potential C2" messages | grep "SRC=10.3.58.3"
```

#### Interval is every 20 minutes 


```
grep "potential C2 floor" messages | less
```
Chosen IP = 10.3.59.6

```
grep "potential C2" messages | grep "SRC=10.3.59.6"
```

#### Interval is every 10 minutes 



### (3a)

/opt/bro/logs/current/signatures.log - for the current hour whilst Bro is running
/opt/bro/logs/YYYY-MM-DD/signatures.<datetime>.log.gz for the previous time window
 
 ### (3b)
 
zcat signatures* | bro-cut sig_id src_addr | grep ^potential-c2.*10\.3\.5[67]\. | sort | uniq | wc -l
 
 
 
 # Lab 2.3

### (2a)

Timestamp: 2013-06-08 16:32:48.000Z
URL: http://download.taxforms.usa.gov.ccmktiejgpq.co.cc/2014_tax_schedules.pdf
Client_IP: 10.3.59.53
HTTP Referer: -
HTTP User-Agent: feevil 18b

### (2c)

Timestamp: 2013-06-08 16:31:54.000Z
URL: http://download.taxforms.usa.gov.ccmktiejgpq.co.cc/taxdocs.exe
Client_IP: 10.3.59.53
HTTP Referer: http://us-mg5.mail.yahoo.com/neo/launch?.rand=2i1degofn30rg
HTTP User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.110 Safari/537.36

### (2d)

Event one was a visit to the .exe URL from Yahoo.com mailbox 
The useragent is Mozilla 5.0
The second event was less than a minute later 
This uses a different user agent and fetches the .pdf file 



### (3a) 

2 other events - both from floor2-PC 

Account Name: floor1 
Account Domain: FLOOR2-PC
Process Name: C:\Users\floor1\AppData\Local\Temp\WZSE0.TMP\taxdocs.exe



Account Name: floor1
Account Domain: FLOOR2-PC 
Process Name: C:\Users\floor1\Downloads\taxdocs.exe


### (3b)

Account Name: floor1 
Account Domain: FLOOR2-PC 
Process Name: C:\Users\floor1\AppData\Local\Temp\WZSE0.TMP\681094798543.exe


### (4a)

feevil 18c - 17 hits
feevil 18b - 1 hit 

### (5a)

Hardware address - 08:00:27:df:33:6d 


### (5e)

Only URL without associated HTTP activity is:

pfumqhbrowahfgk.co.cc


### (6a)



 # Lab 3.2
 
 ### (1a)
 
 ```
 nfdump -R 2012/ -A proto,dstip,dstport -O tstart -o 'fmt:%ts %te %da %pr/%dp %pkt %byt' 'src host 10.3.58.7 and dst host in [ 199.73.28.114 12.190.135.235 ]'
 ```
 
 ### (1b)
 
 HTTP traffic on ports 80, 443.  
 Port 8000 unsure 

### (1c)

nfdump -R 2012/ -A proto,dstip,dstport -O tstart -o 'fmt:%ts %te %da %pr/%dp %pkt %byt' 'src host 10.3.58.7 and dst host in [ 199.73.28.114 12.190.135.235 ] and port 8000'
 

### (2a)

```
 nfdump -R 2012/ -A srcip,dstip -O tstart 'src net 10.3.58.0/24 and dst net 10.3.58.0/24 and not host in [10.3.58.4 10.3.58.255 ]'
 ```
 
 ### (2b)
 
 dont know 
 
 ### (3a) 
 
 ```
 nfdump -R 2012/ -s port:p/bytes 'host 10.3.58.6 and host 10.3.58.6'
 ```
 
 ### (3b)
 
 


# Lab 4.2

### (3g) 

```
tshark -n -r evidence1.pcap -Y 'ftp.request.command=="USER" || ftp.request.command=="PASS"' -T fields -e frame.number -e tcp.stream -e ftp.request.command -e ftp.request.arg
```




# Lab 5.1

### (1a) 



