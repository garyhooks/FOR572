# 1.2

### (A)

```
tshark -n -r  lab-1.2_capture.pcap -Y "http.host contains google"
```


# 2.1

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

### (3)






