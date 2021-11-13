# dns-mail-auth
This repo contains additional material for the RAID 2021 paper [The Evolution of DNS-based Email Authentication: Measuring Adoption and Finding Flaws](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2021/08/04/DNS-based-Mail-Authentication-RAID21.pdf)

## BibTex:
```
@inproceedings{tatang2021dns-mail-auth,
    author = {Tatang, Dennis and Zettl, Florian and Holz, Thorsten},
    title = {{The Evolution of DNS-Based Email Authentication: Measuring Adoption and Finding Flaws}},
    year = {2021},
    booktitle = {24th International Symposium on Research in Attacks, Intrusions and Defenses},
    series = {RAID '21}
}
```

# Crawler
For scanning, primarily three different scripts are used, depending on which list is used:
	
	1. Majestics: code/crawling_dns-majestics.py
	
	2. Alexa:     code/crawling_dns.py
	
	3. Tranco:    code/crawling_dns-tranco.py
    
# Results    
The results are stored in the /Results directory. Furthermore, the DNS entries are examined and then written to a MySQL database.  

The generated DKIM selector list is: code/dictionary.lst
