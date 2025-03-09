# Whackabot
**Sysadmin tool to analyze webserver access logs and quickly find abusers**

Tired of this ? Then Whackabot is your friend !
> `cat /var/log/apache2/site-access.log | cut -d" " -f2 | sort | uniq -c | sort -rn | head`

## Requirements
Python version 3.9, maybe less.\
Tested on: Debian 11+, Ubuntu 22.04+

## Goals:
- one file and no requirements.txt to keep it simple
- ease my boring post-mortems

## Features
Four operation modes:
### Hosts mode (default)
```
$ cat access.log | wab 
Host            Reverse  Hits  H/s  Bytes   UA  G/P/H/o      2/3/4/5/oxx
66.249.70.1     -        3018  <1   675.1M  9   2962/0/56/0  2190/693/135/0/0
163.172.138.63  -        2464  1    75.2M   1   2464/0/0/0   1768/684/12/0/0
46.4.108.51     -        1285  <1   29.5M   1   1285/0/0/0   1182/88/15/0/0
66.249.70.2     -        1159  <1   208.5M  9   1136/0/23/0  864/238/57/0/0
144.76.14.76    -        733   <1   362.4M  1   733/0/0/0    729/3/1/0/0
157.55.39.49    -        703   <1   125.3M  1   703/0/0/0    664/26/13/0/0
157.55.39.58    -        651   <1   71.8M   1   651/0/0/0    614/24/13/0/0
213.44.9.65     -        638   <1   28.0M   1   638/0/0/0    638/0/0/0/0
157.55.39.11    -        594   <1   93.4M   1   594/0/0/0    561/21/12/0/0
207.46.13.155   -        588   <1   102.4M  1   588/0/0/0    546/28/14/0/0
```
UA = unique user-agents\
G/P/H/o = GET/POST/HEAD/other\
2/3/4/5/oxx = HTTP status code class
### User-agents mode
```
$ cat access.log | wab -a
Hits   User-agent
16405  Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36
5474   Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)
3975   Mozilla/5.0 (Linux; Android 7.0;) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)
3735   Mozilla/5.0 (Windows NT 10.0; Win64; x64; trendictionbot0.5.0; trendiction search; http://www.trendiction.de/bot; please let us know of any problems; web at trendiction.com) Gecko/20100101 Firefox/125.0
2892   Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
2464   Mozilla/5.0 (compatible; spider-rs-ng; +https://www.scoop.it/bots.html; like Googlebot;)
2148   Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
1873   Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.155 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
1610   Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0
1312   Mozilla/5.0 (compatible; AwarioBot/1.0; +https://awario.com/bots.html)
```
### Requests mode
```
$ cat access.log | wab -q
2020  /en/ressources/shop/general?parms%5B0%5D=_
1949  /sites/default/files/js/js_z29QQXStuDp9JWcxNjI93Da1lGTDScCfADZ82_anaJM.js?scope=_&delta=_&language=_&theme=_&include=_
1903  /sites/default/files/css/css__1PTj-tCQalzQQxMdHJAVUNg0vcjYf0Q60G88lcrAF8.css?delta=_&language=_&theme=_&include=_
1437  /sites/default/files/js/js_Ab-exdT9qSKlUOEd5h0rLUw5JMN9tzW6Gp6rcZNMkmQ.js?scope=_&delta=_&language=_&theme=_&include=_
1377  /libraries/fontawesome6/webfonts/fa-brands-400.woff2
1348  /en    
1259  /themes/custom/uas_base/asset/icomoon/fonts/icomoon.ttf?3zexv0=_
1227  /libraries/fontawesome6/webfonts/fa-solid-900.woff2
886   /robots.txt
```
### Time distribution mode
```
$ cat access.log | wab -d
[2024-05-15:03:35]  27 *****
[2024-05-15:03:36]  44 ********
[2024-05-15:03:37]  30 *****
[2024-05-15:03:38]  38 *******
[2024-05-15:03:39]  42 *******
[2024-05-15:03:40] 213 ****************************************
[2024-05-15:03:41]  35 ******
[2024-05-15:03:42]  37 ******
[2024-05-15:03:43]  38 *******
[2024-05-15:03:44]  43 ********
[2024-05-15:03:45]  35 ******
```

**NB:** there are no filtering options, just `grep` your logs to stdin

## Install
Download the script somewhere in your PATH and make it executable:
```
sudo curl -so /usr/local/bin/wab https://raw.githubusercontent.com/snowraph/Whackabot/refs/heads/main/whackabot.py
sudo chmod +x /usr/local/bin/wab
```

## Supported log formats
- Apache Combined\
  `66.249.79.128 - - [22/May/2024:18:00:19 +0200] "GET /catalog/ HTTP/1.1" 404 154353 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"`
- Apache Vhost Combined\
  `www.example.com:80 66.249.79.128 - - [22/May/2024:18:00:19 +0200] "GET /catalog/ HTTP/1.1" 404 154353 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"`

## Usage
```
usage: wab [-h] [-f {combined,vcombined}] [--list-formats] [-c COUNT] [-t] [-x] [--no-progress] [--no-color] [-v] [-V] [-r] [-w] [-i] [-u [COUNT]] [-p PREFIX] [-a] [-q] [-s] [-m] [-z] [-d [interval]] [infile]

Find top traffic sources in Apache/Nginx access logs.

positional arguments:
  infile                Logfile (defaut: stdin)

options:
  -h, --help            show this help message and exit
  -f {combined,vcombined}, --format {combined,vcombined}
                        Log format (default: vcombined)
  --list-formats        List available log formats
  -c COUNT, --count COUNT
                        Get top COUNT results for hosts, user-agents and requests modes (default: 10). Format "-COUNT" is also accepted.
  -t, --timestamps      Show timestamps (first/last) for hosts, user-agents and requests modes
  -x, --output-extended
                        Show detailed view for user-agents and requests modes
  --no-progress         Hide progress status
  --no-color            Don't color output
  -v, --verbose         Increase verbosity
  -V, --version         Get program version

Hosts mode (default):
  -r, --reverse-lookup  Try to resolve IP addresses (slow)
  -w, --whois-lookup    Get IP info from Whois (unreliable)
  -i, --ipinfo          Get IP info from ipinfo.io (fast and accurate, read API token from env: export IPINFO_TOKEN=...)
  -u [COUNT], --show-user-agents [COUNT]
                        Show top N (default: 10) user-agents per host
  -p PREFIX, --network-prefix PREFIX
                        Network prefix in CIDR notation (eg. "24" for x.x.x.x/24), to narrow down subnets. Caution: prefixing both IPv4 and IPv6 makes no sense

User agents mode:
  Show top user agents

  -a, --user-agents     User agents mode

Requests mode:
  Show top requests

  -q, --requests        Requests mode
  -s, --requests-ignore-static
                        Ignore static resources
  -m, --requests-remove-query-string
                        Remove query string
  -z, --requests-dont-anonymize-parameters
                        Don't anonymize query string parameters

Time distribution mode:
  Show hits by time interval

  -d [interval], --time-distribution [interval]
                        Time distribution mode (default interval: 1 minute)
  --td-sort-top         Sort by top intervals, display COUNT (default: 10) results
```

## Contributing
Pull requests are welcome. Feel free to open an issue if you want to add other features.
Please provide logs samples for debug.

### Todo
- handle more log formats (see https://goaccess.io/man#options)
- resolve timeout
- resolve cache
- specify custom format from cmdline or config file
- improve ipv6 support
- sorting (hits, bytes, uas)
- machine readable output (csv?)
