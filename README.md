![](https://imgur.com/YEfoooS.png)

[![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/stamparm/identYwaf/blob/master/LICENSE)

**identYwaf** is an identification tool that can recognize web protection type (i.e. WAF) based on blind inference. Blind inference is being done based on responses created by a set of predefined offensive payloads, where those are used only to provoke the web protection system in between. Currently it supports more than 60 different protection products (e.g. `aeSecure`, `Airlock`, `CleanTalk`, `CrawlProtect`, `Imunify360`, `MalCare`, `ModSecurity`, `Palo Alto`, `SiteGuard`, `UrlScan`, `Wallarm`, `WatchGuard`, `Wordfence`, etc.), while the knowledge-base is constantly growing. It has been created as part of an independent research done while developing [sqlmap](https://github.com/sqlmapproject/sqlmap/).

## Usage

```
$ python identYwaf.py 
                                    __ __ 
 ____  ___      ___  ____   ______ |  T  T __    __   ____  _____ 
l    j|   \    /  _]|    \ |      T|  |  ||  T__T  T /    T|   __|
 |  T |    \  /  [_ |  _  Yl_j  l_j|  ~  ||  |  |  |Y  o  ||  l_
 |  | |  D  YY    _]|  |  |  |  |  |___  ||  |  |  ||     ||   _|
 j  l |     ||   [_ |  |  |  |  |  |     ! \      / |  |  ||  ] 
|____jl_____jl_____jl__j__j  l__j  l____/   \_/\_/  l__j__jl__j  (1.0.4)

Usage: python identYwaf.py [options] <host|url>

Options:
  --version          Show program's version number and exit
  -h, --help         Show this help message and exit
  --delay=DELAY      Delay (sec) between tests (default: 0)
  --timeout=TIMEOUT  Response timeout (sec) (default: 10)
  --proxy=PROXY      HTTP proxy address (e.g. "http://127.0.0.1:8080")
```

## Screenshot
![screenshot](https://i.imgur.com/tSOAgnn.png)
