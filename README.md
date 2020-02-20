![](https://i.imgur.com/75HpbHJ.png)

[![Build Status](https://api.travis-ci.org/stamparm/identYwaf.svg?branch=master)](https://travis-ci.org/stamparm/identYwaf) [![Python 2.x|3.x](https://img.shields.io/badge/python-2.x|3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/stamparm/identYwaf/blob/master/LICENSE) [![WAFs 80](https://img.shields.io/badge/WAFs-80-red.svg)](https://github.com/stamparm/identYwaf/blob/master/data.json)

**identYwaf** is an identification tool that can recognize web protection type (i.e. WAF) based on blind inference. Blind inference is being done by inspecting responses provoked by a set of predefined offensive (non-destructive) payloads, where those are used only to trigger the web protection system in between (e.g. `http://<host>?aeD0oowi=1 AND 2>1`). Currently it supports more than 80 different protection products (e.g. `aeSecure`, `Airlock`, `CleanTalk`, `CrawlProtect`, `Imunify360`, `MalCare`, `ModSecurity`, `Palo Alto`, `SiteGuard`, `UrlScan`, `Wallarm`, `WatchGuard`, `Wordfence`, etc.), while the knowledge-base is constantly growing.

For more information you can check [slides](https://www.slideshare.net/stamparm/blind-waf-identification) for a talk "**Blind WAF identification**" held at *Sh3llCON 2019* (Santander / Spain).

Note: as part of this project, [screenshots](https://github.com/stamparm/identYwaf/tree/master/screenshots) of characteristic responses for different web protection systems are being gathered (manually) for the future reference.

## Screenshots

![](https://imgur.com/AZVi9vB.png)

![](https://i.imgur.com/tSOAgnn.png)

![](https://imgur.com/FJchQI0.png)

![](https://imgur.com/RqQdVJJ.png)

![](https://imgur.com/weHTSv9.png)

![](https://imgur.com/UKW2cRs.png)

![](https://imgur.com/20cd08y.png)

## Installation

You can download the latest zipball by clicking [here](https://github.com/stamparm/identYwaf/archive/master.zip).

Preferably, you can download identYwaf by cloning the Git repository:

`git clone --depth 1 https://github.com/stamparm/identYwaf.git`

**identYwaf** works out of the box with any Python version from **2.6.x** to **3.x** on any platform.

## Usage

```
$ python identYwaf.py 
                                    __ __ 
 ____  ___      ___  ____   ______ |  T  T __    __   ____  _____ 
l    j|   \    /  _]|    \ |      T|  |  ||  T__T  T /    T|   __|
 |  T |    \  /  [_ |  _  Yl_j  l_j|  ~  ||  |  |  |Y  o  ||  l_
 |  | |  D  YY    _]|  |  |  |  |  |___  ||  |  |  ||     ||   _|
 j  l |     ||   [_ |  |  |  |  |  |     ! \      / |  |  ||  ] 
|____jl_____jl_____jl__j__j  l__j  l____/   \_/\_/  l__j__jl__j  (1.0.XX)

Usage: python identYwaf.py [options] <host|url>

Options:
  --version           Show program's version number and exit
  -h, --help          Show this help message and exit
  --delay=DELAY       Delay (sec) between tests (default: 0)
  --timeout=TIMEOUT   Response timeout (sec) (default: 10)
  --proxy=PROXY       HTTP proxy address (e.g. "http://127.0.0.1:8080")
  --proxy-file=PRO..  Load (rotating) HTTP(s) proxy list from a file
  --random-agent      Use random HTTP User-Agent header value
  --code=CODE         Expected HTTP code in rejected responses
  --string=STRING     Expected string in rejected responses
  --post              Use POST body for sending payloads
```
