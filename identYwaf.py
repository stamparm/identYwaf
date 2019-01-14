#!/usr/bin/env python

"""
Copyright (c) 2019 Miroslav Stampar (@stamparm), MIT
See the file 'LICENSE' for copying permission

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
"""

import base64
import cookielib
import httplib
import json
import optparse
import os
import random
import re
import ssl
import socket
import string
import struct
import subprocess
import sys
import time
import urllib
import urllib2
import zlib

NAME = "identYwaf"
VERSION = "1.0.5"
BANNER = """
                                   ` __ __ `
 ____  ___      ___  ____   ______ `|  T  T` __    __   ____  _____ 
l    j|   \    /  _]|    \ |      T`|  |  |`|  T__T  T /    T|   __|
 |  T |    \  /  [_ |  _  Yl_j  l_j`|  ~  |`|  |  |  |Y  o  ||  l_
 |  | |  D  YY    _]|  |  |  |  |  `|___  |`|  |  |  ||     ||   _|
 j  l |     ||   [_ |  |  |  |  |  `|     !` \      / |  |  ||  ] 
|____jl_____jl_____jl__j__j  l__j  `l____/ `  \_/\_/  l__j__jl__j  (%s)%s""".strip("\n") % (VERSION, "\n")

RAW, TEXT, HTTPCODE, TITLE, HTML, URL = xrange(6)
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"
GET, POST = "GET", "POST"
GENERIC_PROTECTION_KEYWORDS = ('rejected', 'forbidden', 'suspicious', 'malicious', 'captcha', 'invalid', 'your ip', 'please contact', 'terminated', 'protected', 'blocked', 'protection', 'incident', 'denied', 'detected', 'dangerous', 'firewall', 'fw_block', 'unusual activity', 'bad request', 'request id')
GENERIC_PROTECTION_REGEX = r"(?i)\b(%s)\b"
GENERIC_ERROR_MESSAGE_REGEX = r"\b[A-Z][\w, '-]*(protected by|security|unauthorized|detected|attack|error|rejected|allowed|suspicious|automated|blocked|invalid|denied|permission)[\w, '!-]*"
HEURISTIC_PAYLOAD = "1 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"
PAYLOADS = []
SIGNATURES = {}
DATA_JSON = {}
DATA_JSON_FILE = "data.json"
MAX_HELP_OPTION_LENGTH = 18
IS_TTY = sys.stdout.isatty()
COLORIZE = not subprocess.mswindows and IS_TTY
LEVEL_COLORS = {"o": "\033[00;94m", "x": "\033[00;91m", "!": "\033[00;93m", "i": "\033[00;95m", "=": "\033[00;93m", "+": "\033[00;92m", "-": "\033[00;91m"}
VERIFY_OK_INTERVAL = 5
VERIFY_RETRY_TIMES = 3
DEFAULTS = {"timeout": 10}
MAX_MATCHES = 5

if COLORIZE:
    for _ in re.findall(r"`.+?`", BANNER):
        BANNER = BANNER.replace(_, "\033[01;92m%s\033[00;49m" % _.strip('`'))
    for _ in re.findall(r" [Do] ", BANNER):
        BANNER = BANNER.replace(_, "\033[01;93m%s\033[00;49m" % _.strip('`'))
    BANNER = re.sub(VERSION, r"\033[01;91m%s\033[00;49m" % VERSION, BANNER)
else:
    BANNER = BANNER.replace('`', "")

REVISION = random.randint(20, 64)
PLATFORM = random.sample(("X11; %s %s" % (random.sample(("Linux", "Ubuntu; Linux", "U; Linux", "U; OpenBSD", "U; FreeBSD"), 1)[0], random.sample(("amd64", "i586", "i686", "amd64"), 1)[0]), "Windows NT %s%s" % (random.sample(("5.0", "5.1", "5.2", "6.0", "6.1", "6.2", "6.3", "10.0"), 1)[0], random.sample(("", "; Win64", "; WOW64"), 1)[0]), "Macintosh; Intel Mac OS X 10.%s" % random.randint(1, 11)), 1)[0]
USER_AGENT = "Mozilla/5.0 (%s; rv:%d.0) Gecko/20100101 Firefox/%d.0" % (PLATFORM, REVISION, REVISION)
HEADERS = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "identity", "Cache-Control": "max-age=0"}

original = None
options = None
intrusive = None

_exit = exit

def exit(message):
    print "%s%s" % (message, ' ' * 20)  # identYwaf requires usage of Python 2.x
    _exit(1)

def retrieve(url, data=None):
    retval = {}
    try:
        req = urllib2.Request("".join(url[_].replace(' ', "%20") if _ > url.find('?') else url[_] for _ in xrange(len(url))), data, HEADERS)
        resp = urllib2.urlopen(req, timeout=options.timeout)
        retval[URL] = resp.url
        retval[HTML] = resp.read()
        retval[HTTPCODE] = resp.code
        retval[RAW] = "%s %d %s\n%s\n%s" % (httplib.HTTPConnection._http_vsn_str, retval[HTTPCODE], resp.msg, "".join(resp.headers.headers), retval[HTML])
    except Exception, ex:
        retval[URL] = getattr(ex, "url", url)
        retval[HTTPCODE] = getattr(ex, "code", None)
        try:
            retval[HTML] = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", "")
        except:
            retval[HTML] = ""
        retval[RAW] = "%s %s %s\n%s\n%s" % (httplib.HTTPConnection._http_vsn_str, retval[HTTPCODE] or "", getattr(ex, "msg", ""), "".join(ex.headers.headers) if hasattr(ex, "headers") else "", retval[HTML])
    match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    return retval

def calc_hash(line, binary=True):
    result = zlib.crc32(line) & 0xffffL
    if binary:
        result = struct.pack(">H", result)
    return result

def check_payload(payload, protection_regex=GENERIC_PROTECTION_REGEX % '|'.join(GENERIC_PROTECTION_KEYWORDS)):
    global intrusive

    time.sleep(options.delay or 0)
    _ = "%s%s%s=%s" % (options.url, '?' if '?' not in options.url else '&', "".join(random.sample(string.letters, 3)), urllib.quote(payload))
    intrusive = retrieve(_)
    result = intrusive[HTTPCODE] != original[HTTPCODE] or intrusive[TITLE] != original[TITLE] or (re.search(protection_regex, intrusive[HTML]) is not None and re.search(protection_regex, original[HTML]) is None)
    return result

def colorize(message):
    if COLORIZE:
        message = re.sub(r"\[(.)\]", lambda match: "[%s%s\033[00;49m]" % (LEVEL_COLORS[match.group(1)], match.group(1)), message)

        if "rejected summary" in message:
            for match in re.finditer(r"[^\w]'([^)]+)'", message):
                message = message.replace("'%s'" % match.group(1), "'\033[37m%s\033[00;49m'" % match.group(1), 1)
        else:
            for match in re.finditer(r"[^\w]'([^']+)'", message):
                message = message.replace("'%s'" % match.group(1), "'\033[37m%s\033[00;49m'" % match.group(1), 1)

        if "blind match" in message:
            for match in re.finditer(r"\(((\d+)%)\)", message):
                message = message.replace(match.group(1), "\033[%dm%s\033[00;49m" % (92 if int(match.group(2)) >= 95 else (93 if int(match.group(2)) > 80 else 90), match.group(1)))

        if "hardness" in message:
            for match in re.finditer(r"\(((\d+)%)\)", message):
                message = message.replace(match.group(1), "\033[%dm%s\033[00;49m" % (91 if " insane " in message else (95 if " hard " in message else (93 if " moderate " in message else 92)), match.group(1)))

    return message

def parse_args():
    global options

    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("--delay", dest="delay", type=int, help="Delay (sec) between tests (default: 0)")
    parser.add_option("--timeout", dest="timeout", type=int, help="Response timeout (sec) (default: 10)")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")

    # Dirty hack(s) for help message
    def _(self, *args):
        retval = parser.formatter._format_option_strings(*args)
        if len(retval) > MAX_HELP_OPTION_LENGTH:
            retval = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % retval
        return retval

    parser.usage = "python %s <host|url>" % parser.usage
    parser.formatter._format_option_strings = parser.formatter.format_option_strings
    parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser, type(parser))

    for _ in ("-h", "--version"):
        option = parser.get_option(_)
        option.help = option.help.capitalize()

    try:
        options, _ = parser.parse_args()
    except SystemExit:
        raise

    if len(sys.argv) > 1:
        url = sys.argv[-1]
        if not url.startswith("http"):
            url = "http://%s" % url
        options.url = url
    else:
        parser.print_help()
        raise SystemExit

    for key in DEFAULTS:
        if getattr(options, key, None) is None:
            setattr(options, key, DEFAULTS[key])

def init():
    os.chdir(os.path.abspath(os.path.dirname(__file__)))

    if os.path.isfile(DATA_JSON_FILE):
        print colorize("[o] loading data...")

        content = open(DATA_JSON_FILE, "rb").read()
        DATA_JSON.update(json.loads(content))

        for waf in DATA_JSON["wafs"]:
            for signature in DATA_JSON["wafs"][waf]["signatures"]:
                SIGNATURES[signature] = waf
    else:
        exit(colorize("[x] file '%s' is missing" % DATA_JSON_FILE))

    print colorize("[o] initializing handlers...")

    # Reference: https://stackoverflow.com/a/28052583
    if hasattr(ssl, "_create_unverified_context"):
        ssl._create_default_https_context = ssl._create_unverified_context

    cookie_jar = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie_jar))
    urllib2.install_opener(opener)

    if options.proxy:
        opener = urllib2.build_opener(urllib2.ProxyHandler({"http": options.proxy, "https": options.proxy}))
        urllib2.install_opener(opener)

def run():
    global original

    hostname = options.url.split("//")[-1].split('/')[0]

    if not hostname.replace('.', "").isdigit():
        print colorize("[i] checking hostname '%s'..." % hostname)
        try:
            socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            exit(colorize("[x] host '%s' does not exist" % hostname))

    results = ""
    signature = ""
    counter = 0
    original = retrieve(options.url)

    if 300 <= original[HTTPCODE] < 400 and original[URL]:
        original = retrieve(original[URL])

    options.url = original[URL]

    #if re.search(r"(?i)captcha", original[HTML]) is not None:
        #exit(colorize("[x] there seems to be an activated captcha"))

    if original[HTTPCODE] is None:
        exit(colorize("[x] missing valid response"))

    if original[HTTPCODE] >= 400:
        for waf in DATA_JSON["wafs"]:
            if re.search(DATA_JSON["wafs"][waf]["regex"], original[RAW]):
                found = True
                print colorize("[+] non-blind match: '%s'" % DATA_JSON["wafs"][waf]["name"])
                break

        exit(colorize("[x] access to host '%s' seems to be restricted%s" % (hostname, (" (%d: '%s')" % (original[HTTPCODE], original[TITLE].strip())) if original[TITLE] else "")))

    protection_keywords = GENERIC_PROTECTION_KEYWORDS
    protection_regex = GENERIC_PROTECTION_REGEX % '|'.join(keyword for keyword in protection_keywords if keyword not in original[HTML].lower())

    print colorize("[i] running basic heuristic test...")
    if not check_payload(HEURISTIC_PAYLOAD):
        check = False
        if options.url.startswith("https://"):
            options.url = options.url.replace("https://", "http://")
            check = check_payload(HEURISTIC_PAYLOAD)
        if not check:
            exit(colorize("[x] host '%s' does not seem to be protected" % hostname))

    if not intrusive[HTTPCODE]:
        print colorize("[i] rejected summary: RST|DROP")
    else:
        _ = "...".join(match.group(0) for match in re.finditer(GENERIC_ERROR_MESSAGE_REGEX, intrusive[HTML])).strip().replace("  ", " ")
        print colorize(("[i] rejected summary: %d ('%s%s')" % (intrusive[HTTPCODE], ("<title>%s</title>" % intrusive[TITLE]) if intrusive[TITLE] else "", "" if not _ or intrusive[HTTPCODE] < 400 else ("...%s" % _))).replace(" ('')", ""))

    found = False
    for waf in DATA_JSON["wafs"]:
        if re.search(DATA_JSON["wafs"][waf]["regex"], intrusive[RAW] if intrusive[HTTPCODE] is not None else original[RAW]):
            found = True
            print colorize("[+] non-blind match: '%s'" % DATA_JSON["wafs"][waf]["name"])
            break

    if not found:
        print colorize("[-] non-blind match: -")

    for payload in DATA_JSON["payloads"]:
        counter += 1

        if IS_TTY:
            sys.stdout.write(colorize("\r[i] running payload tests... (%d/%d)\r" % (counter, len(DATA_JSON["payloads"]))))
            sys.stdout.flush()

        if counter % VERIFY_OK_INTERVAL == 0:
            for i in xrange(VERIFY_RETRY_TIMES):
                if not check_payload(str(random.randint(1, 9)), protection_regex):
                    break
                elif i == VERIFY_RETRY_TIMES - 1:
                    exit(colorize("[x] host '%s' seems to be (also) rejecting benign requests%s" % (hostname, (" (%d: '%s')" % (intrusive[HTTPCODE], intrusive[TITLE].strip())) if intrusive[TITLE] else "")))
                else:
                    time.sleep(5)

        last = check_payload(payload, protection_regex)
        signature += struct.pack(">H", ((calc_hash(payload, binary=False) << 1) | last) & 0xffff)
        results += 'x' if last else '.'

    signature = "%s:%s" % (calc_hash(signature).encode("hex"), base64.b64encode(signature))

    print colorize("\n[=] results: '%s'" % results)

    hardness = 100 * results.count('x') / len(results)
    print colorize("[=] hardness: %s (%d%%)" % ("insane" if hardness >= 80 else ("hard" if hardness >= 50 else ("moderate" if hardness >= 30 else "easy")), hardness))

    if not results.strip('.'):
        print colorize("[-] blind match: -")
    else:
        print colorize("[=] signature: '%s'" % signature)

        if signature in SIGNATURES:
            print colorize("[+] blind match: '%s' (100%%)" % DATA_JSON["wafs"][SIGNATURES[signature]]["name"])
        elif results.count('.') < 3:
            print colorize("[-] blind match: -")
        else:
            matches = {}
            markers = set()
            decoded = signature.split(':')[-1].decode("base64")
            for i in xrange(0, len(decoded), 2):
                part = struct.unpack(">H", decoded[i: i + 2])[0]
                markers.add(part)

            for candidate in SIGNATURES:
                counter_y, counter_n = 0, 0
                decoded = candidate.split(':')[-1].decode("base64")
                for i in xrange(0, len(decoded), 2):
                    part = struct.unpack(">H", decoded[i: i + 2])[0]
                    if part in markers:
                        counter_y += 1
                    elif any(_ in markers for _ in (part & ~1, part | 1)):
                        counter_n += 1
                result = int(round(100 * counter_y / (counter_y + counter_n)))
                if SIGNATURES[candidate] in matches:
                    if result > matches[SIGNATURES[candidate]]:
                        matches[SIGNATURES[candidate]] = result
                else:
                    matches[SIGNATURES[candidate]] = result

            matches = [(_[1], _[0]) for _ in matches.items()]
            matches.sort(reverse=True)

            print colorize("[+] blind match: %s" % ", ".join("'%s' (%d%%)" % (DATA_JSON["wafs"][matches[i][1]]["name"], matches[i][0]) for i in xrange(MAX_MATCHES if matches[0][0] != 100 else 1)))

    print

def main():
    if "--version" not in sys.argv:
        print BANNER

    parse_args()
    init()
    run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit(colorize("\r[x] Ctrl-C pressed"))
