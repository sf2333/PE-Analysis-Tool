import re
import json
import string
import unicodedata
import sys

def get_wanted_chars(self):
    wanted_chars = ["\0"] * 256

    for i in range(32, 127):
        wanted_chars[i] = chr(i)

    wanted_chars[ord("\t")] = "\t"
    ms = "".join(wanted_chars)
    return ms


def get_result(filename):
    results = []
    THRESHOLD = 4

    for s in open(filename, errors="ignore").read().translate(get_wanted_chars()).split("\0"):
        if len(s) >= THRESHOLD:
            info = re.findall(r'[^\u4e00-\u9fa5]+', s)
            results.append(info)
    return results


def valid_ip(address):
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if b >= 0 and b <= 255]
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False


def get_info(filename):
    ip_list = []
    file_list = []
    url_list = []
    strings_list = list(get_result(filename))
    for string in strings_list:
        string = str(string)

        urllist = re.findall(r'((smb|srm|ssh|ftps?|file|https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)',
                             string, re.MULTILINE)
        if urllist:
            for url in urllist:
                url_list.append(re.sub(r'\(|\)|;|,|\$', '', url[0]))  # url_list是最终存储url的列表。

        iplist = re.findall(r'[0-9]+(?:\.[0-9]+){3}', string, re.MULTILINE)
        if iplist:
            for ip in iplist:
                if valid_ip(str(ip)) and not re.findall(r'[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}\.0', str(ip)):
                    ip_list.append(str(ip))

        fname = re.findall("(.+(\.([a-z]{2,3}$)|\/.+\/|\\\.+\\\))+", string, re.IGNORECASE | re.MULTILINE)
        if fname:
            for name in fname:
                file_list.append(name[0])

    req_info = []
    for i in urllist:
        req_info.append(i)
    for i in ip_list:
        req_info.append(i)
    for i in file_list:
        req_info.append(i)
    return req_info
