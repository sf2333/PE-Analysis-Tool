import requests
import random
import MyUI


def ip_xthread(ip):
    USER_AGENTS = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71 Safari/537.1 LBBROWSER",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.84 Safari/535.11 LBBROWSER",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SV1; QQDownload 732; .NET4.0C; .NET4.0E; 360SE)",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1",
        "Mozilla/5.0 (iPad; U; CPU OS 4_2_1 like Mac OS X; zh-cn) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148 Safari/6533.18.5",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b13pre) Gecko/20110307 Firefox/4.0b13pre",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:16.0) Gecko/20100101 Firefox/16.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11",
        "Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10"
    ]
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    url = "https://api.threatbook.cn/v3/scene/ip_reputation"

    query = {
        "apikey": "97b2e3238957485e9376ae17d5770c4c29c9fdad155e4106b26061fa3730c36f",
        "resource": ip
    }
    try:
        response = requests.request("GET", url, params=query, headers=headers, timeout=3).json()
        ip_severity_level = response["data"][ip]["severity"]  # 情报危害程度
        ip_judgements = response["data"][ip]["judgments"]  # 判定为恶意的类型
        ip_confidence_level = response["data"][ip]["confidence_level"]  # 可信度。通过情报来源及可信度模型判别出来的恶意可信度程度
        ip_is_malicious = response["data"][ip]["is_malicious"]
        print({"是否是恶意ip": ip_is_malicious, "情报可信度": ip_confidence_level, "ip恶意类型": ip_judgements,
               "情报危害程度 info（无危胁）": ip_severity_level})
    except:
        print(" sorry,微步云端没有查找到该文件的ip报告！")
    return 0


def file_xthread_Credibility(sha256):
    USER_AGENTS = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71 Safari/537.1 LBBROWSER",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.84 Safari/535.11 LBBROWSER",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SV1; QQDownload 732; .NET4.0C; .NET4.0E; 360SE)",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1",
        "Mozilla/5.0 (iPad; U; CPU OS 4_2_1 like Mac OS X; zh-cn) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148 Safari/6533.18.5",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b13pre) Gecko/20110307 Firefox/4.0b13pre",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:16.0) Gecko/20100101 Firefox/16.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11",
        "Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10"
    ]
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    url = 'https://api.threatbook.cn/v3/file/report'
    params = {
        'apikey': '97b2e3238957485e9376ae17d5770c4c29c9fdad155e4106b26061fa3730c36f',
        'sandbox_type': 'win7_sp1_enx86_office2003',
        # win7_sp1_enx64_office2013
        # win7_sp1_enx86_office2013
        # win7_sp1_enx86_office2010
        # win7_sp1_enx86_office2007
        # win7_sp1_enx86_office2003
        # ubuntu_1704_x64
        # centos_7_x64
        'sha256': sha256
    }
    listinfo = []
    try:
        response = requests.request("GET", url, params=params, headers=headers, timeout=3).json()

        listinfo.append(str(response["data"]["summary"]["threat_level"]))  # 威胁等级
        listinfo.append(str(response["data"]["summary"]["threat_score"]))  # 威胁评分
        listinfo.append(str(response["data"]["summary"]["sandbox_type"]))  #沙箱运行环境
        listinfo.append(str(response["data"]["summary"]["multi_engines"]))  # 反病毒扫描引擎检出率
        listinfo.append(str(response["data"]["multiengines"]["result"]["Tencent"]))  # 每个扫描引擎检测结果
        listinfo.append(str(response["data"]["multiengines"]["result"]["AVG"]))
        listinfo.append(str(response["data"]["multiengines"]["result"]["Kaspersky"]))
        listinfo.append(str(response["data"]["static"]["details"]["pe_detect"]["urls"]))  # 可疑的url信息

        str_array = ["* 病毒威胁等级：", "* 病毒威胁评分：", "* 沙箱运行环境：", "* 反病毒引擎检出率：", "* 各病毒引擎扫描：\n腾讯哈勃：", "AVG：", "卡巴斯基：", "* 可疑的url信息："]
        print("信誉报告:")
        MyUI.cloud_info += "\n信誉报告:\n"

        for i in range(len(listinfo)):
            print(str_array[i] + listinfo[i])

        for i in range(len(listinfo)):
            MyUI.cloud_info += str_array[i] + listinfo[i] + "\n"
    except:
        print(" sorry,微步云端没有查找到该文件的信誉报告。")
    return 0


def file_xthread_sandbox(sha256):
    url = 'https://api.threatbook.cn/v3/file/report/multiengines'
    USER_AGENTS = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71 Safari/537.1 LBBROWSER",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.84 Safari/535.11 LBBROWSER",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SV1; QQDownload 732; .NET4.0C; .NET4.0E; 360SE)",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1",
        "Mozilla/5.0 (iPad; U; CPU OS 4_2_1 like Mac OS X; zh-cn) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148 Safari/6533.18.5",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b13pre) Gecko/20110307 Firefox/4.0b13pre",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:16.0) Gecko/20100101 Firefox/16.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11",
        "Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10"
    ]
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    params = {
        'apikey': '97b2e3238957485e9376ae17d5770c4c29c9fdad155e4106b26061fa3730c36f',
        'sandbox_type': 'win7_sp1_enx64_office2013',
        # win7_sp1_enx64_office2013
        # win7_sp1_enx86_office2013
        # win7_sp1_enx86_office2010
        # win7_sp1_enx86_office2007
        # win7_sp1_enx86_office2003
        # ubuntu_1704_x64
        # centos_7_x64
        'sha256': sha256
    }
    listinfo = []

    try:
        response = requests.request("GET", url, params=params, headers=headers, timeout=3).json()

        listinfo.append(str(response["data"]["multiengines"]["threat_level"]))  # 威胁等级
        listinfo.append(str(response["data"]["multiengines"]["malware_type"])) #病毒类型
        listinfo.append(str(response["data"]["multiengines"]["malware_family"])) #病毒家族
        listinfo.append(str(response["data"]["multiengines"]["scans"]["Tencent"])) # 各病毒引擎扫描
        listinfo.append(str(response["data"]["multiengines"]["scans"]["AVG"]))
        listinfo.append(str(response["data"]["multiengines"]["scans"]["Kaspersky"]))

        #print([list(response["data"]["multiengines"]["scans"].items())[i] for i in range(0, 5)])
        str_array = ["* 威胁等级：", "* 病毒类型：", "* 病毒家族：", "* 各病毒引擎扫描：\n腾讯哈勃：", "AVG：", "卡巴斯基："]
        print("反病毒引擎检测报告:")
        MyUI.cloud_info += "反病毒引擎检测报告:\n"

        for i in range(len(listinfo)):
            print(str_array[i] + listinfo[i])

        for i in range(len(listinfo)):
            MyUI.cloud_info += str_array[i] + listinfo[i] + "\n"
    except:

        print(" sorry,微步云端没有查找到该文件的反病毒引擎检测报告。")
    return 0
