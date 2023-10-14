# coding=utf-8
import dpkt
import socket
from scapy.all import *
#from IPy import IP as PYIP
import threading
import os


def Findshellurl(pcap):
    message = []
    f = open(pcap, errors='ignore')
    pcap = dpkt.pcap.Reader(f)

    for timestamp, packet in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(packet)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            tcp = ip.data
            http = dpkt.http.Request(tcp.data)
            shell = ['php', 'asp', 'aspx', 'jsp', 'js']
            if (http.method == "POST"):  # 使用后改为POST,查看一句话木马的
                for WordKey in shell:
                    uri = http.uri.lower()
                    if WordKey in uri:
                        # print("[+] 源地址: {} --> 目标地址: {} 检索到URL中存在 {} 字样,路径为 {}".format(src,dst,WordKey,uri))
                        message.append({
                            "源地址：": src,
                            "目的地址：": dst,
                            "存在{}字样：": WordKey,
                            "所在路径：": uri
                        }
                        )
        except Exception:
            pass
    print(message)
    return message


def FindHivemind(pcap):
    for timestamp, packet in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(packet)
            ip = eth.data
            tcp = ip.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            sport = tcp.sport
            dport = tcp.dport
            print("[+] 源地址: {}:{} --> 目标地址:{}:{}".format(src, sport, dst, dport))
            if 'cmd' in tcp.data.lower():
                print("[+] {}:{}".format(dst, dport))
        except Exception:
            pass


def FindDDosAttack(pcap):
    pktCount = {}
    for timestamp, packet in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(packet)
            ip = eth.data
            tcp = ip.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            sport = tcp.sport
            dport = tcp.dport
            # 累计判断各个src地址对目标地址80端口访问次数
            if dport == 80:
                stream = src + ":" + dst
                if pktCount.has_key(stream):
                    pktCount[stream] = pktCount[stream] + 1
                else:
                    pktCount[stream] = 1
        except Exception:
            pass
    for stream in pktCount:
        pktSent = pktCount[stream]
        # 如果超过设置的检测阈值500,则判断为DDOS攻击行为
        if pktSent > 500:
            src = stream.split(":")[0]
            dst = stream.split(":")[1]
            print("[+] 源地址: {} 攻击: {} 流量: {} pkts.".format(src, dst, str(pktSent)))


def getpcap():
    packets = sniff(iface="Qualcomm Atheros QCA9377 Wireless Network Adapter", timeout=300)
    pcap_time = time.strftime("%Y-%m-%d-%H-%M")
    pcap_name = "D:/8.python/内网流量监测/pcap报文/" + pcap_time + '.pcap'
    wrpcap(pcap_name, packets)
    return pcap_name



# "H:\PE文件分析\exe-restore.pcap"

message = []
file = 'H:\Virus analysis system\exe-restore.pcap'
with open(file, 'rb') as fr:
    pcap = dpkt.pcap.Reader(fr)
    for timestamp, buffer in pcap:
        ethernet = dpkt.ethernet.Ethernet(buffer)
        # 我们仅需要TCP的包
        if not isinstance(ethernet.data, dpkt.ip.IP):
            continue
        ip = ethernet.data

        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue
        tcp = ip.data

        # 过滤掉内容为空的包
        if len(tcp.data) == 0:
            continue
        # 发送方的IP
        src = socket.inet_ntoa(ip.src)
        message.append(src)
        # 接收方的IP
        dst = socket.inet_ntoa(ip.dst)
        message.append(dst)
        # 报文内容（byte数组）
        byteArray = tcp.data

        # TODO 根据自定义的协议内容，解析bytes数组
print(message)


