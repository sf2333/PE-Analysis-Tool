# -*- coding: UTF-8 -*-
import struct
import io
import sys
import codecs
sys.path.append('tcp.py')
from tcp import TcpData
from binascii import unhexlify
import binascii
import chardet
import re

class AnalysisPcap(object):

    def __init__(self, pcap_path):
        self.pcap_path = pcap_path

    def get_tcp_data(self,data):
        #传Tcp中的 src, dst,src_port,dst_port, seq, ack, flags, content
        ip_header_len = (data[14] & 0x0F) * 4
        ip_total_len = struct.unpack(
            '!H', data[16: 18])[0]
        src_ip = '.'.join([str(i) for i in data[26:30]])
        dst_ip = '.'.join([str(i) for i in data[30:34]])
        src_port = struct.unpack(
            '!H', data[14 + ip_header_len:14 + ip_header_len + 2])[0]
        dst_port = struct.unpack(
            '!H', data[14 + ip_header_len + 2:14 + ip_header_len + 4])[0]
        seq = struct.unpack(
            '!I', data[14 + ip_header_len + 4:14 + ip_header_len + 8])[0]
        ack = struct.unpack(
            '!I', data[14 + ip_header_len + 8:14 + ip_header_len + 12])[0]
        flags = data[14 + ip_header_len + 13]
        tcp_header_len = (data[14 + ip_header_len + 12] >> 4) * 4
        tcontent = data[14 + ip_header_len + tcp_header_len:14 + ip_total_len]

        return [src_ip, dst_ip, src_port, dst_port, seq, ack, flags, tcontent]


    def is_ipv4_tcp(self,data):
        return struct.unpack('H', data[12:14])[0] == 8 and data[23] == 6

    def dump_tcp_content(self):   #将pcap报文分层 开发时可以根据计算机网络帧查看标志位
        open_file = open(self.pcap_path, 'rb')
        file_length = int(open_file.seek(0, io.SEEK_END))
        open_file.seek(24)
        pcap_header = 24
        tcp_stream = []
        while pcap_header < file_length:
            open_file.seek(8, io.SEEK_CUR)
            pkt_length = struct.unpack('I', open_file.read(4))[0]
            open_file.seek(4, io.SEEK_CUR)
            pkt_body = open_file.read(pkt_length)
            if self.is_ipv4_tcp(pkt_body):
                data = self.get_tcp_data(pkt_body)
                tcp_stream.append(data)
            pcap_header += 16 + pkt_length
        open_file.close()

        return tcp_stream

    def dump_reassemble_stream(self, client_ads, server_ads):  #获取三次握手
        tcp_stream = self.dump_tcp_content()
        reassemble_stream = TcpData(
            tcp_stream, client_ads, server_ads).reassemble_tcp()
        return reassemble_stream




    def get_header(self): #获取http头
        tcp_data = self.dump_tcp_content()
        for i in tcp_data:
            while "POST" in str(i[7]):
                headers = str(i [7])
                break
        header = headers.replace("b'", "")
        header = header.replace("r", "n")
        header = header.replace("\\n\\n", "\n")
        header = header.replace("\\x", "")
        return header

    def get_filehex(self):
        tcp_data = self.dump_tcp_content()
        content = ''
        for meta in tcp_data:
            if meta[7]:
                content=content+str(binascii.hexlify(meta[7])).replace("b'","").replace("'","")
        return content

    def restorefile(self):
        hex = self.get_filehex()
        jpgstart = "ffd8ff"
        jpgend = "ffd9"
        pngstart="89504e47"
        pngend="ae426082"
        zipstart="504B0304"
        zipend="504b"
        pdfstart="255044462D312E"
        pdfend="2525454f460d"
        dosstart = "4d5a"
        dosend = "5045"


        if jpgend in hex and jpgstart in hex:
            start = hex.find(jpgstart)
            end = hex.rfind(jpgend)
            filehex = hex[start:end]+'ffd9'
            s = open("./result.jpg", "wb")
            for i in range(0, len(filehex), 2):
                temp = filehex[i:i + 2]
                hext = int(temp, 16)
                bint = hext.to_bytes(1, byteorder="big")
                s.write(bint)

        if pngend in hex and pngstart in hex:
            start = hex.find(pngstart)
            end = hex.rfind(pngend)
            filehex = hex[start:end]+'ae426082'
            s = open("./result.png", "wb")
            for i in range(0, len(filehex), 2):
                temp = filehex[i:i + 2]
                hext = int(temp, 16)
                bint = hext.to_bytes(1, byteorder="big")
                s.write(bint)

        if zipend in hex and zipstart in hex:
            start = hex.find(zipstart)
            end = hex.rfind(zipend)
            filehex = hex[start:end]+'504b'
            s = open("./result.zip", "wb")
            for i in range(0, len(filehex), 2):
                temp = filehex[i:i + 2]
                hext = int(temp, 16)
                bint = hext.to_bytes(1, byteorder="big")
                s.write(bint)

        if pdfend in hex and pdfstart in hex:
            start = hex.find(pdfstart)
            end = hex.rfind(pdfend)
            filehex = hex[start:end]+'2525454f460d'
            s = open("./result.pdf", "wb")
            for i in range(0, len(filehex), 2):
                temp = filehex[i:i + 2]
                hext = int(temp, 16)
                bint = hext.to_bytes(1, byteorder="big")
                s.write(bint)

        if dosstart in hex:

            start = hex.find(dosstart)  #找到exe文件在报文中的起始位置
            pestart  =hex.find(dosend) #找到pe头开始的位置，这也是dos头的结束地方
            exe_data = hex[start:]
            pedata = hex[pestart:]
            pe_secnumber = int(pedata[13],16) #pe文件的节区数目
            pe_headerlength = int(pedata[40:42],16)#
            secdata=pedata[48+pe_headerlength*2:]#找到节区的起始
            sec = 0
            datalength = []
            for sec in range(0,pe_secnumber):

                lenbehind = secdata[32+80*sec:34+80*sec]
                leninfron = secdata[34+80*sec:36+80*sec] #找到节区的长度（在dos头中，rtext的信息存放地址到rdata的信息存放地址的长度是40byte，）
                len=int(leninfron+lenbehind,16)
                datalength.append(len)
                sec +=1
            length=0
            for i in datalength:
                 length+=i
            length=2*(length+1024)#1024是因为一般都是这么多。。。
            s = open("./result.exe", "wb")
            for i in range(0, length, 2):
                temp = exe_data[i:i + 2]
                hext = int(temp, 16)
                bint = hext.to_bytes(1, byteorder="big")
                s.write(bint)


