import hashlib
import datetime
import time
import sys
import os
import pefile
import string
import re
import pefile
import MyUI


class pe_static(object):
    def fileinfo(file_name, infolist):

        infolist.append(os.path.basename(file_name))
        infolist.append(str(os.path.getsize(file_name)))

        infolist.append(os.path.dirname(os.path.abspath(file_name)))
        pe_name = pefile.PE(file_name)
        modifiedTime = time.localtime(os.stat(file_name).st_mtime)
        createdTime = time.localtime(os.stat(file_name).st_ctime)
        mTime = time.strftime('%Y-%m-%d %H:%M:%S', modifiedTime)
        cTime = time.strftime('%Y-%m-%d %H:%M:%S', createdTime)
        infolist.append(mTime)
        infolist.append(cTime)

        # 获取引用的dll库
        temp = ''
        for i_dll in pe_name.DIRECTORY_ENTRY_IMPORT:
            temp += str(i_dll.dll)
        infolist.append(temp)

        # 获取文件sha256
        f = open(file_name, 'rb')
        sha256_dx = hashlib.sha256()
        fr = f.read()
        sha256_dx.update(fr)
        f.close()
        file_sha256 = sha256_dx.hexdigest()
        infolist.append(file_sha256)

        # 获取节区数量
        num = 0
        for section in pe_name.sections:
            num += 1
        infolist.append(str(num))
        str_arrary = ["文件名：", "文件大小（byte）：", "文件绝对路径：", "最新修改时间： ", "文件创建时间： ",'引入的dll库: ', "文件sha256： ","节区数量： "]

        for m in range(len(infolist)):
            MyUI.file_info += str_arrary[m] + infolist[m] + "\n"

        print("文件信息:")
        for k in range(len(infolist)):
            print(str_arrary[k] + infolist[k])

        print("\n")
        return infolist

    def is_sandbox(filename, shaxian):
        result = {}

        VM_Sign = {
            "VMware trick": b"VMXh",
            "Xen": b"XenVMM",
            "Red Pill": b"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
            "VirtualPc trick": b"\x0f\x3f\x07\x0b",
            "VMCheck.dll": b"\x45\xC7\x00\x01",
            "VMCheck.dll for VirtualPC": b"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
            "Bochs & QEmu CPUID Trick": b"\x44\x4d\x41\x63",
            "Torpig VMM Trick": b"\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
            "Torpig (UPX) VMM Trick": b"\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
        }
        counttricks = 0
        with open(filename, "rb") as f:
            buf = f.read()
            for trick in VM_Sign:
                pos = buf.find(VM_Sign[trick])
                if pos > -1:
                    counttricks += 1
                    result.update({"trick": trick, "offset": hex(pos)})

        if counttricks == 0:
            answer = '无反沙箱功能'

            shaxian.append(answer)
            MyUI.shaxian_info += "沙箱信息:\n" + answer + "\n沙箱具体信息：无\n"
            shaxian.append('沙箱具体信息：无')
            print("沙箱信息:")
            print(shaxian[-1:-3:-1])
        else:
            answer = '可能为反沙箱文件'
            MyUI.shaxian_info += "沙箱信息:\n" + answer + "\n沙箱具体信息：" + str(result) + "\n"
            shaxian.append(answer)
            shaxian.append('沙箱具体信息：' + str(result))
            print("沙箱信息:")
            print(shaxian[-1:-3:-1])
        print("\n")
        return shaxian

    def isSectionExecutable(section):
        characteristics = getattr(section, 'Characteristics')
        if characteristics & 0x00000020 > 0 or characteristics & 0x20000000 > 0:
            return True
        return False

    def isSectionsusicious(section):

        if section.get_entropy() < 1 or section.get_entropy() > 7:
            return True
        return False

    def sec_info(filename, array):
        pe = pefile.PE(filename)
        print("节区信息:")
        for section in pe.sections:
            try:
                section_name = str(section.Name, 'utf-8').encode('ascii', errors='ignore').strip().decode('ascii')
            except:
                section_name = str(section.Name, 'ISO-8859-1').encode('ascii', errors='ignore').strip().decode('ascii')

            section_name = section_name.replace('\u0000', '')
            if section_name == '':
                section_name = '.noname'
            b = {
                "节区名称":  section_name,
                "块属性":  hex(section.Characteristics),
                "节区代码是否执行":  str(pe_static.isSectionExecutable(section)),
                "节区是否是可疑节区":  str(pe_static.isSectionsusicious(section)),
                "虚拟地址":  hex(section.VirtualAddress),
                "虚拟文件大小":  str(section.Misc_VirtualSize),
                "节区原始大小":  str(section.SizeOfRawData),
                "md5":  section.get_hash_md5(),
                "sha1":  section.get_hash_sha1(),
                "sha256":  section.get_hash_sha256(),
                "节区信息熵":  str(section.get_entropy()),
                "数据":  str(section.get_data())[:50],
            }
            print(b)
            MyUI.section_info += str(b) + "\n"
            b = tuple(b.values())
            array.append(b)

        print("\n")
        return array
