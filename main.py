import pe_data
import static_pe
import pefile
import threading
import pymysql
import api
import get_tcpdata
import os
import MyUI

# 定义用于存放mysql插入数据的列表
section_list = []
infolist = []
tls_list = []
resources_list = []
relocations_list = []
import_list = []


def Virus_analysis_system(inputation):
    if ".pcap" in inputation:
        try:
            t1 = get_tcpdata.AnalysisPcap(inputation)
            t1.restorefile()
            MyUI.restore += "！！！PE文件已恢复成功！！！  默认恢复到当前文件夹，名称为：\"result.exe\"。 \n"
            print("恢复成功！！！！！")
            filename = "result.exe"
        except Exception as e:
            print(e)
    else:
        filename = inputation
    #filename = get_file()
    try:
        os.path.exists(filename)  # 判读文件是否存在
        pe_name = pefile.PE(filename)  # pe文件名

        # 本地分析
        local_analysis(filename, pe_name, infolist, tls_list, resources_list, relocations_list, import_list,section_list)

        # 连接云端分析
        api_connect(infolist)
        # 数据库
        contect_mysql(infolist, tls_list, resources_list, relocations_list, import_list)
        print("-" * 120)


    except Exception as e:
        print(e)

    return 0

def get_file():
    while 1:
        print("是否使用本地pcap文件进行PE文件复原？\n    (1)是的，请马上开始！     (2)不，我直接利用现成的PE文件进行分析。")
        Is_pcap_restore = input("☆please input 1 or 2: ")
        if Is_pcap_restore.isnumeric():
            if int(Is_pcap_restore) == 1:
                pcap_path = input("☆请输入pcap文件绝对路径：")
                #测试文件路径：H:/PE文件分析/exe-restore.pcap
                try:
                    t1 = get_tcpdata.AnalysisPcap(pcap_path)
                    t1.restorefile()
                    print("\n！！！！！文件恢复成功！！！！！")
                    filename = "result.exe"
                    break
                except Exception as e:
                    print("\n！！！！！文件恢复失败！！！！！")
                    print(e)
                    print("输入有误，请重新输入！\n")

            if int(Is_pcap_restore) == 2:
                filename = input("☆请输入本地PE文件的绝对路径：")
                break
        else:
            print("输入有误，请重新输入！\n")
    return filename

def local_analysis(filename, pe_name, infolist, tls_list, resources_list, relocations_list, import_list, section_list):
    print("\n" + "-" * 54 + "本地分析结果" + "-" * 54 + "\n")
    # 使用threading模块，threading.Thread()创建线程，其中target参数值为需要调用的方法，同样将其他多个线程放在一个列表中，遍历这个列表就能同时执行里面的函数了
    threads = [threading.Thread(target=static_pe.pe_static.fileinfo, name='fileinfo', args=(filename, infolist,)),
               threading.Thread(target=static_pe.pe_static.sec_info, name='sec_info', args=(filename, section_list,)),
               threading.Thread(target=static_pe.pe_static.is_sandbox, name='is_sandbox', args=(filename, infolist,)),
               threading.Thread(target=pe_data.get, name='get_information', args=(pe_name, tls_list, resources_list, relocations_list, import_list))
               ]

    for t in threads:
        # 启动线程
        t.start()
        t.join()

    return 0

def api_connect(infolist):

    print("\n" + "-" * 54 + "云端分析结果" + "-" * 54 + "\n")
    sha_256 = infolist[6]
    api.file_xthread_sandbox(sha_256)
    print("\n")
    api.file_xthread_Credibility(sha_256)
    print("\n")

def contect_mysql(infolist, tls_list, resources_list, relocations_list, import_list):

    '''
    while 1:
        print("-" * 120)

        print("是否要将本地分析获得的数据上传数据库？\n    (1)是的，请马上开始！     (2)不，仅仅本地分析就足够。")
        Is_contect_mysql = input("☆please input 1 or 2: ")
        if Is_contect_mysql.isnumeric():
            if int(Is_contect_mysql) == 1:
                username = input("☆请输入您的MySQL数据库用户名：")
                u_password = input("☆请输入该用户名对应的密码：")
                print("Notice: 仅支持MySQL账号的主机地址是：127.0.0.1，端口号是：3306，如不一致，请自行修改!")
                u_host = '127.0.0.1'
                u_port = 3306
    '''
    try:
        # 建立数据库连接
        con_engine = pymysql.connect(host='127.0.0.1', user='root', password='123456',
                                     port=3306, charset='utf8')
    except Exception as e:
        print("\n！！！！！连接失败！！！！！")
        print(e)


    print("\n" + "-" * 53 + "数据库上传结果" + "-" * 53 + "\n")
    # 使用cursor()方法获取游标
    cursor = con_engine.cursor()
    # 创建数据库的sql(如果数据库存在就不创建，防止异常)
    sql = "CREATE DATABASE IF NOT EXISTS eywjjc"
    # 执行创建数据库的sql
    cursor.execute(sql)
    # 连接数据库
    cursor.execute("USE eywjjc")

    # 节区信息表
    sql_createTb = """CREATE TABLE IF NOT EXISTS  节区信息(
                                 节区名称  CHAR(20),
                                 块属性 CHAR(20),
                                 节区代码是否被执行 CHAR(20),
                                 节区是否是可疑节区 CHAR(20),
                                 虚拟地址 CHAR(20),
                                 虚拟文件大小 CHAR(20),
                                 节区原始大小 CHAR(20),
                                 md5 LONGTEXT,
                                 sha1 LONGTEXT,
                                 sha256 LONGTEXT,
                                 节区信息熵 LONGTEXT,
                                 数据 LONGTEXT)
                                 """

    cursor.execute(sql_createTb)

    # 插入数据
    sql_insert = "insert into 节区信息(节区名称, 块属性, 节区代码是否被执行, 节区是否是可疑节区,虚拟地址, 虚拟文件大小, 节区原始大小, md5,sha1,sha256, 节区信息熵, 数据 ) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    try:
        # print(section_list)
        cursor.executemany(sql_insert, section_list)
        con_engine.commit()

        MyUI.mysql_info += "节区信息批量插入成功！\n"
        print("节区信息批量插入成功！\n")
    except Exception as e:
        print(e)
        con_engine.rollback()
        MyUI.mysql_info += "节区信息批量插入失败！\n"
        print("节区信息批量插入失败！\n")

    # 文件信息表
    sql_createTb = """CREATE TABLE IF NOT EXISTS  文件信息(
                                 文件名  CHAR(20),
                                 文件大小 CHAR(20),
                                 文件绝对路径 LONGTEXT,
                                 最新修改时间 LONGTEXT,
                                 文件创建时间 LONGTEXT,
                                 引入的dll库 LONGTEXT,
                                 文件sha256 LONGTEXT,
                                 节区数量 LONGTEXT,
                                 反沙箱功能 LONGTEXT,
                                 反沙箱VM_SIGN LONGTEXT)
                                 """

    cursor.execute(sql_createTb)

    # 插入数据
    sql_insert = "insert into 文件信息(文件名, 文件大小, 文件绝对路径, 最新修改时间, 文件创建时间, 引入的dll库, 文件sha256, 节区数量, 反沙箱功能, 反沙箱VM_SIGN ) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    try:
        temp = tuple(infolist)
        infolist = [temp]
        print(infolist)
        cursor.executemany(sql_insert, infolist)
        con_engine.commit()

        MyUI.mysql_info += "文件信息批量插入成功！\n"
        print("文件信息批量插入成功！\n")
    except Exception as e:
        print(e)
        con_engine.rollback()

        MyUI.mysql_info += "文件信息批量插入失败！\n"
        print("文件信息批量插入失败！\n")

    # TLS表信息表
    sql_createTb = """CREATE TABLE IF NOT EXISTS  TLS表信息(
                                 TLS模板的起始地址  LONGTEXT,
                                 TLS的最后一个字节的地址 LONGTEXT,
                                 TLS索引的位置 LONGTEXT,
                                 指向TLS回调函数数组的指针 LONGTEXT,
                                 模板的大小 LONGTEXT,
                                 描述目标文件中节的对齐方式 LONGTEXT)
                                 """

    cursor.execute(sql_createTb)

    # 插入数据
    sql_insert = "insert into TLS表信息(TLS模板的起始地址, TLS的最后一个字节的地址, TLS索引的位置, 指向TLS回调函数数组的指针, 模板的大小, 描述目标文件中节的对齐方式 ) values(%s,%s,%s,%s,%s,%s)"
    try:
        temp = tuple(tls_list)
        tls_list = [temp]
        print(tls_list)
        cursor.executemany(sql_insert, tls_list)
        con_engine.commit()

        MyUI.mysql_info += "tls表插入成功！\n"
        print("tls表批量插入成功！\n")
    except Exception as e:
        print(e)
        con_engine.rollback()

        MyUI.mysql_info += "tls表插入失败！\n"
        print("tls表批量插入失败！\n")

    # 资源表信息表
    sql_createTb = """CREATE TABLE IF NOT EXISTS  资源表信息(
                                 ICON资源名称  LONGTEXT,
                                 文件数据 LONGTEXT,
                                 是否是pe文件 LONGTEXT,
                                 offset LONGTEXT,
                                 文件大小 LONGTEXT,
                                 使用语言 LONGTEXT,
                                 联合语言 LONGTEXT)
                                 """

    cursor.execute(sql_createTb)

    # 插入数据
    sql_insert = "insert into 资源表信息(ICON资源名称, 文件数据, 是否是pe文件, offset, 文件大小, 使用语言, 联合语言 ) values(%s,%s,%s,%s,%s,%s,%s)"
    try:
        # print(resources_list)
        cursor.executemany(sql_insert, resources_list)
        con_engine.commit()

        MyUI.mysql_info += "资源表插入成功！\n"
        print("资源表信息批量插入成功！\n")
    except Exception as e:
        print(e)
        con_engine.rollback()

        MyUI.mysql_info += "资源表插入失败！\n"
        print("资源表信息批量插入失败！\n")

    # 重定向表信息表
    sql_createTb = """CREATE TABLE IF NOT EXISTS  重定向表信息(
                                 虚拟地址  LONGTEXT,
                                 当前块的总大小 LONGTEXT,
                                 重定向次数 LONGTEXT,
                                 具体信息 LONGTEXT)
                                 """

    cursor.execute(sql_createTb)

    # 插入数据
    sql_insert = "insert into 重定向表信息(虚拟地址, 当前块的总大小, 重定向次数, 具体信息 ) values(%s,%s,%s,%s)"
    try:
        temp = tuple(relocations_list)
        relocations_list = [temp]
        print(resources_list)
        cursor.executemany(sql_insert, relocations_list)
        con_engine.commit()

        MyUI.mysql_info += "重定向表插入成功！\n"
        print("重定向表批量插入成功！\n")
    except Exception as e:
        print(e)
        con_engine.rollback()

        MyUI.mysql_info += "重定向表插入失败！\n"
        print("重定向表批量插入失败！\n")

    # 导入表信息表
    sql_createTb = """CREATE TABLE IF NOT EXISTS  导入表信息(
                                 导入的dll库  LONGTEXT,
                                 函数所在地址 LONGTEXT,
                                 函数名称 LONGTEXT)
                                 """

    cursor.execute(sql_createTb)

    # 插入数据
    sql_insert = "insert into 导入表信息(导入的dll库, 函数所在地址, 函数名称 ) values(%s,%s,%s)"
    try:
        # print(import_list)
        cursor.executemany(sql_insert, import_list)
        con_engine.commit()

        MyUI.mysql_info += "导入表插入成功！\n"
        print("导入表信息批量插入成功！\n")
    except Exception as e:
        print(e)
        con_engine.rollback()

        MyUI.mysql_info += "导入表插入失败！\n"
        print("导入表信息批量插入失败！\n")

    con_engine.close()




