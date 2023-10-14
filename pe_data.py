import pefile
import re
import binascii
import MyUI

# pe_name 是 pefile.PE(文件名) 导入表信息如下
# 输出函数的地址，导入的dll库、函数名称
def get_import(pe_name, import_list):

    dll_info = []
    print("导入表信息:")
    for entry in pe_name.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('ascii')
        for func in entry.imports:  # 这个时候import的都是函数了，这里就是以函数为主体，而不是导入表
            address = func.address  # 各个函数的地址
            try:
                function = func.name.decode('ascii')
            except:
                function = str(func.name)  # .decode('ascii')
            else:
                pass
            if dll not in dll_info:
                dll_info.append(dll)
            b = {
                "导入的dll库":  dll,
                "函数所在地址":  str(address),
                "函数名称":  function
            }
            print(b)
            MyUI.import_info += str(b) + "\n"
            b = tuple(b.values())
            import_list.append(b)
    print("\n")
    return import_list


# 判断文字所在的函数
def get_result(pe_name):          #！！！！！！还需要单独调用
    strings_match = input("请输入需要查找的字符：\n")
    alerts = []
    if hasattr(pe_name, 'DIRECTORY_ENTRY_IMPORT'):
        for imp_info in pe_name.DIRECTORY_ENTRY_IMPORT:  # 输出pefile.ImportDescData所在 （pefile.ImportDescData object at 0x0000029B524FD9D0）(导入表中的)
            for imp in imp_info.imports:  # 导入表中的数据（更加具体<pefile.ImportData object at 0x000001B56BCDD0D0>）
                for alert in strings_match:
                    if alert and imp.name != None:  # remove 'null'
                        if imp.name.decode('ascii').startswith(alert):  # 判断是否有字符串
                            alerts.append(imp.name.decode('ascii'))  # 输出所在的函数
                            # 返回字符串所在的函数。

    str_alerts = ",".join(alerts)
    if str_alerts:
        print("%s字符串在以下函数中：%s 被找到\n" % (strings_match, str_alerts))
    else:
        print("没有找到该字符串！\n")
    return alerts


# 资源目录
# 因为pefile的原因，export表的解析基本上为0，所以进行忽略。
def get_resources(pe_name, resources_list):
    res_array = []
    print("资源表信息:")
    try:
        for resource_type in pe_name.DIRECTORY_ENTRY_RESOURCE.entries:  # resourcce_type <pefile.ResourceDirEntryData object at 0x0000020C33473730>
            if resource_type.name is not None:  # name RT_ICON
                name = "%s" % resource_type.name
            else:
                name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
            if name == None:
                name = "%d" % resource_type.struct.Id

            if hasattr(resource_type, 'directory'):
                i = 0
                for resource_id in resource_type.directory.entries:
                    if len(resource_type.directory.entries) > 1:
                        i = i + 1
                        newname = name + '_' + str(i)
                    else:
                        newname = name
                    # newname  RT_ICON
                    for resource_lang in resource_id.directory.entries:  # resource_lang  <pefile.ResourceDirEntryData object at 0x000001E1E9D735E0>
                        data_byte = pe_name.get_data(resource_lang.data.struct.OffsetToData,
                                                     resource_lang.data.struct.Size)[
                                    :50]  # data_byte(还有hex字节流) ‘\x00\x00\x01\x00\x08\x00\xa8\x08\x00\x00\x01\x00’ <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                        #print(data_byte)
                        is_pe = False
                        if magic_check(data_byte)[:8]:
                            is_pe = True
                        lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
                        sublang = pefile.get_sublang_name_for_lang(resource_lang.data.lang,
                                                                   resource_lang.data.sublang)  # lang和sublang只是输出语言，没有太大的作用
                        res_array = {
                            "ICON资源名称":  newname,
                            "文件数据":  str(data_byte),
                            "是否是pe文件":  str(is_pe),
                            "offset":  str(resource_lang.data.struct.OffsetToData),
                            "文件大小":  str(resource_lang.data.struct.Size),
                            "使用语言":  lang,
                            "联合语言":  sublang
                        }
                        print(res_array)
                        MyUI.resource_info += str(res_array) + "\n"
                        res_array = tuple(res_array.values())
                        resources_list.append(res_array)
    except:
        pass
    print("\n")
    return resources_list


def magic_check(data):
    return re.findall(r'4d5a90', str(binascii.b2a_hex(data)))  # 4d5a90 是exe的文件编码


# 重定向表
# 输出重定向表中的块的信息
def get_relocations(pe_name,relocations_list):  # 重定向  重定位表相对于其他是一块一块的，直到遇到8个字节的0为结束。

    for sec in pe_name.OPTIONAL_HEADER.DATA_DIRECTORY:
        if sec.name == "IMAGE_DIRECTORY_ENTRY_BASERELOC": break
    if not sec or sec.name != "IMAGE_DIRECTORY_ENTRY_BASERELOC":
        return relocations_list
    # 通过IMAGE_DIRECTORY_ENTRY_BASERELOC这个节区进行判断，判断是否重定向。根据这个节的数目，判断重定向的次数。
    relocations_list.append(str(sec.VirtualAddress))  # 真正的RVA=virtualAddress+具体项的低12位
    relocations_list.append(str(sec.Size))   # 具体项的个数 = (size - 8)/ 2
    re_direct = pe_name.parse_relocations_directory(sec.VirtualAddress, sec.Size)  # BaseRelocationData地址
    relocations_list.append(str(len(re_direct)))
    i = 0
    my_items = {}
    for items in re_direct:  # re_direct  <pefile.BaseRelocationData object at 0x000002C51AA3A2B0>
        i = i + 1
        for item in items.entries:
            my_items.update({"重定向块_" + str(i) + "的入口地址": len(items.entries)})
    relocations_list.append(str(my_items))

    print("重定向表信息:")
    str_array = ["虚拟地址：", "节区大小：", "重定向次数：",""]
    for i in range(len(relocations_list)):
        print(str_array[i] + relocations_list[i])

    for i in range(len(relocations_list)):
        MyUI.relocate_info += str_array[i] + relocations_list[i] + "\n"

    print("\n")
    return relocations_list


# 调试目录
def get_debug(pe_name):
    DEBUG_TYPE = {
        "IMAGE_DEBUG_TYPE_UNKNOWN": 0,  # 忽略未知值
        "IMAGE_DEBUG_TYPE_COFF": 1,  # coff调试信息 coff通用对象文件格式是指可执行文件（映像）和对象文件 32 位编程的格式，该格式可跨平台移植。
        "IMAGE_DEBUG_TYPE_CODEVIEW": 2,  # vs c++调试的信息，存储在exe中
        "IMAGE_DEBUG_TYPE_FPO": 3,  # 辅助调试优化的EXE，告诉调试器如何解释非标准堆栈帧
        "IMAGE_DEBUG_TYPE_MISC": 4,  # DBG文件（音频文件）的位置。
        "IMAGE_DEBUG_TYPE_EXCEPTION": 5,  # .pdata节的副本。
        "IMAGE_DEBUG_TYPE_FIXUP": 6,  # Reserved 保存
        "IMAGE_DEBUG_TYPE_OMAP_TO_SRC": 7,  # 从图像中的RVA到源图像中的RVA的映射。
        "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC": 8,  # 从源图像中的RVA到图像中的RVA的映射。
        "IMAGE_DEBUG_TYPE_BORLAND": 9,  # 为Borland保存。
        "IMAGE_DEBUG_TYPE_REPRO": 16,  # PE确定性或可重复性。
        "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS	": 20,  # 扩展的DLL特征位。
    }
    result = {}
    for d in pe_name.OPTIONAL_HEADER.DATA_DIRECTORY:
        if d.name == "IMAGE_DIRECTORY_ENTRY_DEBUG": break

    if not d or d.name != "IMAGE_DIRECTORY_ENTRY_DEBUG":
        return result

    debug_directories = pe_name.parse_debug_directory(d.VirtualAddress, d.Size)
    for debug_directory in debug_directories:  # debug_directories
        if debug_directory.struct.Type == DEBUG_TYPE["IMAGE_DEBUG_TYPE_CODEVIEW"]:
            result.update({
                "PointerToRawData:": debug_directory.struct.PointerToRawData,  # PE装载器通过本域值找到Section数据在文件中的位置
                "size:": debug_directory.struct.SizeOfData
            })

    print("调试信息:")
    if result:
        MyUI.debug_info += str(result) + "\n"
        print(result)
    else:
        MyUI.debug_info += "！！该PE文件不包含调试信息！！\n"
        print("！！该PE文件不包含调试信息！！")
    print("\n")
    return result


# TLS目录
def get_tls(pe_name, tls_list):  # 线程局部存储  TLS 提供了一种简便的方法来实现线程访问与该线程相关联的全局或静态变量的方法。

    for d in pe_name.OPTIONAL_HEADER.DATA_DIRECTORY:
        if d.name == "IMAGE_DIRECTORY_ENTRY_TLS":
            break
    if not d or d.name != "IMAGE_DIRECTORY_ENTRY_TLS":
        return tls_list

    tls_directories = pe_name.parse_directory_tls(d.VirtualAddress, d.Size).struct

    tls_list.append(str(tls_directories.StartAddressOfRawData))
    # TLS模板的起始地址。模板是用于初始化TLS数据的数据块。每次创建线程时，系统都会复制所有这些数据，因此一定不要损坏它。请注意，该地址不是RVA。它是一个地址，.reloc节中应对其进行基本重定位。

    tls_list.append(str(tls_directories.EndAddressOfRawData))
    # TLS的最后一个字节的地址（零填充除外）。与Raw Data Start VA字段一样，这是VA，而不是RVA。

    tls_list.append(str(tls_directories.AddressOfIndex))
    # 接收TLS索引的位置，由加载程序分配。该位置位于普通数据节中，因此可以为程序提供可访问的符号名称。

    tls_list.append(str(tls_directories.AddressOfCallBacks))
    # 指向TLS回调函数数组的指针。该数组以空值结尾，因此，如果不支持回调函数，则此字段指向设置为零的4个字节。。

    tls_list.append(str(tls_directories.SizeOfZeroFill))
    # 模板的大小（以字节为单位），超出了由Raw Data Start VA和Raw Data End VA字段分隔的初始化数据。模板的总大小应与图像文件中TLS数据的总大小相同。零填充是初始化后的非零数据之后的数据量。

    tls_list.append(str(tls_directories.Characteristics))
    # 四个位[23:20]描述对齐信息。可能的值是定义为IMAGE_SCN_ALIGN_ *的值，这些值也用于描述目标文件中节的对齐方式。其他28位保留供将来使用。

    print("TLS表信息:")
    str_array = ["TLS模板的起始地址：", "TLS的最后一个字节的地址：", "接收TLS索引的位置：", "指向TLS回调函数数组的指针地址：", "模板的大小(byte)：", "特征值："]
    for i in range(len(tls_list)):
        print(str_array[i] + tls_list[i])

    for i in range(len(tls_list)):
        MyUI.tls_info += str_array[i] + tls_list[i] + "\n"

    print("\n")
    return tls_list


def get(pe_name, tls_list, resources_list,relocations_list,import_list):
    result = {}
    # The directory of imported symbols
    try:
       get_import(pe_name,import_list)
    except:
        result.update({"import": {}})

    try:
        result.update({"debug": get_debug(pe_name)})  # dict
    except:
        result.update({"debug": {}})
    # Thread local storage directory - structure unknown; contains variables that are declared
    try:
        get_tls(pe_name,tls_list)
    except:
        result.update({"tls": {}})
    # The resources, such as dialog boxes, menus, icons and so on, are stored in the data directory
    try:
        get_resources(pe_name, resources_list)
    except:
        result.update({"resources": []})
    # PointerToRelocations, NumberOfRelocations, NumberOfLinenumbers
    try:
        get_relocations(pe_name,relocations_list)
    except:
        result.update({"relocations": {}})

    return result
