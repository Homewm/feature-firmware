# -*- coding:utf-8 -*-
# @Author:zgd
# @time:2019/6/25
# @File:operateSystem.py

'''
1.将字符串信息写入文件
2.将字符串信息写入数据库 ##暂未做
3.搜索字符串文本中有用的价值，如操作系统，操作系统版本
'''

import magic
import re
import codecs
import os


def is_binary_file_1(ff):
    '''
    根据text文件数据类型判断是否是二进制文件
    :param ff: 文件名（含路径）
    :return: True或False，返回是否是二进制文件
    '''
    TEXT_BOMS = (
        codecs.BOM_UTF16_BE,
        codecs.BOM_UTF16_LE,
        codecs.BOM_UTF32_BE,
        codecs.BOM_UTF32_LE,
        codecs.BOM_UTF8,
    )
    with open(ff, 'rb') as file:
        CHUNKSIZE = 8192
        initial_bytes = file.read(CHUNKSIZE)
        file.close()
    #: BOMs to indicate that a file is a text file even if it contains zero bytes.
    return not any(initial_bytes.startswith(bom) for bom in TEXT_BOMS) and b'\0' in initial_bytes


def is_binwary_file_2(ff):
    '''
    根据magic文件的魔术判断是否是二进制文件
    :param ff: 文件名（含路径）
    :return: True或False，返回是否是二进制文件
    '''
    mime_kw = 'x-executable|x-sharedlib|octet-stream|x-object'  #可执行文件、链接库、动态流、对象
    try:
        magic_mime = magic.from_file(ff, mime=True)
        magic_hit = re.search(mime_kw, magic_mime, re.I)
        if magic_hit:
            return True
        else:
            return False
    except Exception, e:
        return False


def get_files_in_firmExtra(firmExtract_path, firmExtract_files_list):
    '''
    提取某个固件下的所有文件的绝对路径加入一个列表
    :param firmExtract_path: 固件解压文件的绝对路径
    :return: 固件解压文件内部绝对路径列表
    '''
    if os.path.isdir(firmExtract_path):   #排除固件没有解码成功的情况
        firmExtract_dirs = os.listdir(firmExtract_path)
        for d in firmExtract_dirs:
            absolute_path = os.path.join(firmExtract_path, d)
            if os.path.isdir(absolute_path):
               firmExtract_path = absolute_path
               get_files_in_firmExtra(firmExtract_path, firmExtract_files_list)
            elif os.path.isfile(absolute_path):
                firmExtract_files_list.append(absolute_path)
            else:
                continue
    else:
        print "--> .faile <--", firmExtract_path


def get_vendor(vendorPath):
    '''
    获取厂商列表
    :param vendorPath:  存放固件的厂商所在位置
    :return:   厂商列表
    '''
    vendorPath_list = []  #厂商完整路径的列表
    vendor_list = os.listdir(vendorPath)
    for v in vendor_list:
        vendor_path = os.path.join(firmExtract_vendorPath, v) #厂商的完整路径
        vendorPath_list.append(vendor_path)
    return vendorPath_list


def get_firmExtract(vendor_path):
    '''
    固件解码包列表
    :param vendor_path:
    :return:
    '''
    firmExtractPath_list = []
    firmExtract_list = os.listdir(vendor_path)
    for firmExtract in firmExtract_list:
        firmExtract_path = os.path.join(vendor_path, firmExtract)
        if os.path.isdir(firmExtract_path):
            firmExtractPath_list.append(firmExtract_path)
    return firmExtractPath_list

def getStrings(ff, firmStr_savePath, vendor_name, firmExtract_name):
    '''
    提取每个文件的字符串
    :param ff:  固件解压包内部的文件名
    :param firmStr_savePath:  固件提取字符串保存的位置
    :param vendor_name:  厂商名
    :param firmExtract_name: 固件解码包名
    :return:
    '''
    filename = os.path.basename(ff)
    #创建保存的字符串的路径
    str_vendorPath = os.path.join(firmStr_savePath, vendor_name)
    str_dirPath = os.path.join(str_vendorPath, firmExtract_name)
    if not os.path.exists(str_dirPath):
        os.makedirs(str_dirPath)
    else:
        pass
    str_file_path = os.path.join(str_dirPath, filename)
    cmd = "strings {0} > {1}.txt".format(ff, str_file_path)
    os.system(cmd)
    return str_file_path


#替换空格、括号或特殊符号
def path_remake(path):
    '''
    linux下路径存在括号，空格，&等特殊符号，需要替换后使用
    :param path:  路径
    :return:  返回替换后的内容
    '''
    return path.replace(' ', '\ ').replace('(','\(').replace(')','\)').replace('&','\&') ###路径下含有括号、空格、&等，进行转换

##################################################
################################################## start here
firmExtract_sourcePath = "/home/ubuntu/disk/hdd_3/zgd/firmwares_extract_zgd/output/firmwareExtracted"   #所有固件，没按厂商分类
firmExtract_vendorPath = "/home/ubuntu/disk/hdd_3/zgd/firmwares_extract_zgd/output/firmwareExtracted_vendor"  #所有固件，按照厂商进行了分类
# firmExtract_vendorPath = "/home/ubuntu/zgd/ztest/firmware"
firmStr_savePath = "/home/ubuntu/disk/hdd_3/zgd/firmwares_extract_zgd/output/firmwareStrings"  #固件提取的字符串保存的位置
# firmStr_savePath = "/home/ubuntu/zgd/ztest/strings_save"

# test = "/home/ubuntu/disk/hdd_3/zgd/firmwares_extract_zgd/output/test"

if __name__ == "__main__":
    # file_path = "/home/ubuntu/zgd/ztest/_gs418_510txp_v6.6.2.7.stk.extracted/D0"
    # firmExtract_path = "/home/ubuntu/disk/hdd_3/zgd/firmwares_extract_zgd/output/firmwareExtracted_vendor"
    # firmExtract_path = "/home/ubuntu/zgd/ztest/_gs418_510txp_v6.6.2.7.stk.extracted"

    vendorPath_list = get_vendor(firmExtract_vendorPath)  #厂商列表（含路径）
    for vendor_path in vendorPath_list:
        vendor_name = vendor_path.split("/")[-1]
        firmExtractPath_list = get_firmExtract(vendor_path)  #固件解压包列表（含路径）
        for firmExtract in firmExtractPath_list:             #遍历每个固件解压包，对每个固件解压包分析
            try:
                firmExtract = path_remake(firmExtract)
                firmExtract_name = firmExtract.split("/")[-1]
                firmExtract_files_list = []    #某一个固件中的所有文件保存到列表
                get_files_in_firmExtra(firmExtract, firmExtract_files_list)  #获取固件中的所有文件
                # print firmExtract_files_list
                for ff in firmExtract_files_list:
                    ff  = path_remake(ff)
                    if any((is_binary_file_1(ff), is_binwary_file_2(ff))):  #判断文件是否是二进制文件。过滤除压缩包和文本文件
                        str_file_path = getStrings(ff, firmStr_savePath, vendor_name, firmExtract_name)
                        print str_file_path
            except Exception, e:
                pass


    # is_binary =  any((is_binary_file_1(file_path), is_binwary_file_2(file_path)))
    # print any((is_binary_file_1(file_path), is_binwary_file_2(file_path)))
    # print is_binary_file_1(file_path)
    # print is_binwary_file_2(file_path)