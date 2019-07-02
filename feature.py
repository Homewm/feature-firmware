# -*- coding:utf-8 -*-
# @Author:zgd
# @time:2019/04
# @File:featurerExtract.py

'''
对下载的保存在固件库中的固件进行特征提取，
通过固件网页信息、固件压缩文件、固件解压文件、固件二进制文件逆向等方面进行固件多维度属性特征提取，
将信息保存到固件属性信息库中
'''

import timeit
import time
import os
import sys
import hashlib
import re
import json
import shutil
import traceback
from firmExtract import firmwareExtract
from mongoConnect import MongoDB_Connect

import logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s: %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    filename='./log.log',
                    filemode='w'
                    )

import warnings
warnings.filterwarnings("ignore")
reload(sys)
sys.setdefaultencoding("utf-8")


root_dir = os.getcwd()  ##获取当前目录路径
configPath = os.path.join(root_dir, "config_zgd.ini") #配置文件的位置

########路径信息############
try:
    import configparser as configparser
except Exception:
    import ConfigParser as configparser

conf = configparser.ConfigParser()
conf.read(configPath)
# conf.read("/home/ubuntu/zgd/firmware_association/config_zgd.ini")
secs = conf.sections()
# options = conf.options("Path")  ##获取path对应的键
# print options
# items = conf.items("Path")  # 获取sections名为path的全部键值对
# print items
srcPath = conf.get("Path", "srcPath")    #获取path下的srcPath对应的值     ##原始固件位置
destPath = conf.get("Path", "destPath")   #获取path下的srcPath对应的值    ##解压固件所在位置
dirTreePath = conf.get("Path", "dirTreePath")   #tree命令获取的图       ##文件的目录结构
dirTreeSavePath = conf.get("Path", "dirTreeSavePath")   #自身提取的json格式的目录树结构    ##目录文件保存的位置
entropyGraphPath = conf.get("Path","entropyGraphPath")  #提取的信息熵保存的位置           ##提取的原始信息熵
code_root_path = os.getcwd()  ##当前代码存放的位置

########MongoDB数据库连接################
# 网页爬取的固件信息库连接
# conn = MongoDB_Connect("webCrawlFirmInfo", "webFirmInfo")
conn_1 = MongoDB_Connect("zgd", "zgd_test")
# conn_1 = MongoDB_Connect("firmwareWebInfo_zgd", "zgd_total_dataset")  #有待更新数据名称
webFirmInfo_collection = conn_1.get_collections()


# 固件属性数据库的构建
# 数据库名firmAttrExtract_zgd，数据集名称firmAttributes
conn_2 = MongoDB_Connect("firmAttrExtract_zgd","firmAttributes")
firmAttributes = conn_2.get_collections()

##################################


#################获取固件的一些属性值###################
##文件名
def get_filename(filename):
    '''
    filename是包含文件名的固件位置，这里只是想得到固件的文件名
    需要进一步完善，因为压缩包名和固件的名称还不太一致，需要继续处理
    :param filename:  含路径的位置
    :return:     固件名
    '''
    fileName = ""
    try:
        fileName = os.path.split(filename)[-1].strip()
    except Exception as e:
        print "get_filename Error, ", filename
        print e.message
        logging.exception(" ")
    return fileName


##获取的是路径的创建时间或者拷贝的时间  暂时未被利用
def get_file_creat_time(filename):
    '''
    求文件的创建时间，这个不是固件的创建时间，而是文件拷贝过来的时间，因此这个暂时未用。
    :param filename:
    :return:
    '''
    filePath = unicode(filename, 'utf8')
    file_create_time = os.path.getctime(filePath) ##创建时间
    file_mode_time = os.path.getmtime(filePath)  ##修改时间
    # print file_create_time, file_mode_time
    file_create_time = time.localtime(file_create_time)
    file_create_time = time.strftime("%Y-%m-%d %H:%M:%S", file_create_time)
    file_mode_time = time.localtime(file_mode_time)
    file_mode_time = time.strftime("%Y-%m-%d %H:%M:%S", file_mode_time)
    # print file_create_time
    return file_create_time


##文件md5
def get_file_MD5_1(filename):
    '''
    三种方法求文件md5。验证了三种求法的结果是一样的。
    1.md5sum filename
    2.binwalk -v filename （-v或--verbose）
    3.读文件后以MD5求值，hashlib.md5()进行求解
    这里使用了第三种方法。
    '''
    md5obj = hashlib.md5()
    with open(filename) as f:
        md5obj.update(f.read())
        hashValue = md5obj.hexdigest()
        # print hashValue
        f.close()
    # print hashValue
    return hashValue

def get_file_MD5(filename):
    '''
    直接使用md5sum命令直接获取md5的值更为精确
    :param filename: 含路径的文件名
    :return:   MD5值
    '''
    file_MD5 = ""
    if filename:
        try:
            cmd = 'md5sum {0}'.format(filename)
            info = os.popen(cmd).read()
            file_MD5 = info.strip().split(" ")[0].strip()
        except Exception,e:
            file_MD5 = ""
            logging.exception(" ")
    else:
        print "get_file_MD5 Error, ", filename
    return file_MD5


##压缩包大小
def get_file_size(filename):
    '''
    获取为解压固件压缩包的大小，单位为M
    :param filename: 文件名（含路径）
    :return:  固件压缩文件的大小
    '''
    # 以MB为单位
    file_size = 0
    if filename:
        file_size = os.path.getsize(filename)
        file_size = file_size / float(1024 * 1024)
        file_size = round(file_size, 2)
        # print file_size
    file_size = str(file_size) + "M"
    return file_size

##解压后目录大小
def get_dir_size1(firmExtractPath):
    '''
    通过对每个文件的大小进行相加统计得到的目录的大小，这个值偏小
    :param firmExtractPath:
    :return:
    '''
    dirSize = 0L
    if firmExtractPath:
        for root, dirs, files in os.walk(firmExtractPath):
            dirSize += sum([os.path.getsize(os.path.join(root, name)) for name in files])
        dirSize = dirSize / float(1024 * 1024)
        dirSize = round(dirSize, 2)
        # print dirSize
    # dirSize = str(dirSize) + "M"
    return dirSize


##解压后目录大小，使用du命令获取
def get_dir_size(firmExtractPath):
    '''
    通过du命令获取固件解压后的文件夹的大小，单位为M
    :param firmExtractPath:  固件解压文件位置
    :return:   固件解压包大小
    '''
    dirSize = 0L
    if firmExtractPath:
        try:
            if "_failed" not in firmExtractPath:
                if firmExtractPath:
                    if firmExtractPath.endswith(".extracted"):  ###新添加的
                        cmd = 'du {0} -sh'.format(firmExtractPath)
                        info = os.popen(cmd).readline()
                        dirSize = info.split("M\t")[0]
                        dirSize = float(dirSize)
                        dirSize = round(dirSize, 2) ##保留两位小数
                        # print dirSize
                        return dirSize
            else:
                return 0
        except Exception, e:
            print "get_dir_size Error, ", firmExtractPath
            logging.exception(" ")
            return 0
    dirSize = str(dirSize) + "M"
    return dirSize


##固件的压缩比例
def compression_ratio(filename, file_size, dirSize):
    '''
    根据固件文件未解压大小和解压文件夹的大小进行求比值
    :param filename:  文件名（含路径）
    :param file_size: 固件未解码时的大小
    :param dirSize:  固件解码后的包大小
    :return:  固件文件压缩比例
    '''
    ##考虑到固件存储的时候有的后面加了“M”，有的仅仅只是数字
    if str(file_size).endswith("M"):
        file_size = str(file_size).split("M")[0]
        file_size = float(file_size)
    if str(dirSize).endswith("M"):
        dirSize = str(dirSize).split("M")[0]
        dirSize = float(dirSize)
    try:
        if dirSize != 0 :
            compress_ratio = float(file_size) * 100 / dirSize
            # compress_ratio = round(compress_ratio, 2)
            compress_ratio = "%.4f%%" % compress_ratio
            return compress_ratio
        else:
            return 0
    except Exception,e:
        print e.message
        print "compression_ratio Error, " + filename
        logging.exception(" ")
    return  0


##固件解压后深度
def dir_deepth(firmExtractPath):
    '''
    解压成功的文件求文件的深度，作为一个有效的特征
    :param firmExtractPath:  固件解压文件所在的位置
    :return:    解压文件的深度
    '''
    dirDeepth = 0
    if ("._failed" not in firmExtractPath) and (firmExtractPath != None):
        root_list = []
        for root, subFolders, files in os.walk(firmExtractPath):
            root_list.append(root)
        ###目录绝对层数（最后的目录长度减去解压文件所在位置的长度，加上1是因为原始目录长度包含了解压的第一层目录）
        '''存在一个问题，就是root_list的最后一项不一定是最深层的文件所在的目录，'''
        # dirDeepth = len(root_list[-1].split("/")) - len(firmExtractPath.split("/")) + 1
        num_rootList = [len(i.split("/")) for i in root_list]
        root_list_longest_index =  num_rootList.index(max(num_rootList))
        root_list_longest = root_list[root_list_longest_index]
        # print root_list_longest   #长度最长的目录
        dirDeepth = len(root_list_longest.split("/")) - len(firmExtractPath.split("/")) + 1
        for root, subFolders, files in os.walk(root_list[-1]):
            if files:
                dirDeepth += 1
            else:
                dirDeepth = dirDeepth
        # dirDeepth = len(firmExtractPath.split(os.path.sep))   ##此是求根目录到当前位置的深度
    return dirDeepth


##解压文件包含的目录数量
def dir_num(firmExtractPath):
    '''
    通过find命令求固件解压后所含的目录数量
    :param firmExtractPath:
    :return:
    '''
    dir_Num = 0
    try:
        if firmExtractPath:
            cmd = 'find {0} -type d | wc -l'.format(firmExtractPath)
            ##ls -lR | grep “^d” | wc -l
            info = os.popen(cmd).readline()
            dir_Num = int(info.strip())
            return dir_Num
    except Exception, e:
        print "dir_num Error, ", firmExtractPath
        logging.exception(" ")
        return 0
    return dir_Num


##固件解压后含有的文件数量
def file_num(firmExtractPath):
    '''
    通过find命令求固件解压后所含的文件数量
    :param firmExtractPath:
    :return:
    '''
    file_Num = 0
    try:
        if firmExtractPath:
            cmd = 'find {0} -type f | wc -l'.format(firmExtractPath)
            info = os.popen(cmd).readline()
            file_Num = int(info.strip())
            # print file_Num
            return file_Num
    except Exception,e:
        print "file_num Error, ", firmExtractPath
        logging.exception(" ")
        return 0
    return file_Num


##获取解压固件目录树
###这个是画出树结构，只是便于观察，但是实际使用价值不大，对树的利用需要进一步分析    ##TODO
def get_dir_tree(firmExtractPath, file_name):
    '''
    通过tree命令获取目录树的结构
    :param firmExtractPath:  固件解压文件所在路径
    :param file_name:   固件名（不含路径）
    :return:    固件目录树保存的位置
    '''
    firmExtractTreePath = ""
    # ##目录树结构输出
    if "._failed" not in firmExtractPath.split("/")[-1]:
        ##dirTreePath是一个目录保存的位置
        firmExtractTreePath = os.path.join(dirTreePath, file_name)  ##dirTreePath是一个全局变量
        # print "firmExtractTreePath: ",firmExtractTreePath
        firmExtractTreePath = firmExtractTreePath + "_dirTree.txt"
        # print firmExtractTreePath
        try:
            cmd = 'tree {0} > {1}'.format(firmExtractPath, firmExtractTreePath)  ##输出到指定位置
            os.system(cmd)
        except Exception,e:
            print "get_dir_tree Error, ", firmExtractPath
            print e.message
            logging.exception(" ")
        # return firmExtractPath
    else:
        print "get_dir_tree Error, ", firmExtractPath
        print "Not get the dir tree! May be caused by unsuccessful firmware decompression."
    return firmExtractTreePath


##自定义提取固件解压树结构
def extarct_dir_tree(firmExtractPath):
    '''
    自定义格式提取固件解压文件的目录树结构
    :param firmExtractPath:
    :return:
    '''
    tree_list = []
    try:
        content_list = os.listdir(firmExtractPath)
        if content_list:
            for c in content_list:
                c_path = os.path.join(firmExtractPath, c)
                if os.path.isfile(c_path):
                    dict_file = {}
                    dict_file["type"] = "file"
                    dict_file["name"] = c
                    tree_list.append(dict_file)
                elif os.path.isdir(c_path):
                    dict_dir = {}
                    dict_dir["type"] = "directory"
                    dict_dir["name"] = c
                    dict_dir["contents"] = extarct_dir_tree(c_path)
                    tree_list.append(dict_dir)
                else:
                    pass
    except Exception,e:
        pass
    return tree_list


def addDir_tree(firmExtractPath):
    '''
    将最外层的_.extracted目录加载提取的目录最外面
    保存函数extarct_dir_tree中提取的固件解压文件内的文件内容到此函数，此函数直接调用函数extarct_dir_tree
    :param startpath:
    :return:
    '''
    dir_tree_list = []
    if firmExtractPath:
        content_tree_list = extarct_dir_tree(firmExtractPath)  ##获取顶层目录下的文件或文件夹内容
        dir_name = firmExtractPath.split("/")[-1].strip()
        dict_dirAll = {}
        dict_dirAll["type"] = "directory"
        dict_dirAll["name"] = dir_name
        dict_dirAll["content"] = content_tree_list
        dir_tree_list.append(dict_dirAll)
    else:
        pass
    return dir_tree_list


##保存提取的固件目录树结构
def save_extarct_dir_tree(firmExtractPath, file_name):
    '''
    保存函数addDir_tree中提取的固件解压文件的目录树结构到json文件
    此函数直接调用函数addDir_tree
    :param firmExtractPath:   固件解压文件所在位置
    :param file_name:    文件名（不含路径）
    :return:    提取的固件的解压包的文件目录
    '''
    firmSaveTreePath = ""
    # ##目录树结构输出
    if firmExtractPath:
        if "._failed" not in firmExtractPath.split("/")[-1]:
            ##dirTreeSavePath是一个目录保存的位置
            firmSaveTree_Path = os.path.join(dirTreeSavePath, file_name)  ##dirTreeSavePath是一个全局变量，用来保存提取的目录树
            firmSaveTreePath = firmSaveTree_Path + "_tree.json"
            dir_tree_list = addDir_tree(firmExtractPath)
            if dir_tree_list:
                with open(firmSaveTreePath, 'w') as fp:
                    json.dump(dir_tree_list, fp)
                    fp.close()
            else:
                print "did not get the directory tree information! ", firmExtractPath
        else:
            print "save_extarct_dir_tree Error, ", firmExtractPath
            print "Not save firmware extarct dir tree! May be caused by unsuccessful firmware decompression."
    else:
        print "save_extarct_dir_tree Error, " , firmExtractPath
        print "The path of firmExtractPath in save_extarct_dir_tree function is not correct!!!"
    return firmSaveTreePath


##固件信息熵提取
def file_entropy(filename):
    '''
    通过binwalk -E命令获取固件的信息熵信息，返回的是信息熵的一个列表值
    其中binwalk -E -J是保存信息熵图像内容，但是只能保存到分析的固件的位置，因此需要做一个位置前移
    :param filename:  文件名（含路径）
    :return:   信息熵列表，信息熵保存的位置
    '''
    info_theory_list = []
    entropy_save_file = ""  ##信息熵产生的结果保存位置
    entropy_png_save_path = ""  ##熵谱图保存位置
    if filename:
        try:
            # file_name = filename.split("/")[-1].strip()
            file_name = os.path.basename(filename).strip()

            ##binwalk -E -J是保存信息熵图像内容，-N是不输出熵谱图, -q是执行界面进制输出
            ##其中binwalk -J默认的是输出图片的位置到执行代码的位置，而不是文件所在的位置

            # 提取熵谱数据值
            entropy_save_filename = file_name + "_entropy.txt"
            entropy_save_file = os.path.join(entropyGraphPath, entropy_save_filename)  ###entropyGraphPath是一个全局变量，信息熵保存位置
            # print entropy_save_file
            if not os.path.exists(entropy_save_file):
                os.mknod(entropy_save_file)
            elif os.path.getsize(entropy_save_file) > 0:
                os.remove(entropy_save_file)
                os.mknod(entropy_save_file)
            cmd1 = 'binwalk -E -J {0} -f {1}'.format(filename, entropy_save_file)  ###直接把这个信息给输出到固定位置了
            info_line = os.popen(cmd1).readlines()
            cmd2 = 'binwalk -E -N {0}'.format(filename)
            infos = os.popen(cmd2).read()
            if len(info_line) > 4:
                reg = re.compile(r'(\d+)[\S| ]+\(([\d|\.]+)\)')
                data = reg.findall(infos)
                for item in data:
                    addr = int(item[0])  ###十进制地址
                    entropy = float(item[1])  ###信息熵值
                    info_theory_list.append((addr, entropy))

            #熵谱图位置保存
            cmd = 'binwalk -E -J -q {0}'.format(filename)  #-q不输出产生的结果
            os.system(cmd)
            entropy_png = file_name + '.png'   ##固件信息熵产生的图片
            entropy_png_path = os.path.join(code_root_path, entropy_png)  #code_root_path是本脚本存放的路径位置
            entropy_new_png = file_name + '_entropy.png'
            entropy_png_save_path = os.path.join(entropyGraphPath, entropy_new_png)  ###entropyGraphPath是一个全局变量，信息熵保存位置
            if entropy_png_path:
                ##将产生的信息熵图片移植到指定位置
                if not os.path.exists(entropy_png_save_path):
                    os.mknod(entropy_png_save_path)
                if os.path.getsize(entropy_png_save_path) > 0:
                    os.remove(entropy_png_save_path)
                shutil.copyfile(entropy_png_path, entropy_png_save_path)
                os.remove(entropy_png_path)
            else:
                entropy_png_save_path = ""
                print "未提取到熵谱图：", filename
        except Exception,e:
            print e.message
            print "file_entropy Error, ", filename
            logging.exception(" ")
        # print info_theory
    return info_theory_list, entropy_save_file, entropy_png_save_path


##固件文件系统信息 和 文件系统创建时间
def get_file_system(filename):
    '''
    通过binwalk获取固件的文件系统、固件或文件系统的创建时间
    :param filename:  含路径的文件名
    :return:     文件系统类型、创建时间
    '''
    fileSystem = ""
    creatTime = ""
    try:
        cmd = "binwalk {0}".format(filename)
        info = os.popen(cmd).read()
        try:
            reg1 = re.compile(r'[ ]{2,}(\S+) filesystem') ##文件系统正则匹配
            infos = reg1.findall(info)
            if len(infos) >= 1:
                fileSystem =  infos[0] + " " + "filesystem"
            else:
                print "filesystem unknown, ", filename
        except Exception,e:
            print "get_file_system filesystem Error, ", filename
            print e.message
            logging.exception(" ")

        try:
            reg2 = re.compile(r'created: (\d{4}-\d{2}-\d{2})')  ##文件系统创建时间匹配
            infos2 = reg2.findall(info)
            if len(infos2) == 1:      #考虑只有一个时间的情况
                creatTime = infos2[0]
            elif len(infos2) > 1:
                creatTime = infos2[-1] #考虑多个时间的情况
            else:
                print filename, "fileSystem created time unknown"
        except Exception,e:
            print "get_file_system filesystem_creatTime Error, ", filename
            print e.message
            logging.exception(" ")
    except Exception, e:
        print e.message
        print "get_file_system Error, ", filename
        logging.exception(" ")
    return fileSystem, creatTime


##固件含有的字符串的数量
def get_strings_number(filename):
    '''
    使用strings工具直接获取固件中的字符串的数量
    :param filename:  文件名（含路径）
    :return:     固件字符串数量
    '''
    strNum = 0
    if filename:
        try:
            cmd = 'strings {0} | wc -l'.format(filename)
            strNum = os.popen(cmd).readline().strip()
            strNum = int(strNum)
            # print strNum
        except Exception,e:
            print "get_strings_number Error, ", filename
            logging.exception(" ")
    else:
        print "get_strings_number Error, please input the right file path."
    return strNum


##固件字符串信息
def get_file_string(filename):               #TODO
    '''
    使用strings工具提取固件中的字符串，并限制字符串的长度为6，保存字符串的地址
    :param filename:
    :return:
    '''
    str_addr_list = []
    ###num_str输出字符串所在地址和字符串信息，信息如下：
    '''
    2515844 A_SizeOfUnsignedInt64
    2515868 A_SizeOfUnsignedInt
    2515888 A_SizeOfObjectId
    2515908 A_SizeOfInt
    '''
    # # str_addr_list=[item.strip().split(' ')[0] for item in Popen(["strings", "--radix=d",filename], stdout=PIPE).communicate()[0].split('\n')]
    num_str = Popen(["strings", "--radix=d", filename], stdout=PIPE).communicate()[0].split('\n')  ##输出字符串地址和字符串名
    for item in num_str:
        str_addr = item.strip().split(' ')[0]  ###截取字符地址
        str_addr_list.append(str_addr)
    str_addr_list.remove('')
    map(int, str_addr_list)
    return


##固件头部关于镜像的相关信息
#header, header size, image size, Data Address, Entry Point,image type, compression type, system type
def get_mirror_info(filename):
    '''
    使用binwalk -B或file命令获取固件头部的一些重要信息
    其中信息包括固件头类型、固件头大小、镜像大小、数据段地址、入口点地址、镜像类型、文件加密类型、固件系统类型
    :param filename:
    :return:
    '''
    header = ""
    header_size = 0
    CRC_type = ""
    image_size = 0L
    data_address = 0
    entry_point = 0
    image_type = ""
    compression_type = ""
    system_type = ""
    image_name = ""
    if filename:
        cmd1 = 'binwalk -B {0}'.format(filename)
        info1_lines = os.popen(cmd1).readlines()
        info1 = os.popen(cmd1).read()
        cmd2 = 'file {0}'.format(filename)
        info2_lines = os.popen(cmd2).readlines()
        info2 = os.popen(cmd2).read()
        if len(info1_lines) > 4:
            ##header
            try:
                reg_header = re.compile(r'0x[0-9|A-Z|a-z]+\s+([\S| ]+) header,', re.I)
                header = reg_header.findall(info1)[0]
                header = header + " " + "header"
                # print header
            except Exception,e:
                print "get_mirror_info header Error, ", filename
                print e.message
                logging.exception(" ")

            ##header size
            #单位：byte
            try:
                reg_header_size = re.compile(r'header size: (.*?) bytes,', re.I)
                header_size = reg_header_size.findall(info1)[0]
                if not header_size:
                    reg_header_size = re.compile(r'header size: (.*?),', re.I)
                    header_size = reg_header_size.findall(info1)[0]
                header_size = int(header_size)
                header_size = str(header_size) + "bytes"
                # print header_size
            except Exception,e:
                print "get_mirror_info header_size Error, ", filename
                print e.message
                logging.exception(" ")

            ##CRC type 校验机制是CRC还是CRC32还是其它的，常用的是CRC和CRC32
            if "CRC32" in info1:
                CRC_type= "CRC32"
            elif "CRC" in info1:
                CRC_type = "CRC"
            else:
                CRC_type = ""

            ##image size
            #单位byte
            try:
                reg_image_size = re.compile(r'image size: (.*?) bytes,', re.I)
                image_size = reg_image_size.findall(info1)[0]
                image_size = int(image_size)
                image_size = str(image_size) + "bytes"
                # print image_size
            except Exception,e:
                print "get_mirror_info image_size Error, ", filename
                print e.message
                logging.exception(" ")

            ##data address
            try:
                reg_data_address = re.compile(r'Data Address: (.*?),', re.I)
                data_address = reg_data_address.findall(info1)[0]
                data_address = hex(int(data_address, 16)) ##十六进制字符串转为十进制，十进制转为十六进制数字
                # print data_address
            except Exception,e:
                print "get_mirror_info data_address Error, ", filename
                print e.message
                logging.exception(" ")

            ##entry point
            try:
                reg_entry_point = re.compile(r'Entry Point: (.*?),', re.I)
                entry_point = reg_entry_point.findall(info1)[0]
                entry_point = hex(int(entry_point, 16))
                # print entry_point
            except Exception,e:
                print "get_mirror_info entry_point Error, ", filename
                print e.message
                logging.exception(" ")

            ##image type
            try:
                reg_image_type = re.compile(r'image type: (.*?),', re.I)
                image_type = reg_image_type.findall(info1)[0]
                # print image_type
            except Exception,e:
                print "get_mirror_info image_type Error, ", filename
                print e.message
                logging.exception(" ")

            ##compression type
            try:
                reg_compression_type = re.compile(r'compression type: (.*?),', re.I)
                if reg_compression_type:
                    compression_type = reg_compression_type.findall(info1)[0]
                elif "LZMA".lower() in info1.lower():
                    compression_type = "lzma"
                else:
                    compression_type = ""
                # print compression_type
            except Exception,e:
                print "get_mirror_info compression_type Error, ", filename
                print e.message
                logging.exception(" ")

            ##system type
            if "Linux" in info1:
                system_type = "Linux"
            elif "VxWorks" in info1:
                system_type = "VxWindows"
            elif "BIOS".lower() in info1.lower():
                system_type = "BIOS"
            elif "ZynOS".lower() in info1.lower():
                system_type = "ZynOS"
            elif ("PE" or "WinCE" or "Windows" or "windows") in info1:
                system_type = "WinCE"
            elif "μC/OS-II".lower() in info1.lower():
                system_type = "μC/OS-II"
            elif "nucleus" in info1.lower():
                system_type = "nucleus"
            elif "ambarella" in info1.lower():
                system_type = "ambarella"
            elif "ecos" in info1.lower():
                system_type = "ecos"
            elif "rtems" in info1.lower():
                system_type = "rtems"
            elif "fm11-os" in info1.lower():
                system_type = "fm11-0s"
            else:
                system_type = ""
            # print system_type

            ##image name
            try:
                reg_image_name = re.compile(r'image name: "(.*?)"', re.I)
                image_name = reg_image_name.findall(info1)[0].strip()
                # print image_name
            except Exception,e:
                print "get_mirror_info image_name Error, ", filename
                print e.message
                logging.exception(" ")


        ##file命令
        elif "Load Address" in info2_lines:
            ##header
            try:
                reg_header = re.compile(r'u-boot legacy (.*?),', re.I)
                header = reg_header.findall(info2_lines)[0]
                header = header + " " + "header"
                # print header
            except Exception,e:
                print "get_mirror_info header Error, ", filename
                print e.message
                logging.exception(" ")

            ##header size
            header_size = 64
            try:
                ##除了TRX固件头之外，还有
                # Image header、sercomm header、Realtek firmware header、LANCOM WWAN header、Windows CE memory segment header
                if "Trx" in info1 or "TRX" in info1:
                    header_size = 28
                elif "uImage" in info1:
                    header_size = 64
                #Broadcom 96345 如openwrt固件
                elif "Broadcom" in info1:
                    header_size = 256
            except Exception,e:
                header_size = 64
            header_size =str(header_size) + "bytes"
            # print header_size

            ##CRC type 校验机制是CRC还是CRC32还是其它的，常用的是CRC和CRC32
            if "CRC32" in info1:
                CRC_type = "CRC32"
            elif "CRC" in info1:
                CRC_type = "CRC"
            else:
                CRC_type = ""

            ##image size
            try:
                reg_image_size = re.compile(r'(\d{3,}) bytes,', re.I)
                image_size = reg_image_size.findall(info2)[0]
                image_size = int(image_size)
                image_size = str(image_size) + "bytes"
                # print image_size
            except Exception,e:
                print "get_mirror_info image_size Error, ", filename
                print e.message
                logging.exception(" ")

            ##data address
            try:
                reg_data_address = re.compile(r'Load Address: (.*?),', re.I)
                data_address = reg_data_address.findall(info2)[0]
                data_address = hex(int(data_address, 16))  ##十六进制字符串转为十进制，十进制转为十六进制数字
                # print data_address
            except Exception,e:
                print "get_mirror_info data_address Error, ", filename
                print e.message
                logging.exception(" ")

            ##entry point
            try:
                reg_entry_point = re.compile(r'Entry Point: (.*?),', re.I)
                entry_point = reg_entry_point.findall(info2)[0]
                entry_point = hex(int(entry_point, 16))
                # print entry_point
            except Exception,e:
                print "get_mirror_info entry_point Error, ", filename
                print e.message
                logging.exception(" ")

            ##image type
            if "OS Kernel Image" in info2:
                image_type = "OS Kernel Image"
            elif "Linux Kernel Image" in info2:
                image_type = "Linux Kernel Image"
            else:
                image_type = ""
            # print image_type

            ##compression type
            try:
                reg_compression_type = re.compile(r'\((.*?)\),', re.I)
                if reg_compression_type:
                    compression_type = reg_compression_type.findall(info2)[0]
                elif "LZMA".lower() in info2.lower():
                    compression_type = "lzma"
                else:
                    compression_type = ""
                # print compression_type
            except Exception,e:
                print "get_mirror_info compression_type Error, ", filename
                print e.message
                logging.exception(" ")

            ##system type
            if "Linux" in info2:
                system_type = "Linux"
            elif "VxWorks" in info2:
                system_type = "VxWindows"
            elif "BIOS".lower() in info2.lower():
                system_type = "BIOS"
            elif "ZynOS".lower() in info2.lower():
                system_type = "ZynOS"
            elif ("PE" or "WinCE" or "Windows" or "windows") in info2:
                system_type = "WinCE"
            elif "μC/OS-II".lower() in info2.lower():
                system_type = "μC/OS-II"
            elif "nucleus" in info2.lower():
                system_type = "nucleus"
            elif "ambarella" in info2.lower():
                system_type = "ambarella"
            elif "ecos" in info2.lower():
                system_type = "ecos"
            elif "rtems" in info2.lower():
                system_type = "rtems"
            elif "fm11-os" in info2.lower():
                system_type = "fm11-0s"
            else:
                system_type = ""
            # print system_type

            ##image name
            info_split = info2.split(",")[1]
            if not info_split.startswith("Linux"):
                image_name = info_split.strip()
            # print image_name

        else:
            pass
        # print header, header_size, image_size, data_address, entry_point, image_type, compression_type, system_type, image_name

    return header, header_size, CRC_type, image_size, data_address, entry_point, \
           image_type, compression_type, system_type, image_name


##固件指令集
def get_architecture(filename):
    '''
    获取固件的指令集，使用binwalk或file进行固件指令集的提取。

    根据经验需要从四个角度提取，其中（1）和（2）是最好的，但是（1）分析时间比较长，（2）（3）比较合适一些
    （1）使用binwalk -Y file，此信息比较全面一些，但是执行速度极为慢。
    （2）从固件头进行获取；binwalk -B filename
    （3）使用binwalk -A filename进行获取，此信息不够好。
    （4）使用file命令进行获取，file filename。file命令只能获取到部分固件的。
    '''
    #正则表达式，求固件指令集
    #binwalk -Y 的正则匹配
    reg1 = re.compile(r'0x[0-9|A-Z|a-z]+\s+([\S| ]+) executable code', re.I)

    ##binwalk -B命令的正则匹配
    reg2 = re.compile(r'CPU: (.*?),', re.I)

    ##binwalk -A的正则匹配
    reg3 = re.compile(r'0x[0-9|A-Z|a-z]+\s+([\S| ]+) instructions', re.I)

    ##file命令使用的正则匹配
    reg4 = re.compile(r'Linux/(.*?),', re.I)

    instructionSet = "unknown"
    if filename:
        # import eventlet
        # eventlet.monkey_patch()
        # with eventlet.Timeout(4, False):
        #     cmd1 = 'binwalk -Y {0}'.format(filename)
        #     info1 = os.popen(cmd1).readlines()

        cmd2 = 'binwalk -B {0}'.format(filename)
        # info2 = os.popen(cmd2).readlines()   ##6.5日
        info2 = os.popen(cmd2).read()     ##考虑到提取的相关的信息不在第一行的情况，如tp-link的固件TL-R483Gv2_cn_2.0.0_[20161230-rel43594]_up.bin

        cmd3 = 'binwalk -A {0}'.format(filename)
        info3 = os.popen(cmd3).readlines()

        cmd4 = 'file {0}'.format(filename)
        info4 = os.popen(cmd4).read()

        # #binwalk -Y
        # if len(info1) > 4:
        #     try:
        #         if "Thumb" in info1[3]:
        #             instructionSet = "Thumb"
        #         else:
        #             instructionSet = reg1.findall(info1[3])[0]
        #     except Exception,e:
        #         print 'get_architecture Error1, ', filename

        ##binwalk -B
        if len(info2) > 4:  ##binwalk分析就算没结果也是4行，所以要大于4行内容
            try:
                instructionSet = reg2.findall(info2)[0]
                # print instructionSet
            except Exception, e:
                print 'get_architecture Error2, ', filename
                logging.exception(" ")
        # binwalk -A
        elif len(info3) > 4:
            try:
                if len(info3) == 5:     ##考虑分析后只有5行的情况（也就是函数序言只有一行的情况）
                    instructionSet_1 = reg3.findall(info3[3])[0]
                    instructionSet = instructionSet_1
                if len(info3) > 5:      ##考虑大于5行的情况
                    instructionSet_1 = reg3.findall(info3[3])[0]
                    instructionSet_2 = reg3.findall(info3[4])[0]
                    if instructionSet_1 != instructionSet_2:
                        instructionSet = instructionSet_1
                    elif len(info3) > 6:
                        ##提取出binwalk -A指定出的所有的指令集类型，形成列表
                        instructionSet_list = []
                        for i in range(len(info3)):
                            rt_list = reg3.findall(info3[i]) #info[i]为binwalk处理的返回的数据
                            if rt_list:
                                rt = rt_list[0]
                                instructionSet_list.append(rt)
                        if instructionSet_list:
                            ##求提取的信息的众数
                            instructionSet_list_set = set(instructionSet_list)
                            frequency_dict = {}
                            for i in instructionSet_list_set:
                                frequency_dict[i] = instructionSet_list.count(i)
                            grade_mode = []  #指令集的众数的列表，因为需要考虑多个的可能性
                            for key, value in frequency_dict.items():
                                if value == max(frequency_dict.values()):
                                    grade_mode.append(key)
                            instructionSet = grade_mode[0]
                        # print instructionSet
                    else:
                        instructionSet = instructionSet_1
                # print instructionSet
            except Exception, e:
                print 'get_architecture Error3, ', filename
                logging.exception(" ")
        ##file 命令
        elif "Entry Point" in info4:
            try:
                if "/" in info4:
                    instructionSet = reg4.findall(info4)[0]
                    # print instructionSet
            except Exception,e:
                print 'get_architecture Error4, ', filename
                logging.exception(" ")
        else:
            instructionSet = "unknown"
    else:
        instructionSet = "unknown"
    # print instructionSet
    return instructionSet


##固件加载基址
def get_rebase(filename):    ##TODO
    returnimport


##厂商信息，从文件保存目录上获取
def get_vendor(filename):
    '''
    通常有三种方法获取厂商信息：
    1.从下载的文件保存的路径进行获取
    2.从网页爬取的信息库中提取厂商信息
    3.使用binwalk提取固件信息，进而提取厂商信息
    :param filename:
    :return:
    '''
    vendor = ""
    try:
        fileDir = os.path.split(filename)[0]
        # print fileDir
        vendor = fileDir.split("/")[-1]
        return vendor
    except Exception as e:
        logging.exception(" ")
        print e.message
    return vendor


##类别
def get_class(filename):
    return

##型号
def get_model(filename):
    return

##版本
def get_version(filename):
    return

##发行时间
def get_pulishTime(filename):
    return


##提取爬取写入到数据库的厂商、产品类型、型号、版本号、固件发行时间、固件下载URL
def get_firmware_web_info(webFirmInfo_collection, item):
    '''
    根据存储的固件名和爬取的网页信息的数据库中的名称进行匹配，提取厂商、产品类型、型号、版本号、固件发行时间、URL等信息
    :param webFirmInfo_collection:   #固件网页信息数据集
    :param item:    #含路径的的某个固件名
    :return:    #厂商、产品类型、型号、版本号、固件发行时间、URL等信息
    '''
    # file_name = os.path.split(item)[-1].strip()
    file_name = os.path.basename(item).strip()
    result = webFirmInfo_collection.find({
        'firmwareName': file_name
    })
    result = list(result)
    if len(result) > 0:
        if "manufacturer" in result[0]:
            manufacturer = result[0]['manufacturer']
        else:
            manufacturer = ""
        if "productClass" in result[0]:
            productClass = result[0]['productClass']
        else:
            productClass = ""
        if "productModel" in result[0]:
            productModel = result[0]['productModel']
        else:
            productModel = ""
        if "productVersion" in result[0]:
            productVersion = result[0]['productVersion']
        else:
            productVersion = ""
        if "publishTime" in result[0]:
            publishTime = result[0]['publishTime']
        else:
            publishTime = ""
        if "url" in result[0]:
            url = result[0]['url']
        else:
            url = ""
    else:
        manufacturer = ""
        productClass = ""
        productModel = ""
        productVersion = ""
        publishTime = ""
        url = ""

    return manufacturer, productClass, productModel, productVersion, publishTime, url


##固件所在位置中的固件列表
def file_path_list(srcPath):
    '''
    获取固件所属厂商、固件所在的路径
    :param srcPath:   固件保所在位置的根位置
    :return:   所有的文件名（含路径）
    '''
    filePath_list  = []
    vendor_list = os.listdir(srcPath)
    for vendor in vendor_list:
        vendor_path = os.path.join(srcPath, vendor)
        filename_list = os.listdir(vendor_path)
        for filename in filename_list:
            filename_path = os.path.join(vendor_path,filename)
            filePath_list.append(filename_path)
    return filePath_list


###############################################################
###############################################################
def main():
    #################################test area
    # item = "/home/ubuntu/disk/hdd_3/zgd/firmwares_deal_zgd/adslr/FYX-AC01K_4.2.0_r1680.bin"

    ###############################use area
    filePath_list = file_path_list(srcPath)  ##文件名（含路径）
    for item in filePath_list:
        print "开始处理该固件：", item
        startTime = timeit.default_timer()

        manufacturer, productClass, productModel, productVersion, publishTime, url = get_firmware_web_info(webFirmInfo_collection, item)
        if manufacturer and productClass and productModel and productVersion:
            file_name = get_filename(item)
            file_MD5 = get_file_MD5(item)
            file_size = get_file_size(item)
            instructionSet = get_architecture(item)

            fileSystem, creatTime = get_file_system(item)

            header, header_size, CRC_type,image_size, data_address, entry_point, image_type,\
            compression_type, system_type, image_name = get_mirror_info(item)

            strings_number = get_strings_number(item)
            info_theory_list, entropy_save_file, entropy_png_save_path = file_entropy(item)

            ##文件创建时间，暂时不可用
            file_CreatTime = get_file_creat_time(item)

            # ###########解压之后的分析
            firmExtract_path = firmwareExtract(item, destPath)
            # dirSize = get_dir_size1(firmExtract_path)
            dirSize = get_dir_size(firmExtract_path)
            compress_ratio = compression_ratio(item, file_size, dirSize)
            dir_Num = dir_num(firmExtract_path)
            file_Num = file_num(firmExtract_path)
            dirDeepth = dir_deepth(firmExtract_path)
            treeSavePath = get_dir_tree(firmExtract_path, file_name)
            firmSaveTreePath = save_extarct_dir_tree(firmExtract_path, file_name)


            #将属性值插入数据库
            firmAttributes.update(
                {"firmwareName":file_name}, {'$setOnInsert':{
                    "firmwareName":file_name,
                    "manufacturer":manufacturer,
                    "productClass":productClass,
                    "productModel":productModel,
                    "productVersion":productVersion,
                    "publishTime":publishTime,
                    "url":url,
                    "filePath":item,
                    "MD5":file_MD5,
                    "size":file_size,
                    "instructionSet": instructionSet,
                    "stringsNumber":strings_number,
                    "fileSystem":fileSystem,
                    "creatTime":creatTime,
                    "firmwareHeader":header,
                    "headerSize":header_size,
                    "CRC_type":CRC_type,
                    "imageSize":image_size,
                    "dataAddress":data_address,
                    "entryPoint":entry_point,
                    "imageType":image_type,
                    "compressionType":compression_type,
                    "systemType":system_type,
                    "imageName":image_name,
                    "entropy_list":info_theory_list,
                    "entropyInfoSavePath":entropy_save_file,
                    "entropy_png_SavePath":entropy_png_save_path,
                    "firmExtractPath":firmExtract_path,
                    "dirSize":dirSize,
                    "compressionRatio":compress_ratio,
                    "dirNumber":dir_Num,
                    "fileNumber":file_Num,
                    "dirDeepth":dirDeepth,
                    "treeSavePath":treeSavePath,
                    "firmSaveTreePath":firmSaveTreePath,
                    }}, True)
            print "该固件信息提取成功"
        else:
            print "注意：该固件爬取信息库信息不全"

        endTime = timeit.default_timer()
        time_spend =  str(endTime - startTime)
        print "固件处理的时间消耗：", time_spend
        print "\n"

    return



if __name__ == "__main__":
    start_time = timeit.default_timer()

    ###执行程序
    main()

    end_time = timeit.default_timer()
    time_use = str(end_time - start_time)

    timeArray_1 = time.localtime(start_time)
    format_startTime = time.strftime("%Y-%m-%d %H:%M:%S", timeArray_1)

    timeArray_2 = time.localtime(end_time)
    format_endTime = time.strftime("%Y-%m-%d %H:%M:%S", timeArray_2)

    print "===================================="
    print "程序运行开始时间点：", format_startTime
    print "程序运行结束时间点：", format_endTime
    print "程序运行时间：", time_use
    print "====================================="
