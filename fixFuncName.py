#-*- coding:utf-8 -*-

from idaapi import *
import time

symbol_interval = 16 #符号表间隔
load_address = 0x10000 #固件内存加载基址
symbol_table_start = 0x301e64 + load_address   #符号表起始地址
symbol_table_end = 0x3293a4 + load_address #符号表结束地址
ea = symbol_table_start
eaEnd = symbol_table_end

while ea < eaEnd:
    offset = 0   #4个字节为一组数据
    #将函数名指针位置的数据转换为字符串
    MakeStr(Dword(ea - offset), BADADDR)
    #将函数名赋值给变量sName
    sName = GetString(Dword(ea - offset), -1, ASCSTR_C)
    print sName
    if sName:
        #开始修复函数名
        eaFunc = Dword(ea - offset +4)
        MakeName(eaFunc, sName)
        MakeCode(eaFunc)
        MakeFunction(eaFunc, BADADDR)
        ea += symbol_interval

print "ok"