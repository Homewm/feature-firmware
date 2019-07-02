#!/usr/bin/python
#encoding:utf-8
######################################################################

#

# Copyright (C) 2015

#

# This program is free software: you can redistribute it and/or modify

# it under the terms of the GNU General Public License as published by

# the Free Software Foundation, either version 3 of the License, or

# (at your option) any later version.

#

# This program is distributed in the hope that it will be useful,

# but WITHOUT ANY WARRANTY; without even the implied warranty of

# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the

# GNU General Public License for more details.

#

# You should have received a copy of the GNU General Public License

# along with this program.  If not, see <http://www.gnu.org/licenses/>.

#

######################################################################

import sys

import os

import re

from subprocess import *

from collections import Counter

######################################################################Functions Def

def Usage():

	print "###############################################################"

	print "Find powerpc binary-blob firmware's rebase address!"

	# Please don't remove this. At least respect my rights!

	print "Auther: Lambda"

	print "Usage: {} platform <file>".format(sys.argv[0])

	print "  file: the path of firmware file"

	print "Examples: "

	print "  {} powerpc NOE77101.bin".format(sys.argv[0])

	print "Special thanks to: wzjlovecode"

	print "###############################################################"

	sys.exit(0)

###################################################################### Arrow Address

def adjust_arrow(resSet,area_length):
	resList=list(resSet)
	resList.sort()
	#the code below are do the arrow address cluster
	length=len(resList)
	reStart=0
	reEnd=0
	start=0
	end=0
	while not end==length:
		if resList[end]-resList[start]>area_length:
			if end-start>reEnd-reStart:
				reEnd=end
				reStart=start
			start=start+1
		else:
			end=end+1
	return resList[reStart:reEnd]

def get_file_data(filename):
	f = open(filename,"rb")
	filedata = f.read()
	f.close()
	bytedata = bytearray(filedata)
	return bytedata

#arc
def get_arrow_addr_list_arc(filename,area_length):
	bytedata=get_file_data(filename)
	re_str_patt = "\xcf\x70.{4}" # machine code pattern 0xcf 0x70 XX XX XX XX
	reObj = re.compile(re_str_patt)
	res=reObj.findall(bytedata)
	resSet= set()
	for r in res:
		temp=(r[3]<<24)+(r[2]<<16)+(r[5]<<8)+r[4]
		resSet.add(temp)
	return adjust_arrow(resSet,area_length)

#arm
def get_arrow_addr_list_arm(filename,area_length):
	bytedata=get_file_data(filename)
	re_str_patt = ".{2}\x9F\xE5" # machine code pattern  XX XX 0x9F 0xE5
	reObj = re.compile(re_str_patt)
	matchs=reObj.finditer(bytedata)
	resSet= set()
	for match in matchs:
		r=match.group()
		temp=((r[1]&0x0f)<<8)+r[0]+0x08+match.start() # 小端编码，所以 ((r1&0x0f)<<8) + r0
		temp=bytedata[temp]+(bytedata[temp+1]<<8)+(bytedata[temp+2]<<16)+(bytedata[temp+3]<<24) # 解引用
		resSet.add(temp)
	return adjust_arrow(resSet,area_length)

#mips little endian
def get_arrow_addr_list_mips(filename,area_length):
	bytedata=get_file_data(filename)
	resSet= set()
	reObj = re.compile(".{3}[\x24-\x27]")
	matchs=reObj.finditer(bytedata)
	for match in matchs:
		index=match.start()
		test=bytedata[index+2]&0x1f # test respresent target register to save string address
                #searching previous target register operation
                now=index-2
		for i in range(10):
			if now>0:
				if bytedata[now]&0x1f==test and bytedata[now+1]>=0x3c and bytedata[now+1]<=0x3f: # bytedata[now+1] represent the opcode ; 0x3c-0x3f == "0x001111xx" => lui ;
					temp=(bytedata[now-1]<<24)+(bytedata[now-2]<<16)+(bytedata[index+1]<<8)+bytedata[index]
					if bytedata[index+1]>0x80:
						temp=temp-0x10000
					resSet.add(temp)
					break
				else:
					now=now-4
			else:
				break
	return adjust_arrow(resSet,area_length)

#mips big endian
def get_arrow_addr_list_mipsMSB(filename,area_length):
	bytedata=get_file_data(filename)
	resSet= set()
	reObj = re.compile("[\x24-\x27].{3}")
	matchs=reObj.finditer(bytedata)
	for match in matchs:
		index=match.start()
		test=bytedata[index+1]&0x1f

		now=index-3
		for i in range(10):
			if now>0:
				if bytedata[now]&0x1f==test and bytedata[now-1]>=0x3c and bytedata[now-1]<=0x3f:
					temp=(bytedata[now+1]<<24)+(bytedata[now+2]<<16)+(bytedata[index+2]<<8)+bytedata[index+3]
					if bytedata[index+2]>0x80:
						temp=temp-0x10000
					resSet.add(temp)
					break
				else:
					now=now-4
			else:
				break
	return adjust_arrow(resSet,area_length)

def printhex(hexd):
	print hex(hexd)

#powerpc
#利用 lis + addi 指令寻找箭地址
def get_arrow_addr_list_powerpc(filename,area_length):
	bytedata=get_file_data(filename)
	re_str_patt = "[\x3c-\x3f].{7}"
	reObj = re.compile(re_str_patt)
	matchs=reObj.finditer(bytedata) # 定位 lis 指令
	resSet= set()
	totallength=len(bytedata)
	for match in matchs:
		index=match.start()
		test1=bytedata[index]&0x03 # 随机测试字节????
		test2=bytedata[index+1]&0xe0

		now=index+4 # 向后寻找addi指令
		for i in range(10):
			if now<totallength-4:
				if bytedata[now]&0xfc==0x38 and test1==bytedata[now]&0x03 and test2==bytedata[now+1]&0xe0: # 指令的前6位与0x38前6位相同, 加载地址指令的后两位和addi的前两位相同,加载地址指令的第二个字节的前3位与addi的前3位相同
					# if bytedata[index+2]==bytedata[now+2] and bytedata[index+3]==bytedata[now+3]:
					# 	continue
					temp=(bytedata[index+2]<<24)+(bytedata[index+3]<<16)+(bytedata[now+2]<<8)+bytedata[now+3]
					if bytedata[now+2]>0x80:
						temp=temp-0x10000
					# map(printhex, bytedata[index:index+4])
					# map(printhex, bytedata[now:now+4])
					# print hex(temp)
					# print ''
					resSet.add(temp)
					break
				else:
					now=now+4
			else:
				break
	return adjust_arrow(resSet,area_length)


def get_arrow_addr_list_powerpc_bigendian_ysg(filename,area_length):
	bytedata=get_file_data(filename)
	re_str_patt = "[\x3c].{7}"
	reObj = re.compile(re_str_patt)
	matchs=reObj.finditer(bytedata) # 定位 lis 指令
	resSet= set()
	totallength=len(bytedata)
	for match in matchs:
		index=match.start()
		test1=bytedata[index]&0x03 # test1 和 test2 合起来判断 两个指令lis和addi的 src寄存器是否相同
		test2=bytedata[index+1]&0xe0

		now=index+4 # 向后寻找addi指令

		for i in range(10):
			if now<totallength-4:
				if bytedata[now]&0xfc==0x38 and test1==bytedata[now]&0x03 and test2==bytedata[now+1]&0xe0: # 指令的前6位与0x38前6位相同, 加载地址指令的后两位和addi的前两位相同,加载地址指令的第二个字节的前3位与addi的前3位相同
					# if bytedata[index+2]==bytedata[now+2] and bytedata[index+3]==bytedata[now+3]:
					# 	continue
					temp=(bytedata[index+2]<<24)+(bytedata[index+3]<<16)+(bytedata[now+2]<<8)+bytedata[now+3]
					if bytedata[now+2]>0x80:
						temp=temp-0x10000
					# map(printhex, bytedata[index:index+4])
					# map(printhex, bytedata[now:now+4])
					# print hex(temp)
					# print ''
					resSet.add(temp)
					break
				else:
					now=now+4
			else:
				break
	return adjust_arrow(resSet,area_length)

# convert little_endian index to big_endian
def index_bytearray_little_endian_to_big_endian(base_index, index_now ,instruction_length):
	return index_now+instruction_length-(index_now-base_index)

#powerpc big endian
def get_arrow_addr_list_powerpc_little_endian(filename,area_length):
	bytedata=get_file_data(filename)
	re_str_patt = ".{7}[\x3c-\x3f]"
	reObj = re.compile(re_str_patt)
	matchs=reObj.finditer(bytedata)
	resSet= set()
	totallength=len(bytedata)
	for match in matchs:
		index=match.start()
		test1=bytedata[index+7]&0x03
		test2=bytedata[index+6]&0xe0
		now=index+3
		for i in range(10):
			if now<totallength-4:
				if bytedata[now+7]&0xfc==0x38 and test1==bytedata[now+7]&0x03 and test2==bytedata[now+6]&0xe0:
					temp=(bytedata[index+5]<<24)+(bytedata[index+4]<<16)+(bytedata[now+5]<<8)+bytedata[now+4]
					if bytedata[now+5]>0x80:
						temp=temp-0x10000
					resSet.add(temp)
					break
				else:
					now=now+4
			else:
				break
	return adjust_arrow(resSet,area_length)


#sparc
def get_arrow_addr_list_sparc(filename,area_length):
	bytedata=get_file_data(filename)
	re_str_patt = "[\x01-\x3f][\x00-\x3f].{6}"
	reObj = re.compile(re_str_patt)
	resSet= set()
	matchs=reObj.finditer(bytedata)
	totallength=len(bytedata)
	for match in matchs:
		index=match.start()
		if not bytedata[index]&0x1==0x1:
			continue
		test=bytedata[index]&0x3e
		now=index+4
		for i in range(10):
			if now<totallength-4:
				if bytedata[now]&0xc1==0x80 and test==bytedata[now]&0x3e and bytedata[now+1]&0xf8==0x10 and bytedata[now+2]&0x20==0x20:
					temp=(((((bytedata[index+1]&0x3f)<<8)+bytedata[index+2])<<8)+bytedata[index+3]<<10)|(((bytedata[now+2]&0x1f)<<8)+bytedata[now+3])
					resSet.add(temp)
					break
				else:
					now=now+4
			else:
				break
	return adjust_arrow(resSet,area_length)

#superh
def get_arrow_addr_list_superh(filename,area_length):
	bytedata=get_file_data(filename)
	re_str_patt = ".{1}[\xd0-\xdf]" # machine code pattern  XX XX 0x9F 0xE5
	reObj = re.compile(re_str_patt)
	matchs=reObj.finditer(bytedata)
	resSet= set()
	for match in matchs:
		r=match.group()
		temp=(r[0]<<2)+0x02+match.start()
		temp=bytedata[temp]+(bytedata[temp+1]<<8)+(bytedata[temp+2]<<16)+(bytedata[temp+3]<<24)
		resSet.add(temp)
	return adjust_arrow(resSet,area_length)

#X86
def get_arrow_addr_list_x86(filename,area_length):
	bytedata=get_file_data(filename)
	re_str_patt = "\x68.{4}" # machine code pattern 0x3c/0x3d XX XX XX 0x38 XX XX XX
	reObj = re.compile(re_str_patt)
	res=reObj.findall(bytedata)
	resSet= set()
	for r in res:
		temp=r[1]+(r[2]<<8)+(r[3]<<16)+(r[4]<<24)
		resSet.add(temp)
	return adjust_arrow(resSet,area_length)



###################################################################### Target Address
def get_target_addr_list(filename):

	str_addr_list=[item.strip().split(' ')[0] for item in Popen(["strings", "--radix=d",filename], stdout=PIPE).communicate()[0].split('\n')]

	str_addr_list.remove('')

	return map(int,str_addr_list)



def rebase(arrow_addr_set,target_addr_set,offset_lowbound,offset_upbound):

	result={}

	result["hitnum"]=0

	result["hitlist"]=[]

	offset = offset_lowbound

	while offset <= offset_upbound:

		temp_list = map(lambda x : x+offset,target_addr_set)

		count=len(arrow_addr_set & set(temp_list))

		result["hitlist"].append(count)

		if count > result["hitnum"]:

			result["hitnum"] = count

			result["offset"] = offset

		offset+=step

	return result

###################################################################### Main Start Here

if len(sys.argv) ==2 and sys.argv[1]=="-h":

	Usage()

if len(sys.argv) !=3:
	Usage()

platform=sys.argv[1]

inputFile=sys.argv[2]

arrow_function={"arc":get_arrow_addr_list_arc,"arml":get_arrow_addr_list_arm,"mipsl":get_arrow_addr_list_mips, "mipsm":get_arrow_addr_list_mipsMSB,"powerpcl":get_arrow_addr_list_powerpc,"sparc":get_arrow_addr_list_sparc,"superh":get_arrow_addr_list_superh,"x86":get_arrow_addr_list_x86, "powerpcm":get_arrow_addr_list_powerpc_bigendian_ysg}

if platform not in arrow_function:

	print "Error:platform not support!"

	print "only support platform:arc,arml,mipsl,mipsm,powerpcl,sparc,superh,x86,powerpcm"

	Usage()

if not os.path.isfile(inputFile):

	print "Error:file not exist!"

	Usage()



step = 0x400 # memory align,can choose other num

target_addr_list= get_target_addr_list(inputFile) #得到所有字符串偏移offset

target_addr_set = set(target_addr_list)

area_length=target_addr_list[-1]-target_addr_list[0] #string block 大小

arrow_addr_list = arrow_function.get(platform)(inputFile,area_length)

arrow_addr_set = set(arrow_addr_list)

offset_upbound = ( int(arrow_addr_list[-1]) - int(target_addr_list[0]) + step )/step*step

offset_lowbound = (int(arrow_addr_list[0]) - int(target_addr_list[-1])-step)/step*step

if offset_lowbound < 0:

	offset_lowbound = 0

result = rebase(arrow_addr_set,target_addr_set,offset_lowbound,offset_upbound)

print "The rebase address of %s is %s" %(inputFile,hex(result["offset"]))

print "-----------------------details----------------------------"

print "Find %d arrow addresss.They are from %s to %s" %(len(arrow_addr_list),hex(arrow_addr_list[0]),hex(arrow_addr_list[-1]))

print "Find %d target addresss.They are from %s to %s" %(len(target_addr_list),hex(target_addr_list[0]),hex(target_addr_list[-1]))

print "Check offset from %s to %s by step=0x%x" %(hex(offset_lowbound),hex(offset_upbound),step)

print "Offset=%s,Hitnum=%d" %(hex(result["offset"]),result["hitnum"])

orded_pairs = sorted(dict(Counter(result["hitlist"])).iteritems(),key=lambda x:x[0],reverse=True)

if len(orded_pairs)<5:
	print "HitNum-AppearNums pairs:"
	for pair in orded_pairs:
 		print str(pair)
else:
	print "HitNum-AppearNums pairs:%s %s %s %s %s" %(str(orded_pairs[0]),str(orded_pairs[1]),str(orded_pairs[2]),str(orded_pairs[3]),str(orded_pairs[4]))

