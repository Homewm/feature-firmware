#!/usr/bin/python
#-*- encoding:utf-8 -*-

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
	print "file: the path of firmware file"
	print "Examples: "
	print "  {} powerpc NOE77101.bin".format(sys.argv[0])
	print "Special thanks to: wzjlovecode"
	print "###############################################################"
	sys.exit(0)


###################################################################### Arrow Address
###调整指针位置情况
def adjust_arrow(resSet,area_length):
	# print area_length
	resList = list(resSet)
	resList.sort()
	#the code below are do the arrow address cluster
	length=len(resList)
	# print length
	reStart=0
	reEnd=0
	start=0
	end=0
	while not end == length:
		if resList[end] - resList[start] > area_length:
			if end - start > reEnd - reStart:
				reEnd = end
				reStart = start
			start = start + 1
		else:
			end = end + 1
	return resList[reStart:reEnd]


###打开固件二进制文件，读取文件内容并将字符串转化为字节序列
def get_file_data(filename):
	'''
	:param filename:
	:return: bytedata
	'''
	f = open(filename, "rb")
	filedata = f.read()
	f.close()
	bytedata = bytearray(filedata)
	return bytedata


#arc  ------ok
def get_arrow_addr_list_arc(filename,area_length):
	bytedata = get_file_data(filename)
	re_str_patt = "\xCF\x70.{4}" # machine code pattern 0xCF 0x70 XX XX XX XX
	reObj = re.compile(re_str_patt)
	res=reObj.findall(bytedata)
	resSet= set()
	for r in res:
		temp=(r[3]<<24)+(r[2]<<16)+(r[5]<<8)+r[4]
		resSet.add(temp)
	return adjust_arrow(resSet,area_length)


#arm little endian ------ok
##arm架构下的LDR指令对应的编码为0x9F，0xE5
def get_arrow_addr_list_arm(filename, area_length):
	bytedata = get_file_data(filename)
	###如机器码指令3C 01 9F E5  LDR R0, =aModeD
	re_str_patt = ".{2}\x9F\xE5" # machine code pattern  XX XX 0x9F 0xE5
	reObj = re.compile(re_str_patt)
	matchs = reObj.finditer(bytedata)  ##匹配的LDR指令的所有情况
	resSet= set()
	for match in matchs:
		r = match.group()
		##机器码0002346C E4 01 9F  E5
		##对应的机器码为0x32346
		##str_memory_address计算的是字符串内存地址存储到代码段的地址
		# str_memory_address = ((r[1]&0x0f)<<8)+r[0]+0x08+match.start() # 小端编码，所以 ((r1&0x0f)<<8) + r0
		# print hex(match.start())  ##match.start()为机器码所在行的起始地址

		###str_memory_address = str_memory_address1

		str_memory_address = ((match.start() + 0x08) & 0xFFFFFFFC) + (((r[1] & 0x0f) << 8) + r[0])
		# print "str_memory_address, " , str_memory_address
		# print "str_memory_address1, " , hex(str_memory_address1)
		# if str_memory_address == str_memory_address1:
		# 	print "zgd,ok!"
		# print hex(str_memory_address)

		###temp为字符串地址存储位置的机器码，机器码的值实际上就是字符串所在的内存地址
		temp = bytedata[str_memory_address]+(bytedata[str_memory_address+1]<<8)+(bytedata[str_memory_address+2]<<16)+(bytedata[str_memory_address+3]<<24)   # 解引用

		# ##分别输出对应地址位置上的机器码值，如 0xf8 0x31 0x54 0x0；
		# print hex(bytedata[0x1432f8]),hex(bytedata[0x1432f8+1]),hex(bytedata[0x1432f8+2]),hex(bytedata[0x1432f8+3])
		# ##连贯起来的目的是为了输出正确的地址，如0x5431f8
		# print hex(bytedata[0x1432f8]+(bytedata[0x1432f8+1]<<8)+(bytedata[0x1432f8+2]<<16)+(bytedata[0x1432f8+3]<<24))
		resSet.add(temp)
	return adjust_arrow(resSet,area_length)


#arm by zgd but could not use it now
def get_arrow_addr_list_arm_zgd(filename, area_length):
	bytedata = get_file_data(filename)
	offset = 0
	while 0 <= offset < area_length:
		if bytedata[offset + 2] == 0x9F and bytedata[offset + 3] == 0xE5:
			PC = offset + 0x08
			immed_12 = bytedata[offset] + (bytedata[offset + 0x01]<<8)
			address = (PC & 0xFFFFFFFC) + immed_12
			Rd = bytedata[address]+(bytedata[address+1]<<8)+(bytedata[address+2]<<16)+(bytedata[address+3]<<24)
			resSet.add(Rd)
		offset = offset + 0x04
	return adjust_arrow(resSet, area_length)


#Thumb by zgd   ----error
def get_arrow_addr_list_thumb_zgd(filename, area_length):
	bytedata = get_file_data(filename)
	reObj = re.compile(".{1}[\x48-\x4f]")
	matchs = reObj.finditer(bytedata)
	resSet = set()
	for match in matchs:
		r = match.group()
		index = match.start()
		test = bytedata[index+1] & 0xf8
		if test == 0x48:
			str_memory_address = ((match.start() + 0x04)& 0xFFFFFFFC) + (r[0] * 0x04)
			if str_memory_address < area_length:
				temp = bytedata[str_memory_address] + (bytedata[str_memory_address + 1] << 8) + (bytedata[str_memory_address + 2] << 16) + (bytedata[str_memory_address + 3] << 24)
				resSet.add(temp)
	return adjust_arrow(resSet,area_length)



#Thumb by zgd but could not use it now    ----error
def get_arrow_addr_list_Thumb(filename,area_length):
	bytedata = get_file_data(filename)
	offset = 0
	resSet = set()
	while 0 <= offset < area_length+1:
		opcode = bytedata[offset + 1]
		opcode = opcode & 0xf8
		if opcode == 0x48:
			PC = offset + 4
			immed_8 = bytedata[offset]
			str_memory_address = (PC & 0xFFFFFFFC) + (immed_8 * 4)
			if str_memory_address < area_length:
				Rd = bytedata[str_memory_address] + (bytedata[str_memory_address + 1] << 8) + (bytedata[str_memory_address + 2] << 16) + (bytedata[str_memory_address + 3] << 24)
				resSet.add(Rd)
			else:
				pass
		offset = offset + 2
	return adjust_arrow(resSet,area_length)



#mips little endian    ------ok
def get_arrow_addr_list_mips(filename,area_length):
	bytedata=get_file_data(filename)
	resSet= set()
	reObj = re.compile(".{3}[\x24-\x27]")
	matchs=reObj.finditer(bytedata)
	for match in matchs:
		index=match.start()
		test=bytedata[index+2]&0x1f  # test respresent target register to save string address
		# searching previous target register operation
		now=index-2
		for i in range(10):
			if now>0:
				if bytedata[now]&0x1f==test and bytedata[now+1]>=0x3c and bytedata[now+1]<=0x3f: #???
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


#mips big endian   ------ok
def get_arrow_addr_list_mipsMSB(filename,area_length):
	bytedata=get_file_data(filename)
	resSet= set()
	reObj = re.compile("[\x24-\x27].{3}")
	matchs=reObj.finditer(bytedata)
	for match in matchs:
		index=match.start()

		#开始偏移是否是4字节对齐   ####下面两行是新加上去的
		if index%4 != 0:
			continue
		test=bytedata[index+1]&0x1f  # "test" respresent target register to save string address
		source_reg = ((bytedata[index+1]&0xe0)>>5)+((bytedata[index]&0x3)<<3)
		if source_reg>25 :#过滤寄存器   ###这两句是新加上去的
			continue
		#searching previous target register operation
		now=index-3
		for i in range(10):
			if now>0:
				# bytedata[now+1] represent the opcode ; 0x3c-0x3f == "0x001111xx" => lui ;
				if bytedata[now]&0x1f==source_reg and bytedata[now-1]>=0x3c and bytedata[now-1]<=0x3f:
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

# def printhex(hexd):
# 	print hex(hexd)


#powerpc   -----ok
#利用 lis + addi 指令寻找箭地址
def get_arrow_addr_list_powerpc(filename,area_length):
	bytedata = get_file_data(filename)
	re_str_patt = "[\x3c-\x3f].{7}"   ###？为啥是7位？
	reObj = re.compile(re_str_patt)
	matchs = reObj.finditer(bytedata) # 定位 lis 指令
	resSet= set()
	totallength=len(bytedata)
	for match in matchs:
		index = match.start()
		test1 = bytedata[index]&0x03
		test2 = bytedata[index+1]&0xe0

		now=index+4 # 向后寻找addi指令
		for i in range(10):
			if now<totallength-4:
				# 加载地址指令的前6位与0x38前6位相同, 加载地址指令的后两位和addi的前两位相同,加载地址指令的第二个字节的前3位与addi的前3位相同
				if bytedata[now]&0xfc==0x38 and test1==bytedata[now]&0x03 and test2==bytedata[now+1]&0xe0:
					# if bytedata[index+2]==bytedata[now+2] and bytedata[index+3]==bytedata[now+3]:
					# 	continue

					###temp为字符串内存地址存储的位置
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


###powerpc  ----ok
def get_arrow_addr_list_powerpc_big_endian(filename,area_length):
	bytedata=get_file_data(filename)
	re_str_patt = "[\x3c-\x3f].{3}"  ##？？？为何是7？为何是4？为何不是3？
	reObj = re.compile(re_str_patt)
	matchs=reObj.finditer(bytedata) # 定位 lis 指令
	resSet= set()
	totallength=len(bytedata)
	for match in matchs:
		index=match.start()
		test1=bytedata[index]&0x03  #test1 和 test2 合起来判断 两个指令lis和addi的 src寄存器是否相同
		test2=bytedata[index+1]&0xe0
		#下面一行代码更换了
		target_reg = (test1<<3) + (test2>>5)  #计算lis指令的目标寄存器，用来匹配addi指令的源寄存器
		# print index, ':', hex(0x20000+index), ':', map(hex, bytedata[index:index+4])
		'''
		target_reg2 = bytedata[index] & 0x03 + bytedata[index + 1] & 0xe0
		if target_reg == target_reg2:
			print "ok!"
		'''
		now=index+4 # 向后寻找addi指令
		for i in range(10):
			if now<totallength-4:
				addi_source_reg = bytedata[now+1]&0x1f
				if bytedata[now]&0xfc==0x38 and target_reg==addi_source_reg: # 指令的前6位与0x38前6位相同, 加载地址指令的后两位和addi的前两位相同,加载地址指令的第二个字节的前3位与addi的前3位相同
					# if bytedata[index+2]==bytedata[now+2] and bytedata[index+3]==bytedata[now+3]:
					# 	continue
					temp=(bytedata[index+2]<<24)+(bytedata[index+3]<<16)+(bytedata[now+2]<<8)+bytedata[now+3]
					if bytedata[now+2]>0x80:
						temp=temp-0x10000
					# map(printhex, bytedata[index:index+4])
					# map(printhex, bytedata[now:now+4])
					# print 'valid address:',hex(temp)
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



#sparc   ------ok
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



#superh   ------ok
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


#X86  ------ok
def get_arrow_addr_list_x86(filename,area_length):
	bytedata=get_file_data(filename)
	re_str_patt = "\x68.{4}" # machine code pattern 0x3c/0x3d XX XX XX 0x38 XX XX XX    ###zgd: 68 XX XX XX XX
	reObj = re.compile(re_str_patt)
	res=reObj.findall(bytedata)
	resSet= set()
	for r in res:
		temp=r[1]+(r[2]<<8)+(r[3]<<16)+(r[4]<<24)
		resSet.add(temp)
	return adjust_arrow(resSet,area_length)



###################################################################### Target Address
###获取字符串偏移地址（输入固件名，输出字符串偏移地址列表）_by_zgd
def get_target_addr_list(filename):
	'''
	:param filename:
	:return: list of string address
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
	num_str = Popen(["strings", "--radix=d",filename], stdout=PIPE).communicate()[0].split('\n') ##输出字符串地址和字符串名
	for item in num_str:
		str_addr = item.strip().split(' ')[0]   ###截取字符串偏移地址
		str_addr_list.append(str_addr)

	str_addr_list.remove('')
	# print map(int, str_addr_list)
	return map(int,str_addr_list)  ##map的用法就是直接将列表中的内容都按照函数的规则进行处理



def rebase(arrow_addr_set,target_addr_set,offset_lowbound,offset_upbound):
	result={}
	result["hitnum"]=0
	result["hitlist"]=[]
	offset = offset_lowbound

	while offset <= offset_upbound:
		temp_list = map(lambda x : x+offset, target_addr_set) ###相对地址 + 偏移地址
		# print offset
		count=len(arrow_addr_set & set(temp_list)) ###相对地址+偏移地址 == 内存地址 时出现的次数
		result["hitlist"].append(count)
		if count > result["hitnum"]:
			result["hitnum"] = count
			result["offset"] = offset
		offset += step
	return result



###################################################################### Main Start Here

if len(sys.argv) ==2 and sys.argv[1]=="-h":
	Usage()

if len(sys.argv) !=3:
	Usage()

platform=sys.argv[1]  ##平台
inputFile=sys.argv[2]  ##固件文件
arrow_function={"arc":get_arrow_addr_list_arc,
				"arml":get_arrow_addr_list_arm,
				"arm_test":get_arrow_addr_list_arm_zgd,
				"thumb":get_arrow_addr_list_thumb_zgd,
				"thumb_test":get_arrow_addr_list_Thumb,
				"mipsl":get_arrow_addr_list_mips,
				"mipsm":get_arrow_addr_list_mipsMSB,
				"powerpcl":get_arrow_addr_list_powerpc,
				"powerpcm":get_arrow_addr_list_powerpc_big_endian,
				"sparc":get_arrow_addr_list_sparc,
				"superh":get_arrow_addr_list_superh,
				"x86":get_arrow_addr_list_x86,
				}

if platform not in arrow_function:
	print "Error:platform not support!"
	print "only support platform:arc,arml,thumb,mipsl,mipsm,powerpcl,powerpcm,sparc,superh,x86"
	Usage()

if not os.path.isfile(inputFile):
	print "Error:file not exist!"
	Usage()

step = 0x0400  # memory align,can choose other num  ###内存字节对齐，以4字节   #???
target_addr_list = get_target_addr_list(inputFile) #得到所有字符串偏移offset列表值
target_addr_set = set(target_addr_list)

area_length = target_addr_list[-1] - target_addr_list[0] #string block 大小，结束字符串的地址与起始字符串的地址之差
# print area_length

arrow_addr_list = arrow_function.get(platform)(inputFile,area_length)  ###获取字符串的内存地址
arrow_addr_set = set(arrow_addr_list)

# print "last: ",arrow_addr_list[-1]
# print "start:",arrow_addr_list[0]
#
# arrow_addr_list.sort()
# print "last: ",arrow_addr_list[-1]
# print "start:",arrow_addr_list[0]

offset_upbound = ( int(arrow_addr_list[-1]) - int(target_addr_list[0]) + step )/step*step
offset_lowbound = (int(arrow_addr_list[0]) - int(target_addr_list[-1]) - step)/step*step

if offset_lowbound < 0:
	offset_lowbound = 0

result = rebase(arrow_addr_set,target_addr_set,offset_lowbound,offset_upbound)

print "The rebase address of %s is %s" %(inputFile,hex(result["offset"]))
print "-----------------------details----------------------------"
print "Find %d arrow addresss.They are from %s to %s" %(len(arrow_addr_list),hex(arrow_addr_list[0]),hex(arrow_addr_list[-1]))
print "Find %d target addresss.They are from %s to %s" %(len(target_addr_list),hex(target_addr_list[0]),hex(target_addr_list[-1]))
print "Check offset from %s to %s by step=0x%x" %(hex(offset_lowbound),hex(offset_upbound),step)
print "Offset=%s,Hitnum=%d" %(hex(result["offset"]),result["hitnum"])

# print '-------------'
# print result["hitlist"]
# print '*********'
# print Counter(result["hitlist"])
# print '-------------'

##zgd
# print "hitlist",result["hitlist"]

orded_pairs = sorted(dict(Counter(result["hitlist"])).iteritems(),key=lambda x:x[0],reverse=True)   ###偏移配对成功的一个倒序排列
# print orded_pairs

if len(orded_pairs)<5:
	print "HitNum-AppearNums pairs:"
	for pair in orded_pairs:
		print str(pair)
else:
	print "HitNum-AppearNums pairs:%s %s %s %s %s" %(str(orded_pairs[0]),str(orded_pairs[1]),str(orded_pairs[2]),str(orded_pairs[3]),str(orded_pairs[4]))
