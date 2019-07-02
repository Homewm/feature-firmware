#!/usr/bin/env python
#-*- coding:utf-8 -*-

'''
该脚本用于对目标二进制体系结构进行分类。
步骤：
step1：使用capstone将二进制字节代码反汇编为某种架构或平台的汇编语言;
	   Capstone反汇编框架支持多个架构和多个平台反汇编。
step2：使用".byte"将所有汇编语言拆分为.text段;
step3：根据一些特殊指令来计算某些架构的置信度。
'''

from capstone import *
from numpy import *
import sys

# save all possible instruction mnemonic to list
##将所有可能的指令助记符保存到列表中
##mips大端
MIPS_BIG_LIST=[]
##mips小端
MIPS_LITTLE_LIST=[]
##arm大端
ARM_BIG_LIST=[]
##arm小端
ARM_LITTLE_LIST=[]
##powerpc大端
PPC_BIG_LIST=[]
##powerpc小端
PPC_LITTLE_LIST=[]
##x86架构
X86_LIST=[]

#save filtered instructions to list
##保存已过滤的指令到列表
MIPS_BIG_TEXT=[]
MIPS_LITTLE_TEXT=[]
ARM_BIG_TEXT=[]
ARM_LITTLE_TEXT=[]
PPC_BIG_TEXT=[]
PPC_LITTLE_TEXT=[]
X86_TEXT=[]

CONTINUS_TEXT_UP=400


#locate maximum length of .text section by key instruction rate (such like "lw")
#get_longest_text(MIPS_LITTLE_LIST,10,"lw",6)
def get_longest_text(assam_list,inst_kind,key_inst,key_inst_per):
	start=0
	end=-1
	result_start=0
	result_end=0
	while True:
		try:
			end = assam_list.index(".byte",end+1)  ###end   ???
			if key_inst in assam_list[start:end]:
				per=100*assam_list[start:end].count(key_inst)/len(assam_list[start:end])  #compute key instruction rate in all instructions
			else:
				per=0
			if (end-start) > (result_end-result_start) and len(set(assam_list[start:end]))>inst_kind and per>=key_inst_per:  ###??
				result_start=start
				result_end=end
			start=end+1
		except:
			break
	print("text_section:[%d,%d] continus_text_len:%d inst_kinds:%d"%(result_start*4,result_end*4,(result_end-result_start)*4,len(set(assam_list[result_start:result_end]))))

	if( result_end - result_start < CONTINUS_TEXT_UP ):
		return assam_list[0:0]
	return assam_list[result_start:result_end]



###每个指令占所有代码段的指令的比例
def observe_inst_per(text_list):
	for inst in set(text_list):
		if (100*text_list.count(inst)/len(text_list))>0:
			print("%-10s%d%%"%(inst,100*text_list.count(inst)/len(text_list)))

###？？？
def stumpClassify(dataMatrix,dimen,threshVal,threshIneq): #just classify the data
    retArray = ones((shape(dataMatrix)[0],1))
    if threshIneq == 'lt':
        retArray[dataMatrix[:,dimen] <= threshVal] = -1.0
    else:
        retArray[dataMatrix[:,dimen] > threshVal] = -1.0
    return retArray


def adaClassify(datToClass,classifierArr):
    dataMatrix = mat(datToClass) #do stuff similar to last aggClassEst in adaBoostTrainDS
    m = shape(dataMatrix)[0]
    aggClassEst = mat(zeros((m,1)))
    #total_alpha=0;
	#compute sum of weighted instruction rate
    for i in range(len(classifierArr)):
        classEst = stumpClassify(dataMatrix,classifierArr[i]['dim'],\
                                 classifierArr[i]['thresh'],\
                                 classifierArr[i]['ineq'])  #call stump classify
        aggClassEst += classifierArr[i]['alpha']*classEst
    return sign(aggClassEst)


MIPS_classifierArr=[{'dim': 5, 'ineq': 'lt', 'thresh': 9.1999999999999993, 'alpha': 1.479281753885036},
					{'dim': 1, 'ineq': 'lt', 'thresh': 14.4, 'alpha': 1.1744952138444913},
					{'dim': 0, 'ineq': 'lt', 'thresh': 1.1499999999999999, 'alpha': 1.3642594086501636},
					{'dim': 4, 'ineq': 'lt', 'thresh': 3.5999999999999996, 'alpha': 0.8626870219562903},
					{'dim': 1, 'ineq': 'lt', 'thresh': 10.199999999999999, 'alpha': 0.9584463880746368}]

ARM_classifierArr=[{'dim': 1, 'ineq': 'lt', 'thresh': 2.6000000000000001, 'alpha': 2.454485820159878},
				   {'dim': 0, 'ineq': 'lt', 'thresh': 5.4000000000000004, 'alpha': 2.595551641120444},
				   {'dim': 4, 'ineq': 'lt', 'thresh': 3.3999999999999999, 'alpha': 2.684387915098299},
				   {'dim': 6, 'ineq': 'lt', 'thresh': 0.0, 'alpha': 1.6003074328667952}]

PPC_classifierArr=[{'dim': 0, 'ineq': 'lt', 'thresh': 6, 'alpha': 1},
				   {'dim': 1, 'ineq': 'lt', 'thresh': 3, 'alpha': 1},
				   {'dim': 2, 'ineq': 'lt', 'thresh': 3, 'alpha': 1},
				   {'dim': 3, 'ineq': 'lt', 'thresh': 3, 'alpha': 1},
				   {'dim': 4, 'ineq': 'lt', 'thresh': 3, 'alpha': 1},
				   {'dim': 5, 'ineq': 'lt', 'thresh': 3, 'alpha': 1}]

X86_classifierArr = [{'dim':0, 'ineq':'lt', 'thresh':10, 'alpha': 2},
					 {'dim':1, 'ineq':'lt', 'thresh':1, 'alpha': 1},
					 {'dim': 2, 'ineq': 'lt', 'thresh': 0.5, 'alpha': 1},
					 {'dim':3, 'ineq':'lt', 'thresh':1, 'alpha': 2}]


def judge_X86(text_list):
	stat_insn = ['mov', 'push', 'lea', 'add']
	input_list = [100*text_list.count(stat_insn[i])/len(text_list) for i in range(len(stat_insn))]
	return adaClassify(input_list, X86_classifierArr)


def judge_MIPS(text_list):
	input_list=[]
	if "move" in text_list:
		move_per=100*text_list.count("move")/len(text_list)
	else:
		move_per=0
	if "lw" in text_list:
		lw_per=100*text_list.count("lw")/len(text_list)
	else:
		lw_per=0
	if "jal" in text_list:
		jal_per=100*text_list.count("jal")/len(text_list)
	else:
		jal_per=0
	if "jalr" in text_list:
		jalr_per=100*text_list.count("jalr")/len(text_list)
	else:
		jalr_per=0
	if "lui" in text_list:
		lui_per=100*text_list.count("lui")/len(text_list)
	else:
		lui_per=0
	if "addiu" in text_list:
		addiu_per=100*text_list.count("addiu")/len(text_list)
	else:
		addiu_per=0
	if "sw" in text_list:
		sw_per=100*text_list.count("sw")/len(text_list)
	else:
		sw_per=0
	#if	lw_per>0:
		#print("%d	%d	%d	%d	%d	%d	%d	-1"%(move_per,lw_per,jal_per,jalr_per,lui_per,addiu_per,sw_per))
	input_list.append(move_per)
	input_list.append(lw_per)
	input_list.append(jal_per)
	input_list.append(jalr_per)
	input_list.append(lui_per)
	input_list.append(addiu_per)
	input_list.append(sw_per)
	return adaClassify(input_list,MIPS_classifierArr)
	#return 0

def judge_ARM(text_list):
	input_list=[]
	if "ldr" in text_list:
		ldr_per=100*text_list.count("ldr")/len(text_list)
	else:
		ldr_per=0
	if "add" in text_list:
		add_per=100*text_list.count("add")/len(text_list)
	else:
		add_per=0
	if "mov" in text_list:
		mov_per=100*text_list.count("mov")/len(text_list)
	else:
		mov_per=0
	if "cmp" in text_list:
		cmp_per=100*text_list.count("cmp")/len(text_list)
	else:
		cmp_per=0
	if "bl" in text_list:
		bl_per=100*text_list.count("bl")/len(text_list)
	else:
		bl_per=0
	if "str" in text_list:
		str_per=100*text_list.count("str")/len(text_list)
	else:
		str_per=0
	if "beq" in text_list:
		beq_per=100*text_list.count("beq")/len(text_list)
	else:
		beq_per=0
	#if	ldr_per>0:
		#print("%d	%d	%d	%d	%d	%d	%d	-1"%(ldr_per,add_per,mov_per,cmp_per,bl_per,str_per,beq_per))
	input_list.append(ldr_per)
	input_list.append(add_per)
	input_list.append(mov_per)
	input_list.append(cmp_per)
	input_list.append(bl_per)
	input_list.append(str_per)
	input_list.append(beq_per)
	return adaClassify(input_list,ARM_classifierArr)
	#return 0


def judge_PPC(text_list):
	input_list=[]
	if "lwz" in text_list:
		lwz_per=100*text_list.count("lwz")/len(text_list)
	else:
		lwz_per=0
	if "stw" in text_list:
		stw_per=100*text_list.count("stw")/len(text_list)
	else:
		stw_per=0
	if "li" in text_list:
		li_per=100*text_list.count("li")/len(text_list)
	else:
		li_per=0
	if "mr" in text_list:
		mr_per=100*text_list.count("mr")/len(text_list)
	else:
		mr_per=0
	if "addi" in text_list:
		addi_per=100*text_list.count("addi")/len(text_list)
	else:
		addi_per=0
	if "cmpwi" in text_list:
		cmpwi_per=100*text_list.count("cmpwi")/len(text_list)
	else:
		cmpwi_per=0
	#if	lwz_per>0:
		#print("%d	%d	%d	%d	%d	%d	-1"%(lwz_per,stw_per,li_per,mr_per,addi_per,cmpwi_per))
	input_list.append(lwz_per)
	input_list.append(stw_per)
	input_list.append(li_per)
	input_list.append(mr_per)
	input_list.append(addi_per)
	input_list.append(cmpwi_per)
	return adaClassify(input_list,PPC_classifierArr)
	#return 0


def usage():
	print "--use like this:--"
	print "python {} path_to_binary".format(sys.argv[0])



###############################################################mian start here
if len(sys.argv)<2:
	print(usage())
	exit(0)

file_object = open(sys.argv[1],'rb')
CODE = file_object.read()
file_object.close()
print "file size:%d" % len(CODE)


###############################MIPS-Little
print "dectect MIPS-Little..."
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)   #Cs为capstone中的类
md.syntax = 0
md.skipdata = True
for insn in md.disasm(CODE, 0x1000):
	MIPS_LITTLE_LIST.append(insn.mnemonic)  #insn.mnemonic  such like push, mov ...
MIPS_LITTLE_TEXT=get_longest_text(MIPS_LITTLE_LIST,10,"lw",6)
if judge_MIPS(MIPS_LITTLE_TEXT)==mat(([1])):
	observe_inst_per(MIPS_LITTLE_TEXT)
	print("	result: MIPS-Little")
	sys.exit(1)


################################MIPS-Big
print("dectect MIPS-Big...")
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
md.syntax = 0
md.skipdata = True
for insn in md.disasm(CODE, 0x1000):
	MIPS_BIG_LIST.append(insn.mnemonic)
MIPS_BIG_TEXT=get_longest_text(MIPS_BIG_LIST,10,"lw",6)
if judge_MIPS(MIPS_BIG_TEXT)==mat(([1])):
	observe_inst_per(MIPS_BIG_TEXT)
	print("	result: MIPS-Big")
	sys.exit(2)


print("dectect ARM-Little...")
md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
md.syntax = 0
md.skipdata = True
for insn in md.disasm(CODE, 0x1000):
	ARM_LITTLE_LIST.append(insn.mnemonic)
ARM_LITTLE_TEXT=get_longest_text(ARM_LITTLE_LIST,15,"ldr",5)
if judge_ARM(ARM_LITTLE_TEXT)==mat(([1])):
	observe_inst_per(ARM_LITTLE_TEXT)
	print("	result: ARM-Little")
	sys.exit(3)


print("dectect ARM-Big...")
md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_BIG_ENDIAN)
md.syntax = 0
md.skipdata = True
for insn in md.disasm(CODE, 0x1000):
	ARM_BIG_LIST.append(insn.mnemonic)
ARM_BIG_TEXT=get_longest_text(ARM_BIG_LIST,15,"ldr",5)
if judge_ARM(ARM_BIG_TEXT)==mat(([1])):
	observe_inst_per(ARM_BIG_TEXT)
	print("	result: ARM-Big")
	sys.exit(4)


print("dectect PPC-Big...")
md = Cs(CS_ARCH_PPC, CS_MODE_BIG_ENDIAN)
md.syntax = 0
md.skipdata = True
for insn in md.disasm(CODE, 0x1000):
	PPC_BIG_LIST.append(insn.mnemonic)
PPC_BIG_TEXT=get_longest_text(PPC_BIG_LIST,15,"lwz",4)
if judge_PPC(PPC_BIG_TEXT)==mat(([1])):
	observe_inst_per(PPC_BIG_TEXT)
	print("	result: PowerPC-Big")
	sys.exit(5)


print("dectect PPC-Little...")
md = Cs(CS_ARCH_PPC, CS_MODE_LITTLE_ENDIAN)
md.syntax = 0
md.skipdata = True
for insn in md.disasm(CODE, 0x1000):
	PPC_LITTLE_LIST.append(insn.mnemonic)
PPC_LITTLE_TEXT=get_longest_text(PPC_LITTLE_LIST,15,"lwz",4)
if judge_PPC(PPC_LITTLE_TEXT)==mat(([1])):
	observe_inst_per(PPC_LITTLE_TEXT)
	print("	result: PowerPC-Little")
	sys.exit(6)


print("detect X86...")
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.syntax = 0
md.skipdata = True
# we can not know the aligned address for certain instruction
for insn in md.disasm(CODE, 0x0):
	X86_LIST.append(insn.mnemonic)
X86_TEXT = get_longest_text(X86_LIST, 10, 'mov', 5)
if judge_X86(X86_TEXT) == mat(([1])):
	observe_inst_per(X86_TEXT)
	print(" result: X86")
	sys.exit(7)

sys.exit(0)




