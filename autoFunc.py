#-*- coding:utf-8 -*-


import idc
import idautils
import idaapi

FUNCTIONS_REGISTERS = {"g_log": "rcx", "g_log_error": "rdx"}


def get_string_for_function(call_func_addr, register):
    """
    :param start_addr: The function call address
    :return: the string offset name from the relevant register
    """
    cur_addr = call_func_addr
    str_func = ""
    start_addr = idc.GetFunctionAttr(cur_addr, idc.FUNCATTR_START)
    cur_addr = idc.PrevHead(cur_addr)
    # go through previous opcodes looking for assignment to the register
    while cur_addr >= start_addr:
        if idc.GetMnem(cur_addr)[:3] == "lea" and idc.GetOpnd(cur_addr, 0) == register:
            str_func = idc.GetOpnd(cur_addr, 1)
            return str_func
        cur_addr = idc.PrevHead(cur_addr)
    return str_func


def get_fixed_source_filename(addr):
    """
    :param addr: The address of the source filename string
    :return: The fixed source filename's string
    """
    # replace " " or "/" with "_"
    func_name = idc.GetString(idc.LocByName(addr)).replace("/", "_").replace(" ", "_")
    func_name = "AutoFunc_" + func_name
    # if the debug print is a path, delete the extension
    if func_name.endswith(".c") or func_name.endswith(".h"):
        func_name = func_name[:-2]
    # you can add whatever you want here in order to have your preferred function name
    return func_name


def is_function_name(cur_func_name):
    """
    :param cur_func_name: the current function name
    :return: True/ False - depends if the name is the default name or auto-generated one,
             Names that were chosen by the user will stay the same
    """
    if cur_func_name.startswith("AutoFunc_"):
        return True
    elif cur_func_name.startswith("sub_"):
        return True
    else:
        return False


def search_function():
    curr_addr = MinEA()
    end = MaxEA()
    current_func_name = ""
    while curr_addr < end:
        if curr_addr == idc.BADADDR:
            break
        elif idc.GetMnem(curr_addr) == 'call':
            if idc.GetOpnd(curr_addr, 0) in FUNCTIONS_REGISTERS.keys():
                func_name_addr= get_string_for_function(curr_addr,
                                                        FUNCTIONS_REGISTERS[idc.GetOpnd(curr_addr, 0)].lower())
                if func_name_addr:
                    try:
                        function_start = idc.GetFunctionAttr(curr_addr, idc.FUNCATTR_START)
                        new_filename = get_fixed_source_filename(func_name_addr)
                        current_func_name = idc.GetFunctionName(function_start)
                        if is_function_name(current_func_name):
                            idaapi.set_name(function_start, new_filename, idaapi.SN_FORCE)
                        else:
                            print "Function:", current_func_name, "was not changed"
                    except:
                        print "failed at address " + hex(curr_addr), \
                            "function:", current_func_name, "call:", idc.GetOpnd(curr_addr, 0)
        curr_addr = idc.NextHead(curr_addr)


search_function()