import re
import time
import sys
from MemObject import *
from OperandInfo import OperandInfo
from TraceFormat import TraceFormat
from TraceStack import TraceStack

pro_name = sys.argv[1]

def getFormat(line_num,line):
    pattern =r'<R@([a-z]*)\[([0-9a-z]*)\]\[4\]'
    max_base = 0
    max_reg = ''
    memregs = re.findall(pattern,line)
    if memregs:
        if line.find('movs') > 0 or line.find('rep movs') > 0:
            max_base = int(memregs[-1][1],16)
            max_reg = memregs[-1][0]
        else:
            for i in memregs:
                if int(i[1],16)>max_base:
                    max_base = int(i[1],16)
                    max_reg = i[0]
    line = line.strip('\n').split('\t')
    ins_addr = line[0]
    ins = line[1].replace('%al','%eax')
    num_op = int(line[2][7])
    operand_list = []
    for i in range(num_op):
        operand = OperandInfo(line[3+i*2][0], line[3+i*2][2:].split('[')[0], line[3+i*2][2:].split('[')[1].split(']')[0], line[3+i*2].split('(')[1].split(')')[0],line[4+i*2])
        operand_list.append(operand)
        i = i + 1
    trace = TraceFormat(line_num,ins_addr,ins,num_op,operand_list,max_base,max_reg)
    return trace

def translate(pro_name, lib_offset=0):
    call_dict = {}
    pattern =r'([0-9a-z]*) <(.*)>:'
    if  lib_offset > 0:
        with open('lt-'+pro_name+'-objdump.txt','r') as f:
            for l in f:
                tmp = re.findall(pattern,l)
                if len(tmp) > 0:
                    call_dict[tmp[0][0]] = tmp[0][1]
        with open(pro_name+'-objdump.txt','r') as file:
            for line in file:
                tmp = re.findall(pattern,line)
                if len(tmp) > 0:
                    addr = hex(int(tmp[0][0],16) + lib_offset)
                    call_dict[addr[2:]] = tmp[0][1]
    else:
        with open(pro_name+'-objdump.txt','r') as file:
            for line in file:
                tmp = re.findall(pattern,line)
                if len(tmp) > 0:
                    call_dict[tmp[0][0]] = tmp[0][1]
    return call_dict

def get_heap(pro_name,file_length, lib_offset=0):
    loc_addr = []
    free_addr = []
    with open(pro_name+'-objdump.txt','r') as f:
        for l in f:
            if l.find('<malloc@plt>:')>0 or l.find('<calloc@plt>:')>0:
                loc_addr.append(hex(int(l[:8],16) + lib_offset)[2:])
            if l.find('<free@plt>:')>0:
                free_addr.append(hex(int(l[:8],16) + lib_offset)[2:])
    i = 0
    flag=0
    trace_list = []
    ret_addr = ''
    heap_list = []
    with open(pro_name+'.txt','r') as file:
        for line in file:
            if len(line)>1:
                i = i + 1
                trace=getFormat(i,line)
                trace_list.append(trace)
                if trace.ins[-8:] in loc_addr:
                    ret_addr = trace.operand_list[1].content
                    if trace_list[len(trace_list)-2].ins.find(',(%esp)') > 0:
                        if trace_list[len(trace_list)-3].ins.find(',0x4(%esp)') > 0:
                            size = int(trace_list[len(trace_list)-2].operand_list[0].content,16) * int(trace_list[len(trace_list)-3].operand_list[0].content,16)
                        else:
                            size = int(trace_list[len(trace_list)-2].operand_list[0].content,16)
                    elif trace_list[len(trace_list)-3].ins.find(',(%esp)') > 0:
                        if trace_list[len(trace_list)-4].ins.find(',0x4(%esp)') > 0:
                            size = int(trace_list[len(trace_list)-3].operand_list[0].content,16) * int(trace_list[len(trace_list)-4].operand_list[0].content,16)
                        else:
                            size = int(trace_list[len(trace_list)-3].operand_list[0].content,16)
                    else:
                        continue
                    flag = 1
                if flag == 1:
                    if trace_list[len(trace_list)-2].ins.startswith('ret') and trace_list[len(trace_list)-2].operand_list[0].content == ret_addr:
                        heap_list.append([trace.operand_list[0].content,size,trace.line_num,file_length])
                        flag = 0
                if trace.ins[-8:] in free_addr:
                    for heap in heap_list:
                        if heap[0] == trace_list[len(trace_list)-2].operand_list[0].content:
                            if heap[-1] == file_length:
                                heap[-1] = trace.line_num
                            else:
                                pass #UAF
                            break
    with open(pro_name+'-heap.txt','w') as file:
        for heap in heap_list:
            file.write(str(heap)+'\n')
    return heap_list

def get_stack(pro_name,call_dict):
    i = 0
    j = 0
    flag = 0
    depth = 0
    TmpTree = TraceStack('root')
    TmpTree.begin = 0
    TmpTree.depth = 0
    with open(pro_name+'.txt','r') as file:
        for line in file:
            if len(line)>1:
                i = i + 1
                trace=getFormat(i,line)
                if trace.ins.startswith('call') and trace.ins_addr.startswith('8') and trace.num_op == 2 and (trace.ins[-8:] in call_dict) and call_dict[trace.ins[-8:]] != 'exit@plt':
                    if TmpTree.end is not None:
                        TmpTree = TmpTree.parent
                        depth -= 1
                        TmpTree.depth = depth
                    NewTree = TraceStack(call_dict[trace.ins[-8:]])
                    NewTree.begin = trace.line_num
                    NewTree.ret_address = trace.operand_list[1].content
                    TmpTree.add_child(NewTree)
                    NewTree.parent = TmpTree
                    TmpTree = NewTree
                    depth += 1
                    TmpTree.depth = depth
                    flag = 1
                if trace.ins.startswith('ret'):
                    if (trace.num_op == 1 and TmpTree.ret_address == trace.operand_list[0].content) or (trace.num_op == 2 and TmpTree.ret_address == trace.operand_list[1].content):
                        TmpTree.end = trace.line_num
                        TmpTree = TmpTree.parent
                        depth -= 1
                        TmpTree.depth = depth
                if trace.ins.startswith('sub    $') and trace.ins[-4:] == '%esp' and flag == 1:
                    TmpTree.tmp_list.append(int(trace.operand_list[1].content,16))
                    flag = 0
                if trace.ins.startswith('lea    ') and trace.ins_addr.startswith('8') and trace.ins.find('(%ebp),') > 0:
                    TmpTree.tmp_list.append(int(trace.operand_list[0].addr,16))
                    TmpTree.tmp_list = list(set(TmpTree.tmp_list))
                    TmpTree.tmp_list.sort()
                    TmpTree.obj_list = []
                    for j in range(len(TmpTree.tmp_list)-1):
                        TmpTree.add_obj([hex(TmpTree.tmp_list[j]),TmpTree.tmp_list[j+1]-TmpTree.tmp_list[j]])
    while TmpTree.parent is not None:
        if TmpTree.end is None:
            TmpTree.end = i
        TmpTree = TmpTree.parent
    if TmpTree.end is None:
        TmpTree.end = i  
    return TmpTree

def search_stack(TmpTree,target_lineNum):
    call_stack = []
    call_obj = []
    while(len(TmpTree.child_list)>0):
        found = False
        for ChildTree in TmpTree.child_list:
            if ChildTree.begin <= target_lineNum and ChildTree.end >= target_lineNum:
                call_stack.append([ChildTree.call_address,ChildTree.begin,ChildTree.end])
                TmpTree = ChildTree  
                found = True
                break
        if found == False:
            break
    call_obj = [call_stack,TmpTree.obj_list]
    return call_obj

def get_libcall(pro_name,call_dict,api_list):
    flag = 0
    i = 0
    trace_list = []
    lib_call_list = []
    lib_tmp = []
    lineNum=""
    with open(pro_name+'.txt','r') as file:
        for line in file:
            if len(line)>1:
                i = i + 1
                trace = getFormat(i,line)
                trace_list.append(trace)
            if len(trace_list)<2:
                continue
            if trace_list[len(trace_list)-1].ins_addr.startswith("8") and trace_list[len(trace_list)-2].ins_addr.startswith("b"):
                if len(lib_tmp)!=0:
                    lib_call_list.append([lineNum,addr,inst,lib_tmp])
                    lib_tmp=[]
                    lineNum=""
                flag = 0
            if flag ==1:
                for op in trace.operand_list:
                    if "T1" in op.taintTag:
                        lib_tmp.append(trace)
                        break
                continue
            if trace_list[len(trace_list)-1].ins_addr.startswith("b") and trace_list[len(trace_list)-2].ins_addr.startswith("8"):
                flag = 1
                if trace_list[len(trace_list)-3].ins.startswith('call'):
                    inst = call_dict[trace_list[len(trace_list)-3].ins[-8:]]
                    lineNum = trace_list[len(trace_list)-3].line_num
                    addr = trace_list[len(trace_list)-3].ins_addr
                elif trace_list[len(trace_list)-7].ins.startswith('call'):
                    inst = call_dict[trace_list[len(trace_list)-7].ins[-8:]]
                    lineNum = trace_list[len(trace_list)-7].line_num
                    addr = trace_list[len(trace_list)-7].ins_addr
                else:
                    continue
                api_list.append([lineNum,addr,inst])
                for op in trace.operand_list:
                    if "T1" in op.taintTag:
                        lib_tmp.append(trace)
                        break
                continue

    with open(pro_name+'-api-list.txt','w') as f:
        for api in api_list:
            if '@plt' in api[2]:
                f.write(str(api)+'\n')
        f.write('\n')
    return

def get_syscall(pro_name):
    trace_list = []
    syscall_list = []
    syscall_num = []
    i = 0
    with open('./syscall.txt','r') as f:
        for line in f:
            syscall_list.append([line.split()[1],line.split()[0]])
        syscall_dict = dict(syscall_list)
    with open(pro_name+'.txt','r') as file:
        for line in file:
            if len(line)>1:
                i = i + 1
                trace = getFormat(i,line)
                trace_list.append(trace)
            if trace.ins == 'int    $0x80' and trace_list[len(trace_list)-2].ins.find('eax')>0:
                syscall_num.append([trace.line_num,trace.ins_addr,trace_list[len(trace_list)-2].ins.split('$')[1].split(',')[0]])
    with open(pro_name+'-syscall-list.txt','w+') as l:
        for line,ins,num in syscall_num:
            l.write(str([line,ins,syscall_dict[str(int(num,16))]])+'\n')
    return i

def get_taint_range(trace,loc):
    taint_tmp = set()
    pattern = r", (\d*)\);"
    tmp = re.findall(pattern,trace.operand_list[loc].taintTag)
    for i in tmp:
        taint_tmp.add(int(i))
    taint_tmp = list(taint_tmp)
    taint_tmp.sort()
    tag = bin(int(trace.operand_list[loc].taintTag.split('{')[1].split('(')[0]))
    taint_tmp.append(tag.count('1'))
    return taint_tmp

def group(moas,taint_tmp,num):
    if len(moas)==0:
        return False
    if num == 1:
        if taint_tmp[0] - moas[-1].α[-1][1] == 1:
            moas[-1].α[-1][1] += taint_tmp[-2] - taint_tmp[0] + 1
            moas[-1].offset[1] += taint_tmp[-1]
            return True
        elif taint_tmp[0] > moas[-1].α[-1][1]:
            moas[-1].α.append([taint_tmp[0],taint_tmp[-2]])
            moas[-1].offset[1] += taint_tmp[-1]
            return True
    elif num == 2:
        if taint_tmp[0] - moas[-2].α[-1][1] == 1:
            moas[-2].α[-1][1] += taint_tmp[-2] - taint_tmp[0] + 1
            moas[-2].offset[1] += taint_tmp[-1]
            return True
        elif taint_tmp[0] > moas[-2].α[-1][1]:
            moas[-2].α.append([taint_tmp[0],taint_tmp[-2]])
            moas[-2].offset[1] += taint_tmp[-1]
            return True
    return False

def get_optype(trace):
    loc = 0
    optype = base = ''
    if trace.ins.startswith('mov'):
        if trace.operand_list[1].type == 'M':
            loc = 1
            optype = 'write'
            base = trace.operand_list[1].addr
        elif trace.operand_list[0].type == 'M':
            loc = 0
            optype = 'read'
            base = trace.operand_list[0].addr
    elif trace.ins.startswith('rep movs'):
        if trace.operand_list[3].type == 'M':
            loc = 3
            optype = 'write'
            base = trace.operand_list[3].addr  
        elif trace.operand_list[1].type == 'M':
            loc = 1
            optype = 'read'
            base = trace.operand_list[1].addr
    elif trace.ins.startswith('cmp'):
        if trace.operand_list[1].type == 'M':
            loc = 1
            optype = 'read'
            base = trace.operand_list[1].addr
        elif trace.operand_list[0].type == 'M':
            loc = 0
            optype = 'read'
            base = trace.operand_list[0].addr
    return [loc,optype,base]
    
def get_obj(trace,tr,TmpTree,moas,func_addr,cc_addr,length,loc,optype,base,α,mo_type,heap_list = None):
    offset = -1
    if mo_type == 'static':
        mo = MemObject([tr.operand_list[0].addr],4,mo_type,True)
        offset = int(base,16) - int(tr.operand_list[0].content,16)
    elif mo_type == 'heap':
        for heap in heap_list:
            if tr.max_base == int(heap[0],16):
                if heap[2] <= trace.line_num and heap[3] >= trace.line_num:
                    v = True
                else:
                    v = False
                mo = MemObject([heap[0]],heap[1],mo_type,v)
                offset = int(base,16) - tr.max_base
                break
    elif mo_type == 'stack':
        call_obj = search_stack(TmpTree,tr.line_num)
        for obj in call_obj[1]:
            if obj[0] == tr.operand_list[0].addr:
                for func in call_obj[0]:
                    func_addr.append(func[0])
                if call_obj[0][-1][1] <= trace.line_num and call_obj[0][-1][2] >= trace.line_num:
                    v = True
                else:
                    v = False
                mo = MemObject([func_addr,obj[0]],obj[1],mo_type,v)
                offset = int(base,16) - int(tr.operand_list[0].addr,16)
                break
    if offset >= 0:
        target_obj = search_stack(TmpTree,trace.line_num)
        for cc in target_obj[0]:
            cc_addr.append(cc[0])
        if len(moas) > 0 and cc_addr == moas[-1].cc and optype == moas[-1].optype and mo == moas[-1].mo:
            taint_tmp = get_taint_range(trace,loc)
            if moas[-1].α[-1][1] + 1 == taint_tmp[0]:
                if(group(moas,taint_tmp,1)):
                    return trace.operand_list[loc].addr
        elif len(moas) > 1 and cc_addr == moas[-2].cc and optype == moas[-2].optype and mo == moas[-2].mo and moas[-1].optype != moas[-2].optype:
            taint_tmp = get_taint_range(trace,loc)
            if moas[-1].α[-1][1] + 1 == taint_tmp[0]:
                if(group(moas,taint_tmp,2)):
                    return trace.operand_list[loc].addr
        else:
            moas.append(MemObjectAccess(mo,cc_addr,[trace.ins_addr,trace.ins,trace.line_num],optype,[α],[offset,offset+length]))
            return trace.operand_list[loc].addr
    return

def searchObj(target_trace,trace_list,heap_list,heap_addr,TmpTree,loc,optype,base,moas,MAX):
    func_addr = []
    cc_addr = []
    trace = target_trace
    memregs = [trace.max_reg,trace.max_base]
    taint_tmp = get_taint_range(trace,loc)
    α=[taint_tmp[0],taint_tmp[-2]]
    length = taint_tmp[-1] - 1
    if trace.ins.startswith('mov') and (memregs[1] in heap_addr):
        base_last=get_obj(trace,trace,TmpTree,moas,func_addr,cc_addr,length,loc,optype,base,α,'heap',heap_list)
        return base_last
    if (trace.ins.startswith('mov') or trace.ins.startswith('cmp')) and (memregs[0] == 'ebp' or memregs[0] == 'esp'):
        pattern = r"(\(.*\))"
        string = re.findall(pattern,trace.ins)
        for tmp in string:
            ins = trace.ins.replace(tmp,tmp.replace(',',''))
        if ins.split(',')[1].find('ebp') > 0 or ins.split(',')[1].find('esp') > 0:
            trace.operand_list[0].addr = trace.operand_list[1].addr
        base_last=get_obj(trace,trace,TmpTree,moas,func_addr,cc_addr,length,loc,optype,base,α,'stack')
        return base_last
    for tr in reversed(trace_list):
        if trace.line_num - tr.line_num > MAX:
            return
        if tr.line_num in range(0,trace.line_num):
            if tr.ins.startswith('movs') and trace.ins.startswith('rep movs'):
                if len(moas) > 0 and moas[-1].op[1].startswith('movs'):
                    if(group(moas,taint_tmp,1)):
                        return trace.operand_list[loc].addr
            if tr.num_op<2 or tr.num_op>3:
                continue
            if tr.num_op==3:
                if memregs == [ tr.operand_list[2].addr , int(tr.operand_list[2].content,16) ]:
                    memregs = [ tr.operand_list[1].addr , int(tr.operand_list[1].content,16) ]
            else:
                if memregs == [ tr.operand_list[1].addr , int(tr.operand_list[1].content,16) ]:
                    if tr.ins.startswith('lea    '):
                        memregs = [ tr.max_reg, tr.max_base ]
                        if memregs[0]=='ebp':
                            base_last=get_obj(trace,tr,TmpTree,moas,func_addr,cc_addr,length,loc,optype,base,α,'stack')
                            return base_last
                    elif tr.ins.startswith('mov') and tr.ins_addr.startswith('8') and memregs[0]=='ebp':
                        tr.operand_list[0].addr = tr.operand_list[0].content
                        base_last=get_obj(trace,tr,TmpTree,moas,func_addr,cc_addr,length,loc,optype,base,α,'stack')
                        return base_last
                    elif tr.ins.startswith('mov    $') and tr.operand_list[0].type == 'I':
                        base_last=get_obj(trace,tr,TmpTree,moas,func_addr,cc_addr,length,loc,optype,base,α,'static')
                        return base_last
                    elif tr.ins.startswith('mov    %eax') and tr.ins_addr.startswith('8'):
                        for heap in heap_list:
                            if tr.line_num == heap[2]:
                                base_last=get_obj(trace,tr,TmpTree,moas,func_addr,cc_addr,length,loc,optype,base,α,'heap',heap_list)
                                return base_last              
                    else:
                        if tr.ins.startswith('inc') or tr.ins.startswith('dec'):
                            memregs = [ tr.operand_list[0].addr , int(tr.operand_list[0].content,16) ]
                        else:
                            if tr.operand_list[0].content == tr.operand_list[1].content:
                                memregs = [ tr.operand_list[0].addr , int(tr.operand_list[0].content,16) ]

def main():
    time_start = time.time()
    i = 0
    lib_offset=0
    MAX = 10000
    base_last = ''
    trace_list = []
    api_list = []
    heap_addr = []
    moas = []
    call_dict = translate(pro_name,lib_offset)
    get_libcall(pro_name,call_dict,api_list)
    file_length = get_syscall(pro_name)
    StackTree = get_stack(pro_name,call_dict)
    StackTree.print_node(StackTree,pro_name)
    heap_list = get_heap(pro_name,file_length,lib_offset)
    for heap in heap_list:
        heap_addr.append(int(heap[0],16))
    with open(pro_name+'.txt','r') as file:
        for line in file:
            if len(line) > 1:
                i = i + 1
                trace=getFormat(i,line)
                if line.find('T1') > 0:
                    if trace.ins.startswith('mov'):
                        trace.operand_list[1].taintTag=trace.operand_list[0].taintTag
                    if trace.ins.startswith('rep movs'):
                        trace.operand_list[3].taintTag=trace.operand_list[1].taintTag
                    [loc,optype,base] = get_optype(trace)
                    if base != '' and ('T1' in trace.operand_list[loc].taintTag) and base != base_last:
                        if len(moas) > 0 and [trace.ins_addr,trace.ins] == [moas[-1].op[0],moas[-1].op[1]] and int(trace.operand_list[loc].addr,16) > (int(moas[-1].mo.alloc[-1],16) + moas[-1].offset[-1]):
                            taint_tmp = get_taint_range(trace,loc)
                            if(group(moas,taint_tmp,1)):
                                base_last = base
                        elif len(moas) > 1 and [trace.ins_addr,trace.ins] == [moas[-2].op[0],moas[-2].op[1]] and int(trace.operand_list[loc].addr,16) > (int(moas[-2].mo.alloc[-1],16) + moas[-2].offset[-1]):
                            taint_tmp = get_taint_range(trace,loc)
                            if(group(moas,taint_tmp,2)):
                                base_last = base
                        else:
                            base_last_tmp = searchObj(trace,trace_list,heap_list,heap_addr,StackTree,loc,optype,base,moas,MAX)
                            if base_last_tmp is not None:
                                base_last = base_last_tmp
                trace_list.append(trace)
    with open(pro_name+'-moas.txt','w') as f:
        for moa in moas:
            line_num=moa.op.pop(-1)
            if moa.mo.size < moa.offset[1]:
                print('Buffer Overflow in ',str(line_num),str(moa.op))
                f.write('*')
            if moa.mo.v == False:
                print('Use After Free in ',str(line_num),str(moa.op))
                f.write('*')
            f.write(str(line_num)+'\t'+str([moa.mo.alloc,moa.mo.size,moa.mo.type,moa.mo.v])+'\t'+str(moa.cc)+'\t'+str(moa.op)+'\t'+str(moa.optype)+'\t'+str(moa.α)+'\t'+str(moa.offset)+'\n')
    time_end = time.time()
    print("End...\t\tTime cost: ",time_end-time_start,'s') 

if __name__ =='__main__':
    main()