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

def translate(pro_name):
    call_dict = {}
    pattern =r'([0-9a-z]*) <(.*)>:'
    with open(pro_name+'-objdump.txt','r') as file:
        for line in file:
            tmp = re.findall(pattern,line)
            if len(tmp) > 0:
                call_dict[tmp[0][0]] = tmp[0][1]
    return call_dict

def get_heap(pro_name,file_length):
    loc_addr = []
    free_addr = []
    with open(pro_name+'-objdump.txt','r') as f:
        for l in f:
            if l.find('<malloc@plt>:')>0:
                loc_addr = l[:8]
            if l.find('<free@plt>:')>0:
                free_addr = l[:8]
    i = 0
    trace_list = []
    ret_addr = ''
    heap_list = []
    with open(pro_name+'.txt','r') as file:
        for line in file:
            if len(line)>1:
                i = i + 1
                trace=getFormat(i,line)
                trace_list.append(trace)
                if trace.ins[-8:] == loc_addr:
                    ret_addr = trace.operand_list[1].content
                    size = int(trace_list[len(trace_list)-2].operand_list[0].content,16)
                if trace_list[len(trace_list)-2].ins.startswith('ret') and trace_list[len(trace_list)-2].operand_list[0].content == ret_addr:
                    heap_list.append([trace.operand_list[0].content,size,trace.line_num,file_length])
                if trace.ins[-8:] == free_addr:
                    for heap in heap_list:
                        if heap[0] == trace_list[len(trace_list)-2].operand_list[0].content:
                            if heap[-1] == file_length:
                                heap[-1] = trace.line_num
                            else:
                                pass
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
                if trace.ins.startswith('call') and trace.ins_addr.startswith('8') and trace.ins[-8] == '0' and trace.num_op == 2 and (trace.ins[-8:] in call_dict) and call_dict[trace.ins[-8:]] != 'exit@plt':
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
                if (trace.ins.startswith('lea    ') or trace.ins.startswith('mov    ')) and trace.ins_addr.startswith('8') and trace.ins.find('(%ebp),') > 0:
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

def get_taint(pro_name,call_dict,api_list):
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

def get_taint_range(trace):
    taint_tmp = set()
    pattern = r", (\d*)\);"
    [loc,optype,base] = get_optype(trace)
    tmp = re.findall(pattern,trace.operand_list[loc].taintTag)
    for i in tmp:
        taint_tmp.add(int(i))
    taint_tmp = list(taint_tmp)
    taint_tmp.sort()
    tag = bin(int(trace.operand_list[loc].taintTag.split('{')[1].split('(')[0]))
    taint_tmp.append(tag.count('1'))
    return taint_tmp

def group(mem_obj,taint_tmp,num):
    if len(mem_obj)==0:
        return
    if num == 1:
        if taint_tmp[0] - mem_obj[-1].α[-1][1] == 1:
            mem_obj[-1].α[-1][1] += taint_tmp[-2] - taint_tmp[0] + 1
        elif taint_tmp[0] > mem_obj[-1].α[-1][1]:
            mem_obj[-1].α.append([taint_tmp[0],taint_tmp[-2]])
        mem_obj[-1].offset[1] += taint_tmp[-1]
    elif num == 2:
        if taint_tmp[0] - mem_obj[-2].α[-1][1] == 1:
            mem_obj[-2].α[-1][1] += taint_tmp[-2] - taint_tmp[0] + 1
        elif taint_tmp[0] > mem_obj[-2].α[-1][1]:
            mem_obj[-2].α.append([taint_tmp[0],taint_tmp[-2]])
        mem_obj[-2].offset[1] += taint_tmp[-1]

    return

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
    
def get_obj(trace,tr,TmpTree,mem_obj,func_addr,cc_addr,length,base,α,optype,var_type,heap_list = None):
    offset = -1
    if var_type == 'static':
        var = MemObject(tr.operand_list[0].addr,4,var_type,True)
        offset = int(base,16) - int(tr.operand_list[0].content,16)
    elif var_type == 'heap':
        for heap in heap_list:
            if tr.operand_list[0].content == heap[0]:
                if heap[2] <= trace.line_num and heap[3] >= trace.line_num:
                    v = True
                else:
                    v = False
                var = MemObject(heap[0],heap[1],var_type,v)
                offset = int(base,16) - int(tr.operand_list[0].content,16)
                break    
    elif var_type == 'stack':
        call_obj = search_stack(TmpTree,tr.line_num)
        for obj in call_obj[1]:
            if obj[0] == tr.operand_list[0].addr:
                for func in call_obj[0]:
                    func_addr.append(func[0])
                if call_obj[0][-1][1] <= trace.line_num and call_obj[0][-1][2] >= trace.line_num:
                    v = True
                else:
                    v = False
                var = MemObject([func_addr,obj[0]],obj[1],var_type,v)
                offset = int(base,16) - int(tr.operand_list[0].addr,16)
                break
    if offset >= 0:
        target_obj = search_stack(TmpTree,trace.line_num)
        for cc in target_obj[0]:
            cc_addr.append(cc[0])
        if len(mem_obj) > 0 and cc_addr == mem_obj[-1].cc and optype == mem_obj[-1].optype and var == mem_obj[-1].var:
            taint_tmp = get_taint_range(trace)
            group(mem_obj,taint_tmp,1)
        elif len(mem_obj) > 1 and cc_addr == mem_obj[-2].cc and optype == mem_obj[-2].optype and var == mem_obj[-2].var and mem_obj[-1].optype != mem_obj[-2].optype:
            taint_tmp = get_taint_range(trace)
            group(mem_obj,taint_tmp,2)
        else:
            mem_obj.append(MemObjectAccess(var,cc_addr,[trace.line_num,trace.ins],optype,[α],[offset,offset+length]))
    return

def searchObj(target_trace,trace_list,heap_list,TmpTree,optype,base,mem_obj,ins_list):
    MAX = 10000
    func_addr = []
    cc_addr = []
    trace = target_trace
    memregs = [trace.max_reg,trace.max_base]
    taint_tmp = get_taint_range(trace)
    α=[taint_tmp[0],taint_tmp[-2]]
    length = taint_tmp[-1] - 1
    
    if (trace.ins.startswith('mov') or trace.ins.startswith('cmp')) and (memregs[0] == 'ebp' or memregs[0] == 'esp'):
        pattern = r"(\(.*\))"
        string = re.findall(pattern,trace.ins)
        for tmp in string:
            ins = trace.ins.replace(tmp,tmp.replace(',',''))
        if ins.split(',')[1].find('ebp') > 0 or ins.split(',')[1].find('esp') > 0:
            trace.operand_list[0].addr = trace.operand_list[1].addr
        get_obj(trace,trace,TmpTree,mem_obj,func_addr,cc_addr,length,base,α,optype,'stack')
        ins_list.append([trace.ins_addr,trace.ins])
        return
    for tr in reversed(trace_list):
        if trace.line_num - tr.line_num > MAX:
            return
        if tr.line_num in range(0,trace.line_num):
            if tr.ins.startswith('movs') and trace.ins.startswith('rep movs'):
                group(mem_obj,taint_tmp,1)
                return
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
                            get_obj(trace,tr,TmpTree,mem_obj,func_addr,cc_addr,length,base,α,optype,'stack')
                            ins_list.append([trace.ins_addr,trace.ins])
                            return
                    elif tr.ins.startswith('mov') and tr.ins_addr.startswith('8') and memregs[0]=='ebp':
                        tr.operand_list[0].addr = tr.operand_list[0].content
                        get_obj(trace,tr,TmpTree,mem_obj,func_addr,cc_addr,length,base,α,optype,'stack')
                        ins_list.append([trace.ins_addr,trace.ins])
                        return
                    elif tr.ins.startswith('mov    $') and tr.operand_list[0].type == 'I':
                        get_obj(trace,tr,TmpTree,mem_obj,func_addr,cc_addr,length,base,α,optype,'static')
                        ins_list.append([trace.ins_addr,trace.ins])
                        return
                    elif tr.ins.startswith('mov    %eax') and tr.ins_addr.startswith('8'):
                        for heap in heap_list:
                            if tr.line_num == heap[2]:
                                get_obj(trace,tr,TmpTree,mem_obj,func_addr,cc_addr,length,base,α,optype,'heap',heap_list)
                                ins_list.append([trace.ins_addr,trace.ins])
                                return                
                    else:
                        if tr.ins.startswith('inc') or tr.ins.startswith('dec'):
                            memregs = [ tr.operand_list[0].addr , int(tr.operand_list[0].content,16) ]
                        else:
                            if tr.operand_list[0].content == tr.operand_list[1].content:
                                memregs = [ tr.operand_list[0].addr , int(tr.operand_list[0].content,16) ]

def main():
    time_start = time.time()
    i = 0
    base_last = ''
    trace_list = []
    mem_obj = []
    ins_list = []
    api_list = []
    call_dict = translate(pro_name)
    get_taint(pro_name,call_dict,api_list)
    file_length = get_syscall(pro_name)
    StackTree = get_stack(pro_name,call_dict)
    StackTree.print_node(StackTree,pro_name)
    heap_list = get_heap(pro_name,file_length)
    with open(pro_name+'.txt','r') as file:
        for line in file:
            if len(line) > 1:
                i = i + 1
                trace=getFormat(i,line)
                if line.find('T1') > 0:
                    [loc,optype,base] = get_optype(trace)
                    if base != '' and ('T1' in trace.operand_list[loc].taintTag) and base != base_last:
                        if len(ins_list) > 0 and [trace.ins_addr,trace.ins] == ins_list[-1]:
                            taint_tmp = get_taint_range(trace)
                            group(mem_obj,taint_tmp,1)
                        elif len(ins_list) > 1 and [trace.ins_addr,trace.ins] == ins_list[-2] and len(mem_obj)>1 and trace.ins == mem_obj[-2].op[1]:
                            taint_tmp = get_taint_range(trace)
                            group(mem_obj,taint_tmp,2)
                        else:
                            searchObj(trace,trace_list,heap_list,StackTree,optype,base,mem_obj,ins_list)
                        base_last = base
                trace_list.append(trace)
    with open(pro_name+'-result.txt','w') as f:
        for memobject in mem_obj:
            if memobject.var.size != 5 and memobject.var.size < memobject.offset[1]:
                print('Stack Overflow in ',str(memobject.cc))
            f.write(str([memobject.var.alloc,memobject.var.size,memobject.var.type,memobject.var.v])+'\t'+str(memobject.cc)+'\t'+str(memobject.op)+'\t'+str(memobject.optype)+'\t'+str(memobject.α)+'\t'+str(memobject.offset)+'\n')
    time_end = time.time()
    print("End...\t\tTime cost: ",time_end-time_start,'s') 

if __name__ =='__main__':
    main()