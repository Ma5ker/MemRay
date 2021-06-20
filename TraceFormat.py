class TraceFormat(object):
    """
    type origin_info target_info -> OperandList
    """
    def __init__(self,line_num,ins_addr,ins,num_op,operand_list,max_base,max_reg):
        self.line_num = line_num
        self.ins_addr = ins_addr
        self.ins = ins
        self.num_op = num_op
        self.operand_list =  operand_list
        self.max_base = max_base
        self.max_reg = max_reg