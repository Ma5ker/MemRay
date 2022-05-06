class MemObject(object):
    """description of class"""
    def __init__(self,alloc,size,type,v):
        self.alloc = alloc
        self.size = size
        self.type = type
        self.v = v
    def __eq__(self,other):
        return self.alloc == other.alloc and self.size == other.size and self.type == other.type and self.v == other.v

class MemObjectAccess(object):
    def __init__(self,mo,cc,op,optype,α,offset):
        self.mo = mo
        self.cc = cc
        self.op = op
        self.optype = optype
        self.α = α
        self.offset = offset
