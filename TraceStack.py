class TraceStack(object):
    def __init__(self, call_address):
        self.call_address = call_address
        self.ret_address = None
        self.parent = None
        self.begin = None
        self.end = None
        self.depth = None
        self.child_list = []
        self.obj_list = []
        self.tmp_list = []
    def add_child(self,node):
        self.child_list.append(node)
    def add_obj(self,node):
        self.obj_list.append(node)
    def print_node(self, root,pro_name):
        """
        :type root: Node
        :rtype: List[int]
        """
        with open(pro_name+'-stack.txt','w') as file:
            if not root:
                return
            nodeList = [root]
            while nodeList:
                node = nodeList.pop(0)
                if node:
                    file.write('\t'*node.depth+node.call_address+'\t'+str([node.begin,node.end])+'\n')
                    for i in node.child_list[::-1]:
                        nodeList.insert(0, i)
        