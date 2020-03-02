import re

PRIMITIVE_TYPES = {
    'V' : 'Void',
    'Z' : 'Boolean',
    'B' : 'Byte',
    'S' : 'Short',
    'C' : 'Char',
    'I' : 'Int',
    'J' : 'Long',
    'F' : 'Float',
    'D' : 'Double'
}

class OpCodeParser(object):
    trace = False

    def __init__(self, expression):
        self.expression = re.compile(expression)

    @staticmethod
    def extract_type(line):
        ret_type = 'Null'
        # check if the type is primitive
        if len(line)==1 and line in 'VZBSCIJFD':
            return PRIMITIVE_TYPES[line]
        # check if the type is primitive array
        elif len(line)==2 and line[0] == '[' and line[1] in 'VZBSCIJFD':
            return PRIMITIVE_TYPES[line] + ' Array'
        elif line[0] == 'L':
            return line[1:-1]
        else:
            return 'Invalid Type'

    @staticmethod
    def get_int_value(val):
        ptn = re.compile(r'-?0x\w+?[ts]')

        # handle comments
        if '#' in val:
            val = val.split('#')[0]

        if ptn.match(val):
            return int(val[:-1], 16)
        elif "0x" in val:
            return int(val, 16)

        return int(val)

    @staticmethod
    def extract_mdata(line):
        # print(line)
        ptn = re.compile(r'(?P<cname>.+);->(?P<mname>.+)\((?P<paras>.+)\)')
        m = ptn.search(line)
        if m is None:
            return False
        else:
            paras = m.group('paras').split(';')
            if(paras[-1] == ''):
                paras.pop()

            return (m.group('cname'),m.group('mname'), paras)

class op_Invoke(OpCodeParser):
    
    def __init__(self):
        OpCodeParser.__init__(self, r'invoke-(?P<family>[a-z]+) \{(?P<reg>.*)\},\s*(?P<m_name>.+\))(?P<type>.+)')
        reg = []
        obj_reg = {}
        m_name = 'None'
        self.m_type = 'None'

    def parse(self,line):
        self.opcode = 'invoke'
        self.reg = []
        self.obj_reg = {}
        self.m_name = 'None'
        self.m_type = 'None'
        m = self.expression.search(line)
        if m is None:
            return False

        registers = m.group('reg').replace(" ", "").split(',') # remove white space and create a list
        obj_register = None

        mdata = self.extract_mdata(m.group('m_name'))
        self.m_name = mdata[1]
        self.m_type = m.group('type')

        # check if the method wasn't static add the obj reg
        if(m.group('family') != 'static'):
            obj_register = registers[0]
            registers = registers[1:]

            temp = {
                    'name' : obj_register,
                    'value' : 'NotSet',
                    'type' : mdata[0]
            }
            self.obj_reg = temp

        # add the registers used in the function call 
        count = 0
        for r in registers:
            t = mdata[2]
            temp = {
                'name' : r,
                'value' : 'NotSet',
                'type' : t[count]
            }
            self.reg.append(temp) 

        return True

class op_Const(OpCodeParser):
    def __init__(self):
        OpCodeParser.__init__(self, r'const(?P<bit_fam>/\d+)?\s+(?P<reg>.+),\s*(?P<val>.+)')
        reg = []
        obj_reg = {}

    
    def parse(self, line):
        self.reg = []
        self.obj_reg = {}
        m = self.expression.search(line)
        if m is None:
            return False
        
        registers = m.group('reg').replace(" ", "").split(',') # remove white space and create a list
        val = OpCodeParser.get_int_value(m.group('val'))
        temp = {
            'name' : registers[0],
            'value' : val,
            'type' : 'Int'
        }
        
        self.reg.append(temp)

        return True

'''
class op_ConstString(OpCodeParser):

    def __init__(self):
        OpCodeParser.__init__(self, r'const-string(?:/jumbo)? (?P<reg>.+),\s*\"(?P<val>.*)\"')
'''