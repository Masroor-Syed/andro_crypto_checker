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


    # @abstractstaticmethod
    def eval(vm, *args):
        pass

class op_Const(OpCodeParser):

    def __init__(self):
        OpCodeParser.__init__(self, r'^const(/\d+)?\s+(.+),\s*(.+)')

    @staticmethod
    def eval(vm, _, vx, lit):
        pass

class op_ConstWide(OpCodeParser):

    def __init__(self):
        OpCodeParser.__init__(self, r'^const-wide(/\d+)? (.+),\s*(.+)')

    @staticmethod
    def eval(vm, _, vx, lit):
        # OpCodeParser.get_int_value(lit)
        pass

class op_ConstString(OpCodeParser):

    def __init__(self):
        OpCodeParser.__init__(self, r'^const-string(?:/jumbo)? (.+),\s*"(.*)"')

    @staticmethod
    def eval(vm, vx, s):
        pass
        
class op_Move(OpCodeParser):

    def __init__(self):
        OpCodeParser.__init__(self, r'^move(-object)?[\/from16]* (.+),\s*(.+)')

    @staticmethod
    def eval(vm, _, vx, vy):
        pass

class op_MoveResult(OpCodeParser):

    def __init__(self):
        OpCodeParser.__init__(self, r'^move-result(-object)? (.+)')

    @staticmethod
    def eval(vm, _, dest):
        pass

class op_ArrayLength(OpCodeParser):

    def __init__(self):
        OpCodeParser.__init__(self, r'array-length (.+),\s*(.+)')

    @staticmethod
    def eval(vm, vx, vy):
        pass

class op_ArrayFillData(OpCodeParser):

    def __init__(self):
        OpCodeParser.__init__(self, r'fill-array-data (.+),\s*(.+)')

    @staticmethod
    def eval(vm, vx, label):
        pass

class op_IputBoolean(OpCodeParser):
    # iput-boolean v0, p0, Lcom/a;->a:Z

    def __init__(self):
        OpCodeParser.__init__(self, r'^iput-boolean\s*(.+),\s*(.+),\s*(.+)$')

    @staticmethod
    def eval(vm, vx, _, vz):
        pass

class op_IgetBoolean(OpCodeParser):
    # iput-boolean v0, p0, Lcom/a;->a:Z

    def __init__(self):
        OpCodeParser.__init__(self, r'^iget-boolean\s*(.+),\s*(.+),\s*(.+)$')

    @staticmethod
    def eval(vm, vx, _, vz):
        pass

class op_Aget(OpCodeParser):

    def __init__(self):
        OpCodeParser.__init__(self, r'^aget[\-a-z]* (.+),\s*(.+),\s*(.+)')

    @staticmethod
    def eval(vm, vx, vy, vz):
        pass

class op_NewInstance(OpCodeParser):

    def __init__(self):
        OpCodeParser.__init__(self, r'^new-instance (.+),\s*(.+)')

    @staticmethod
    def eval(vm, vx, klass):
        pass

class op_NewArray(OpCodeParser):
    '''new-array vx,vy,type_id

    Generates a new array of type_id type and vy element size and puts the
    reference to the array into vx.
    '''

    def __init__(self):
        OpCodeParser.__init__(self, r'^new-array (.+),\s*(.+),\s*(.+)')

    @staticmethod
    def eval(vm, vx, vy, klass):
        pass

class op_APut(OpCodeParser):
    '''aput vx,vy,vz

    Puts the integer value in vx into an element of an integer array.
    The element is indexed by vz, the array object is referenced by vy.
    '''

    def __init__(self):
        OpCodeParser.__init__(self, r'^aput(-[a-z]+)? (.+),\s*(.+),\s*(.+)')

    @staticmethod
    def eval(vm, _, vx, vy, vz):
        pass

class op_Invoke(OpCodeParser):

    def __init__(self):
        OpCodeParser.__init__(self, r'^invoke-(?P<family>[a-z]+) \{(?P<reg>.*)\},\s*(?P<m_name>.+\))(?P<type>.+)')

    def parse(self,line):
        m = self.expression.search(line)
        reg = m.group('reg').replace(" ", "").split(',') # remove white space and create a list
        obj_reg = None

        # check if the method was static
        if(m.group('family') != 'static'):
            obj_reg = reg[0] 


class op_SPutObject(OpCodeParser):

    def __init__(self):
        # sput-object v9, Lcom/whatsapp/messaging/a;->z:[Ljava/lang/String;
        # aput-object v6, v8, v7
        OpCodeParser.__init__(self, r'^sput-object+\s(.+),\s*(.+)')

    @staticmethod
    def eval(vm, vx, staticVariableName):
        pass

class op_SPut(OpCodeParser):

    def __init__(self):
        # const/16 v0, 0xed
        # sput v0, Lcom/a;->g:I
        OpCodeParser.__init__(self, r'^sput\s(.+),\s*(.+)')

    @staticmethod
    def eval(vm, vx, staticVariableName):
        pass

class op_SGet(OpCodeParser):

    def __init__(self):
        # sget v0, Lcom/a;->g:I
        OpCodeParser.__init__(self, r'^sget+\s(.+),\s*(.+)')

    @staticmethod
    def eval(vm, vx, staticVariableName):
        pass

class op_SGetObject(OpCodeParser):

    def __init__(self):
        # sput-object v9, Lcom/whatsapp/messaging/a;->z:[Ljava/lang/String;
        # aput-object v6, v8, v7
        OpCodeParser.__init__(self, r'^sget-object+\s(.+),\s*(.+)')

    @staticmethod
    def eval(vm, vx, staticVariableName):
        pass

class op_Return(OpCodeParser):

    def __init__(self):
        OpCodeParser.__init__(self, r'^return(-[a-z]*)*\s*(.+)*')

    @staticmethod
    def eval(vm, ctype, vx):
        pass

