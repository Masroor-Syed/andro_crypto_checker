import json
import re
import sys
from smalisca.modules.parser import * 
from smalisca.modules.crypto_method_analysis import * 

class ProgramSlicing():
    """Iterate through files and extract data

    Attributes:
        location (str): Path of dumped APK
        crypto_methods (list): list of crypto method
        debug (bool): debugging 

    """
    def __init__(self, location, cm, debug):
        self.location = location
        self.cm = cm
        self.debug = debug
        self.code = ''
        self.crypto_methods = []
        self.opParser = []
        self.obj_reg = []
        self.reg = []
        self.track = []
        '''self.cipher_data = {
            "obj_reg": None,
            "Cipher": None,
            "Mode": None,
            "Padding": None,
            "Key": None,
            "IV": None
        }'''

        # dynamicly load op codes
        for entry in dir(sys.modules['smalisca.modules.parser']):
            if entry.startswith('op_'):
                self.opParser.append(globals()[entry]())

    def update_opreg(self, reg):
        # remove old register value
        c = 0
        for r in self.reg:
            if (r['name'] == reg['name']):
                self.reg.pop(c)
            c+=1
        
    def add_opreg_dict(self, objreg):
        for i in self.obj_reg:
            if (i['name'] == objreg['name']) and (i['type'] == objreg['type']):
                return False
        # if obj_reg not there add it to the list
        self.obj_reg.append(objreg)
        self.track.append(objreg['name'])

        return True

    def add_reg_dict(self, reg):
        # del the previous val of register updated
        for r in reg:
            self.update_opreg(r)
        
        for r in reg:
            self.reg.append(r)
            # if not in tracker
            if not (r['name'] in self.track):
                self.track.append(r['name'])

    def skip_line(self, line):
        for tr in self.track:
            ptn = re.compile(r'\b' + tr + r'\b')
            if ptn.search(line) != None:
                return False
        return True
    
    def parse_line(self, line, c_data):
        # Search for appropriate parser.
        for parser in self.opParser:
            if parser.parse(line):
                # put the reg in self
                if parser.obj_reg != {}:
                    self.add_opreg_dict(parser.obj_reg) 
                self.add_reg_dict(parser.reg)
                self.populate_cipher_data(parser, c_data)

                return True

        return False

    def populate_cipher_data(self, parser, c_data):
        if (isinstance(parser, op_Invoke)):
            self.is_crypto_method(parser, c_data)

    def read_file(self, file_path):
        with open(file_path, 'r', encoding='utf8') as f:
            self.code = f.read()

    def read_all_method(self):
        # read all crypto method into a list
        for m in self.cm:
            p = r'(?P<m_name>\.method\s+.*'+m['name']+ r').*$(?P<m_body>[\w\W]*?\.end\s+method)$'
            pattern = re.compile(p,re.MULTILINE)
            match = pattern.finditer(self.code)

            for m in match:
                cm = m.group('m_name') + '\n' + m.group('m_body')
                self.crypto_methods.append(cm)

    def analyze_methods(self):
        for method in self.crypto_methods:
            self.analyze_method(method)

    def analyze_method(self, method):
        pattern = r'(.method[\s\S]*Ljavax/crypto/Cipher;->doFinal.*$)'
        regex = re.compile(pattern, re.MULTILINE)

        method = regex.search(method).group(1)
        # reverse the method so start backward slice at doFinal method        
        break_method =  method.split('\n')
        break_method.reverse()

        # analyse the first line and set up reg and obj_reg
        c_data = CryptoData()
        self.parse_line(break_method[0], c_data)
        break_method.pop(0)
        #self.cipher_data['obj_reg'] = self.obj_reg[0]['name']

        for line in break_method:
            if not self.skip_line(line):
                self.parse_line(line,c_data)
                break_method.pop(0)
            
        
        print("obj_reg =",self.obj_reg)
        print("reg =",self.reg)
        print(c_data.reg)

    def is_crypto_method(self, parser, c_data):
        if parser.m_name == 'doFinal':
            if 'Ljavax/crypto' in parser.obj_reg['type']:
                c_data.reg = self.obj_reg[0]['name']
                print('df')
        elif parser.m_name == 'init':
            if 'Ljavax/crypto' in parser.obj_reg['type']:
                print('cinit')
        elif parser.m_name == 'getInstance':
            if len(parser.reg)==1 and 'Ljavax/crypto' in parser.m_type:
                print('getInstanceeeee')
