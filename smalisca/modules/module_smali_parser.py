#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# -----------------------------------------------------------------------------
# File:         modules/module_parser.py
# Created:      2015-01-16
# Purpose:      Parse for functions/methods/calls in Smali files
#
# Copyright
# -----------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2015 Victor Dorneanu <info AAET dornea DOT nu>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

"""
    Implements parsing functionalities for Smali files
"""

import os
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

class SmaliParser():
    """Iterate through files and extract data

    Attributes:
        location (str): Path of dumped APK
        suffix (str): File name suffix
        current_path (str): Will be updated during parsing
        classes (list): Found classes

    """
    def __init__(self, location, suffix, debug):
        self.location = location
        self.suffix = suffix
        self.current_path = None
        self.classes = []
        self.debug = debug
        self.crypto_files = []

    def run(self):
        """
            Looks for files that use crypto and parses them
        """
        self.detect_lib_crypto_use()
        self.parse_crypto_files()

    def detect_lib_crypto_use(self):
        """
            Parse files in specified location to detect if
            cryptography is used in a file append file path
            to the crypto_file list
        """
        for root, dirs, files in os.walk(self.location):
            for f in files:
                if f.endswith(self.suffix):
                    file_path = root + "/" + f
                    # Set current path
                    self.current_path = file_path

                    if self.detect_file_crypto_use(file_path):
                        self.d_log("Crypto use found in file:\t %s" % file_path)
                        self.crypto_files.append(file_path)

    def detect_file_crypto_use(self,file_path):
        """
            Searches a smali file to detect the use of doFinal method used for
            cryptogrpahic implementations
        """
        detected = False
        pattern = r'javax/crypto/Cipher;->doFinal'
        regex = re.compile(pattern)
        with open(file_path, 'r', encoding='utf8') as f:
            fcontent = f.read()
            if regex.search(fcontent) is not None:
                detected =  True

        return detected

    def parse_crypto_files(self):
        for file_path in self.crypto_files:
            self.parse_file(file_path)

    def parse_file(self, filename):
        """Parse specific file

        This will parse specified file for:
            * classes
            * class properties
            * class methods
            * calls between methods

        Args:
            filename (str): Filename of file to be parsed

        """
        with open(filename, 'r', encoding='utf8') as f:
            current_class = None
            current_method = None
            current_call_index = 0

            # Read line by line
            for l in f.readlines():
                if '.class' in l:
                    match_class = self.is_class(l)
                    if match_class:
                        current_class = self.extract_class(match_class)
                        self.classes.append(current_class)

                elif '.super' in l:
                    match_class_parent = self.is_class_parent(l)
                    if match_class_parent:
                        current_class['parent'] = match_class_parent

                elif '.field' in l:
                    match_class_property = self.is_class_property(l)
                    if match_class_property:
                        p = self.extract_class_property(match_class_property)
                        current_class['properties'].append(p)

                #elif 'const-string' in l:
                    #match_const_string = self.is_const_string(l)
                    #if match_const_string:
                        #c = self.extract_const_string(match_const_string)
                        #current_class['const-strings'].append(c)

                elif '.method' in l:
                    match_class_method = self.is_class_method(l)
                    if match_class_method:
                        m = self.extract_class_method(match_class_method)
                        current_method = m
                        current_call_index = 0
                        current_class['methods'].append(m)

                elif 'invoke' in l:
                    match_method_call = self.is_method_call(l)
                    if match_method_call:
                        m, is_crypto = self.extract_method_call(match_method_call)

                        # Add calling method (src)
                        m['src'] = current_method['name']

                        # Add call index
                        m['index'] = current_call_index
                        current_call_index += 1

                        # Add call to current method 
                        current_method['calls'].append(m)
                        # Add to classes crypto method
                        if is_crypto:
                            cm = self.extract_crypto_method(current_method)
                            current_class['crypto_methods'].append(cm)
        # Close fd
        f.close()

    def parse_location(self):
        """Parse files in specified location"""
        for root, dirs, files in os.walk(self.location):
            for f in files:
                if f.endswith(self.suffix):
                    # TODO: What about Windows paths?
                    file_path = root + "/" + f

                    # Set current path
                    self.current_path = file_path

                    # Parse file
                    self.d_log("Parsing file:\t %s" % f)
                    self.parse_file(file_path)

    def is_class(self, line):
        """Check if line contains a class definition

        Args:
            line (str): Text line to be checked

        Returns:
            bool: True if line contains class information, otherwise False

        """
        match = re.search("\.class\s+(?P<class>.*);", line)
        if match:
            self.d_log("Found class: %s" % match.group('class'))
            return match.group('class')
        else:
            return None

    def is_class_parent(self, line):
        """Check if line contains a class parent definition

        Args:
            line (str): Text line to be checked

        Returns:
            bool: True if line contains class parent information, otherwise False

        """
        match = re.search("\.super\s+(?P<parent>.*);", line)
        if match:
            self.d_log("\t\tFound parent class: %s" % match.group('parent'))
            return match.group('parent')
        else:
            return None

    def is_class_property(self, line):
        """Check if line contains a field definition

        Args:
            line (str): Text line to be checked

        Returns:
            bool: True if line contains class property information,
                  otherwise False

        """
        match = re.search("\.field\s+(?P<property>.*);", line)
        if match:
            self.d_log("\t\tFound property: %s" % match.group('property'))
            return match.group('property')
        else:
            return None

    def is_const_string(self, line):
        """Check if line contains a const-string

        Args:
            line (str): Text line to be checked

        Returns:
            bool: True if line contains const-string information,
                  otherwise False

        """
        match = re.search("const-string\s+(?P<const>.*)", line)
        if match:
            self.d_log("\t\tFound const-string: %s" % match.group('const'))
            return match.group('const')
        else:
            return None

    def is_class_method(self, line):
        """Check if line contains a method definition

        Args:
            line (str): Text line to be checked

        Returns:
            bool: True if line contains method information, otherwise False

        """
        match = re.search("\.method\s+(?P<method>.*)$", line)
        if match:
            self.d_log("\t\tFound method: %s" % match.group('method'))
            return match.group('method')
        else:
            return None

    def is_method_call(self, line):
        """Check [MaÔif the line contains a method call (invoke-*)

        Args:
            line (str): Text line to be checked

        Returns:
            bool: True if line contains call information, otherwise False

        """
        match = re.search("invoke-\w+(?P<invoke>.*)", line)
        if match:
            self.d_log("\t\t Found invoke: %s" % match.group('invoke'))
            return match.group('invoke')
        else:
            return None

    def extract_class(self, data):
        """Extract class information

        Args:
            data (str): Data would be sth like: public static Lcom/a/b/c

        Returns:
            dict: Returns a class object, otherwise None

        """
        class_info = data.split(" ")
        self.d_log("class_info: %s" % class_info[-1].split('/')[:-1])
        c = {
            # Last element is the class name
            'name': class_info[-1],

            # Package name
            'package': ".".join(class_info[-1].split('/')[:-1]),

            # Class deepth
            'depth': len(class_info[-1].split("/")),

            # All elements refer to the type of class
            'type': " ".join(class_info[:-1]),

            # Current file path
            'path': self.current_path,

            # Properties
            'properties': [],

            # Const strings
            'const-strings': [],

            # Methods
            'methods': [],

            # Methods using Cryptography
            'crypto_methods' : []
        }

        return c

    def extract_class_property(self, data):
        """Extract class property info

        Args:
            data (str): Data would be sth like: private cacheSize:I

        Returns:
            dict: Returns a property object, otherwise None

        """
        prop_info = data.split(" ")

        # A field/property is usually saved in this form
        #  <name>:<type>
        prop_name_split = prop_info[-1].split(':')

        p = {
            # Property name
            'name': prop_name_split[0],

            # Property type
            'type': prop_name_split[1] if len(prop_name_split) > 1 else '',

            # Additional info (e.g. public static etc.)
            'info': " ".join(prop_info[:-1])
        }

        return p

    def extract_const_string(self, data):
        """Extract const string info

        Args:
            data (str): Data would be sth like: v0, "this is a string"

        Returns:
            dict: Returns a property object, otherwise None

        """
        match = re.search('(?P<var>.*),\s+"(?P<value>.*)"', data)

        if match:
            # A const string is usually saved in this form
            #  <variable name>,<value>

            c = {
                # Variable
                'name': match.group('var'),

                # Value of string
                'value': match.group('value')
            }

            return c
        else:
            return None

    def extract_class_method(self, data):
        """Extract class method info

        Args:
            data (str): Data would be sth like:
                public abstract isTrue(ILjava/lang/..;ILJava/string;)I

        Returns:
            dict: Returns a method object, otherwise None

        """
        method_info = data.split(" ")

        # A method looks like:
        #  <name>(<arguments>)<return value>
        m_name = method_info[-1]
        m_args = None
        m_ret = None

        # Search for name, arguments and return value
        match = re.search(
            "(?P<name>.*)\((?P<args>.*)\)(?P<return>.*)", method_info[-1])

        if match:
            m_name = match.group('name')
            m_args = match.group('args')
            m_ret = match.group('return')

        m = {
            # Method name
            'name': m_name,

            # Arguments
            'args': m_args,

            # Return value
            'return': m_ret,

            # Additional info such as public static etc.
            'type': " ".join(method_info[:-1]),

            # Calls
            'calls': []
        }

        return m

    def extract_crypto_method(self,method):
        """
            Extract details of method that is calling on a crypto function
        """
        cm = {
            # Method name
            'name': method['name'],

            # Arguments
            'args': method['args'],

            # Return value
            'return': method['return'],

            # Additional info such as public static etc.
            'type': method['type']
        }

        return cm

    def extract_method_call(self, data):
        """Extract method call information

        Args:
            data (str): Data would be sth like:
            {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

        Returns:
            dict: Returns a call object, otherwise None
        """
        # Default values
        c_dst_class = data
        c_dst_method = None
        c_local_args = None
        c_dst_args = None
        c_ret = None
        crypto = False

        # The call looks like this
        #  <destination class>) -> <method>(args)<return value>
        match = re.search(
            '(?P<local_args>\{.*\}),\s+(?P<dst_class>.*);->' +
            '(?P<dst_method>.*)\((?P<dst_args>.*)\)(?P<return>.*)', data)

        if match:
            c_dst_class = match.group('dst_class')
            c_dst_method = match.group('dst_method')
            c_dst_args = match.group('dst_args')
            c_local_args = match.group('local_args')
            c_ret = match.group('return')

        c = {
            # Destination class
            'to_class': c_dst_class,

            # Destination method
            'to_method': c_dst_method,

            # Local arguments
            'local_args': c_local_args,

            # Destination arguments
            'dst_args': c_dst_args,

            # Return value
            'return': c_ret
        }
        # check if the crypto funciton is being called in this method
        if c_dst_method == "doFinal":
            crypto = True

        return (c,crypto)

    def get_results(self):
        """Get found classes in specified location

        Returns:
            list: Return list of found classes

        """
        return self.classes

    def d_log(self, msg):
        if self.debug:
            print(msg)

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
    def parse_method_call(line):
        pattern = r'invoke-virtual\s*({[\w\s,]*}),[\s]*([\w/]*);->([\w_]*)\(([\w\[/;]*)\)([\[\w/]*)'
        regex = re.compile(pattern)
        call_data = regex.match(line)

        m_para_reg = call_data.group(1)
        m_class = call_data.group(2)
        m_name = call_data.group(3)
        m_para_types = call_data.group(4)
        m_ret_type = call_data.group(5)

        return (m_para_reg, m_class, m_name, m_para_types, m_ret_type)

