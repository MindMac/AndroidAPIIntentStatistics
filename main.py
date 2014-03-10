#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Created on 2014-3-10

@author: Wenjun Hu
'''

import os, codecs
from optparse import OptionParser

from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.bytecodes.apk import APK
from androguard.core.analysis.analysis import VMAnalysis

from class_method import CLASS_METHOD


# Options definition
option_0 = { 'name' : ('-i', '--input'), 'help' : 'Directory of APK files to analyze', 'nargs' : 1 }
option_1 = { 'name' : ('-o', '--output'),'help' : 'Output file of result', 'nargs': 1}
options = [option_0, option_1]


def to_unicode(string):
    if string:
        return unicode(string, 'utf-8', 'ignore')
    else:
        return string
    
    
class Analyzer():
    def __init__(self, apk_file, analysis_results):
        self.apk_file = apk_file
        self.analysis_results = analysis_results
        
        self.apis = []
        self.strings = []
        self.intents = []
        
    def run(self):      
        # analysis
        print 'Start analyzing %s... \n' % self.apk_file
        try:
            self.perform_analysis()
        except Exception, ex:
            print ex
            return
        
        try:
            self.perform_statistics()
        except Exception, ex:
            print ex
            return
        
            
    def perform_analysis(self):
        if self.apk_file and os.path.exists(self.apk_file):
            try:
                apk = APK(self.apk_file)
            except Exception, ex:
                print ex
                return
            
            # Intents
            self.intents = apk.get_elements('action', 'android:name')
            # Create DalvikFormat
            dalvik_vm_format = None
            try:
                dalvik_vm_format = DalvikVMFormat( apk.get_dex() )
            except Exception, ex:
                print ex
                return
            
            # Create VMAnalysis
            vm_analysis = None
            if dalvik_vm_format:
                try:
                    vm_analysis = VMAnalysis( dalvik_vm_format )
                except Exception, ex:
                    print ex
                    return
            
            dalvik_vm_format.set_vmanalysis( vm_analysis ) 
            
            # Get strings
            for s, _ in vm_analysis.tainted_variables.get_strings():
                if s.get_info():
                    self.strings.append(to_unicode(s.get_info())) 
                
            # Get apis
            api_class_list = CLASS_METHOD.keys()
            for tainted_package,_ in vm_analysis.tainted_packages.get_packages():
                paths = tainted_package.get_methods()
                class_name = tainted_package.get_name()
                if class_name in api_class_list:
                    for path in paths:
                        self.apis.append('%s->%s' % (class_name, path.get_name()))
            
            
    def perform_statistics(self):
        self.analysis_results['total_num'] += 1
        
        for intent in self.intents:
            if intent in self.analysis_results['intents']:
                self.analysis_results['intents'][intent] += 1
            else:
                self.analysis_results['intents'][intent] = 1
        
        for string in self.strings:
            if string in self.analysis_results['strings']:
                self.analysis_results['strings'][string] += 1
            else:
                self.analysis_results['strings'][string] = 1
                
        for api in self.apis:
            if api in self.analysis_results['apis']:
                self.analysis_results['apis'][api] += 1
            else:
                self.analysis_results['apis'][api] = 1
                
def main(options, arguments):
    apk_file_list = []
    analysis_results = {'intents':{}, 'strings': {}, 'apis': {}, 'total_num': 0}

    if(options.input != None):
        apk_file_directory = options.input
        if(not os.path.exists(apk_file_directory)):
            print '%s not exists' % apk_file_directory
            return
        else:
            for root, dir, files in os.walk(apk_file_directory):
                apk_file_list.extend([os.path.join(root, file_name) for file_name in files])
        
        if(options.output != None):
            output_file = options.output
        else:
            output_file = 'statistics.txt'
            
        # Start analysis
        start_analysis(apk_file_list, analysis_results)   
        
        # Store results    
        store_results(output_file, analysis_results)
        
        print 'Analysis done, result is stored in %s' % output_file

def start_analysis(apk_file_list, analysis_results):
    while apk_file_list:
        apk_file = apk_file_list.pop()
        analyzer = Analyzer(apk_file, analysis_results)
        analyzer.run()
                   
def store_results(output_file, analysis_results): 
    # Analysis done
    sorted_intents = sorted(analysis_results['intents'].items(), key=lambda item:item[1], reverse=True)
    sorted_strings= sorted(analysis_results['strings'].items(), key=lambda item:item[1], reverse=True)
    sorted_apis= sorted(analysis_results['apis'].items(), key=lambda item:item[1], reverse=True)
    

    
    try:
        output = codecs.open(output_file, 'w', 'utf-8')
    except IOError, ex:
        print ex
    try:
        output.write('================= Analysis Results ================== \n')
        output.write('Total number of valid APKs: %d \n' % analysis_results['total_num'])

        output.write('\n')
        output.write('----------------- Intent Results -------------- \n')
        for intent in sorted_intents:
            output.write('%s : %s \n' % (intent[0], intent[1]))
    
        output.write('\n')
        output.write('----------------- API Results ---------------- \n')
        for api in sorted_apis:
            output.write('%s : %s \n' % (api[0], api[1]))
            
        output.write('\n')
        output.write('----------------- String Results ---------------- \n')
        for string in sorted_strings:
            output.write('%s : %s \n' % (string[0], string[1]))
            
        
    except IOError, ex:
        print ex
    finally:
        output.close()
            
            
if __name__ == '__main__':
    # Options
    parser = OptionParser()
    for option in options:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    #options, arguments = parser.parse_args()
    options, arguments = parser.parse_args(['-i', r'E:\01-MobileSec\01-Android\TestApks'])
    main(options, arguments)
        
            
                
            
            
            
            
            
            
        
        
