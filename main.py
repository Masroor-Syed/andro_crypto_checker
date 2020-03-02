from smalisca.modules.module_smali_parser import SmaliParser
from smalisca.modules.module_static_analysis import ProgramSlicing
import json


# Specify the location where your APK has been dumped
location = 'smalisca/modules/com.badminton.free-313913/smali_classes2/com/ironsource/mediationsdk/utils'
# location = r'D:\UCalgary\CPSC502.04\all_apks\com.badminton.free-313913'
# location = r'D:\UCalgary\CPSC502.04\com.sina.weibo-8.10.3-3767'

# Specify file name suffix
suffix = 'smali'

# debug mode
debug = False

# Create a new parser
parser = SmaliParser(location, suffix, debug)

parser.run()

# Get results
res = parser.get_results()

# All the method with Crypto call inside it
for r in res:
    # create analyzer
    slicer = ProgramSlicing(location, r['crypto_methods'], debug)    
    file_path = location + "/" + r['name'].split('/')[-1] +r'.' + suffix
    
    slicer.read_file(file_path)
    slicer.read_all_method()

    slicer.analyze_method(slicer.crypto_methods[0])

    #print(slicer.crypto_methods)

