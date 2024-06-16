import sys 
import os 

base_path = os.path.dirname(os.path.realpath(sys.argv[0])) + os.sep 
sys.path.insert(0, base_path)

# - Directories 
webshells_path = base_path + "webshells" + os.sep 
scripts_path = base_path + "scripts" + os.sep 
output_path = base_path + "output" + os.sep
ex_webshells_path = output_path + "ex_webshells" + os.sep
weevely_shells = output_path + "weevely_shells" + os.sep

# - Files
weevely_script = scripts_path + "Weevely3.php" 
sharpy_script = scripts_path + "SharPyShellExtract.ps1"
log_path = base_path + "wstd_log.txt" 

banner = """
     __     __     ______     ______   _____    
    /\ \  _ \ \   /\  ___\   /\__  _\ /\  __-.  
    \ \ \/ ".\ \  \ \___  \  \/_/\ \/ \ \ \/\ \ 
     \ \__/".~\_\  \/\_____\    \ \_\  \ \____- 
      \/_/   \/_/   \/_____/     \/_/   \/____/ 
                                            
      Web Shell Traffic Decryptor - @rb3nzr
         """ 

