from colorama import init, Fore, Style
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

# - Init Fore colors for console
init()
green = Fore.GREEN
red = Fore.RED
blue = Fore.BLUE
yellow = Fore.YELLOW
magenta = Fore.MAGENTA
cyan = Fore.CYAN
white = Fore.WHITE
end = Style.RESET_ALL

banner = f"""{green}
     __     __     ______     ______   _____    
    /\ \  _ \ \   /\  ___\   /\__  _\ /\  __-.  
    \ \ \/ ".\ \  \ \___  \  \/_/\ \/ \ \ \/\ \ 
     \ \__/".~\_\  \/\_____\    \ \_\  \ \____- 
      \/_/   \/_/   \/_____/     \/_/   \/____/ 
                                            
      {blue}Web Shell Traffic Decryptor - @rb3nzr
         {end}""" 

# - Strings to find uploaded shells in the pcap
ws_strings = [
   'object[] iN = new object[] {r, p}', 'byte[] a =', 'byte[] data =', 'string pass =', 'string r = Request.Form["data"]', 
   'aS.CreateInstance("SharPy")', '<% Import Namespace="System.Reflection" %>', '0x2f,0x6e,0xf6,0x63,0x36,0x38,0x34',
   'Xor Asc(Mid(key,(i mod keySize)+1,1)))', 'Context.Session["payload"] == null', 'stringBuilder.Append(md5.Substring(0, 16))', 
   '((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY")', '$c = $K[$i+1&15]', '$D[$i] = $D[$i]^$c',
   'stringBuilder.Append(md5.Substring(16))', '<%@ Page Language="Jscript"%><%eval(Request.Item["', '$payloadName=', 
   '$payload=encode($_SESSION[$payloadName],$key)', 'String xc=', 'xc.getBytes(),"AES"', 'CreateInstance("LY")', 
   'object o = ((System.Reflection.Assembly', 'pass + key))).Replace', '<%@ Page Language="Jscript"%><%eval(Request.Item["', 
   'string key="', '<?php include "\160\x68\141\x72\72\57\57"', 'basename(__FILE__)."\57\x78";__HALT_COMPILER()'
]
