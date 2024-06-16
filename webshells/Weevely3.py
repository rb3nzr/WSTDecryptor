from core.Config import *
from core.Utility import php_exists, init_logger
from core.Extractor import BaseExtractor

import re 
import json 
import zlib
import base64 
import datetime 
import subprocess
from typing import Tuple
from colorama import Fore 

class Weevely3Decryptor():
    def __init__(self, webshell_file, pcap, ip):
        self.webshell_file = webshell_file
        self.pcap = pcap 
        self.ip = ip 
        self.logger = init_logger(log_path)

    def run(self):
        print(Fore.GREEN + ">> Extracting payload data, this may take a minute..\n")
        extractor = WeevelyDataExtractor(self.pcap, self.ip)
        pl_data = extractor.run()
        
        k, kh, kf, p = self._get_md5_slices(self.webshell_file)
        print(Fore.CYAN + f">> key = {k}")
        print(Fore.MAGENTA + f">> payload prefix md5 chunk: {kh}")
        print(Fore.MAGENTA + f">> payload suffix md5 chunk: {kf}\n")
        
        cdt = datetime.datetime.now()
        ts = cdt.strftime("%Y%m%d_%H%M%S")
        os.rename(os.path.join(weevely_shells, "x"), os.path.join(weevely_shells, f"shell_{ts}.php"))
        output_file = os.path.join(output_path, f"weevely_output_{ts}.txt")

        print(Fore.GREEN + ">> Decrypting data..\n")
        try:
            with open(output_file, 'w') as file:
                for i, data in pl_data:
                    try:
                        result = self._process_data(data, kh, kf, k)
                        if result:
                            try:
                                file.write(f"DATA: {result.decode('utf-8')}\n\n")
                            except Exception as e:
                                self.logger.error(f">> Error writing weevely3 results: {e}\n")
                    except Exception as e:
                        self.logger.error(f">> Error decrypting weevely3 data: {e}\n")
        except Exception as e:
            self.logger.error(f">> Error opening/creating weevely output file: {e}\n")
            
        print(Fore.GREEN + f">> Done! Check output/weevely_output.txt")
    
    def _process_data(self, data, kh, kf, k):
        match = re.search(f"{kh}(.+){kf}", data)
        if match:
            m = match.group(1)
            decoded = base64.b64decode(m)
            decompressed = zlib.decompress(self._xor_decrypt(decoded.decode('latin1'), k).encode('latin1'))
        return decompressed

    def _xor_decrypt(self, data, key):
        res = []
        d_len = len(data)
        k_len = len(key)
        for i in range(d_len):
            res.append(chr(ord(data[i]) ^ ord(key[i % k_len])))
        return ''.join(res)

    def _get_md5_slices(self, webshell_file):
        if not php_exists():
            print(Fore.RED + "PHP CLI not installed, exiting..")
            sys.exit(1)
        try:
            result = subprocess.run(
                ['php', weevely_script, webshell_file], capture_output=True, text=True)
            data = json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            self.logger.error(f">> PHP process error: {e}\n")
        except json.JSONDecodeError as e:
            self.logger.error(f">> JSON decoding error: {e}\n")

        k = data.get('k')
        kh = data.get('kh')
        kf = data.get('kf')
        p = data.get('p')

        return k, kh, kf, p
    
class WeevelyDataExtractor(BaseExtractor):
    def __init__(self, pcap, ip):
        super().__init__(pcap, ip)
    
    def run(self):
        payloads = self._extract_payloads()
        pl_data = self._extract_b64_pl_data(payloads, export=False, url_decode=False)
        return pl_data

        



 

            
