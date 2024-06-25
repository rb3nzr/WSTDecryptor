from core.Config import *
from core.Utility import php_exists, init_logger
from core.Extractor import BaseExtractor

import re 
import json 
import zlib
import base64 
import datetime 
import subprocess

class Weevely3Decryptor():
    def __init__(self, webshell_file, pcap, ip, port):
        self.webshell_file = webshell_file
        self.pcap = pcap 
        self.ip = ip 
        self.port = port
        self.logger = init_logger('Weevely3Decryptor', log_path)

    def run(self):
        print(f"{cyan}>> Extracting payload data, this may take a minute..{end}")
        extractor = WeevelyDataExtractor(self.pcap, self.ip, self.port)
        pl_data = extractor.run()
        
        k, kh, kf, p = self._get_md5_slices(self.webshell_file)
        print(f"\n{green}>> key => {k}{end}")
        print(f"{green}>> payload prefix => {kh}{end}")
        print(f"{green}>> payload suffix => {kf}{end}\n")
        
        cdt = datetime.datetime.now()
        ts = cdt.strftime("%Y%m%d_%H%M%S")
        os.rename(os.path.join(weevely_shells, "x"), os.path.join(weevely_shells, f"shell_{ts}.php"))
        output_file = os.path.join(output_path, f"weevely_output_{ts}.txt")

        print(f"{cyan}>> Decrypting data..{end}")
        try:
            with open(output_file, 'w') as file:
                for i, data in pl_data:
                    try:
                        result = self._process_data(data, kh, kf, k)
                        if result:
                            try:
                                file.write(f"DATA: {result.decode('utf-8')}\n\n")
                            except Exception as e:
                                self.logger.critical(f">> Error writing weevely3 results: {e}")
                    except Exception as e:
                        self.logger.critical(f">> Error decrypting weevely3 data: {e}")
        except Exception as e:
            self.logger.critical(f">> Error opening/creating weevely output file: {e}")
            
        print(f"{magenta}>> Done! Check output/weevely_output.txt{end}")
        print(f"{magenta}>> Check wstd_log.txt for details{end}\n")
    
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
            print(f"{red}>> PHP CLI not installed, exiting..{end}\n")
            sys.exit(1)
        try:
            result = subprocess.run(
                ['php', weevely_script, webshell_file], capture_output=True, text=True)
            data = json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            self.logger.error(f">> PHP process error: {e}")
        except json.JSONDecodeError as e:
            self.logger.error(f">> JSON decoding error: {e}")

        k = data.get('k')
        kh = data.get('kh')
        kf = data.get('kf')
        p = data.get('p')

        return k, kh, kf, p
    
class WeevelyDataExtractor(BaseExtractor):
    def __init__(self, pcap, ip, port):
        super().__init__(pcap, ip, port)
    
    def run(self):
        payloads = self._extract_payloads()
        pl_data = self._extract_b64_pl_data(payloads)
        return pl_data
        



 

            
