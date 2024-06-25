from core.Config import *
from core.Extractor import BaseExtractor
from core.Utility import init_logger

from colorama import Fore 
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad 
from itertools import cycle 
import base64 
import datetime
import subprocess
import io 

class SharPyShellDecryptor:
    class FromBase64Transform:
        def __init__(self):
            self.decoder = base64.b64decode

        def transform_block(self, input_data):
            return self.decoder(input_data)
        
    def __init__(self, pcap, ip, port, key, extract: bool):
        self.pcap = pcap 
        self.ip = ip
        self.port = port
        self.key = key 
        self.extract = extract
        self.logger = init_logger('SharPyShellDecryptor', log_path)
    
    def run(self):
        print(f"{cyan}>> Extracting TCP segment data, this may take a minute..{end}")
        extractor = SharPyDataExtractor(self.pcap, self.ip, self.port)
        pl_data = extractor.run()

        print(f"{cyan}>> Decrypting data..{end}")
        self._process_data(pl_data)

        print(f"{magenta}>> Done! Check output/sharpy_output.cs{end}")
        print(f"{magenta}>> Check wstd_log.txt for details/errors{end}\n")

        if self.extract == True:
            print(f"{magenta}>> Check the output/sharpy_data for extracted modules/shellcode{end}")
    
    def _decrypt(self, data, key):
        def xor_decrypt(data, key):
            key = key.encode()
            decrypted = b''.join(bytes(
                [(x ^ y)]) for (x, y) in list(zip(data, cycle(key))))
            return decrypted
                
        try:
            i_stream = io.BytesIO(data.encode())
            o_stream = io.BytesIO()
            self._decode_b64_stream(i_stream, o_stream)
            o_stream.seek(0)
            decoded = o_stream.read()
        except Exception as e:
            self.logger.warning(f">> Error in decoding: {e}")
            return None

        try:
            aesKey = bytearray.fromhex(key)
            iv = bytes(aesKey[:16])
            cipher = AES.new(aesKey, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(decoded)
            decrypted = unpad(decrypted, AES.block_size)
        except ValueError as e:
            try:
                decrypted = xor_decrypt(decoded, key)
            except Exception as e:
                self.logger.warning(f">> Decryption failed: {e}")
                return None
            
        return decrypted 

    def _decode_b64_stream(self, i_stream, o_stream):
        transform = self.FromBase64Transform()
        try:
            i_chunk_size = 4096
            while True:
                i_data = i_stream.read(i_chunk_size)
                if not i_data:
                    break
                o_data = transform.transform_block(i_data)
                o_stream.write(o_data)
        except Exception as e:
            self.logger.error(f">> Error decoding: {e}")

    def _process_data(self, payloads):
        cdt = datetime.datetime.now()
        ts = cdt.strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_path, f"sharpy_output_{ts}.cs")
        temp_dir = os.path.join(output_path, f"sharpy_data_{ts}")
        
        try:
            counter = 0
            with io.open(output_file, 'a') as file:
                for i, data in payloads:
                    try:
                        result = self._decrypt(data, self.key)
                        if result:
                            counter += 1
                            file.write(f"--------------------------- [ PAYLOAD {counter} ] ---------------------------\n\n")
                            file.write(result.decode('utf-8', errors='ignore'))
                    except Exception as e:
                        self.logger.critical(f">> Error processing payload {i}: {e}")
        except IOError as e:
            self.logger.critical(f">> IOError: {e}")
        
        if self.extract == True:
            print(f"{cyan}>> Extracting any shellcode/modules/commands from the output..{end}")
            os.makedirs(temp_dir, exist_ok=True)
            self._extract_from_output(output_file, temp_dir, self.key)

    def _extract_from_output(self, output_file, temp_dir, key):
        try:
            process = subprocess.run(
                ['powershell', sharpy_script, output_file, temp_dir, key], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                check=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"{red}>> Error running SharPyShellExtract.ps1{end}")
            self.logger.critical(f">> Error running SharPyShellExtract.ps1: {e.stderr}")
        except Exception as e:
            self.logger.critical(f">> Error running SharPyShellExtract.ps1: {e}")
            return

class SharPyDataExtractor(BaseExtractor):
    def __init__(self, pcap, ip, port):
        super().__init__(pcap, ip, port)
        
    def run(self):
        payloads = self._extract_payloads()
        pl_data = self._extract_b64_pl_data(payloads)
        return pl_data
