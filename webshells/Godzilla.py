from core.Config import *
from core.Extractor import BaseExtractor
from core.Utility import init_logger

from colorama import Fore
from Crypto.Cipher import AES 
from Crypto.Util.Padding import unpad 
import base64
import gzip 
import datetime
import os 
import io 

class GodzillaDecryptor:
    def __init__(self, pcap, ip, key, raw=False):
        self.pcap = pcap
        self.ip = ip 
        self.key = key.encode()
        self.raw = raw
        self.logger = init_logger(log_path)

    def run(self):
        to_server = '-'*32+''+'[ TO SERVER ]'+''+'-'*32
        from_server = '-'*32+''+'[ SERVER RESPONSE ]'+''+'-'*32

        print(Fore.GREEN + ">> Extracting TCP segment data, this may take a minute..\n")

        if self.raw == True:
            extractor = GodzillaDataExtractorRaw(self.pcap, self.ip)
            pl_data_ts = extractor.get_data_ts()
            pl_data_fs = extractor.get_data_fs()

            print(Fore.GREEN + ">> Decrypting data..\n")
            self._process_data(pl_data_ts, to_server, ex_slices=False)
            self._process_data(pl_data_fs, from_server, ex_slices=False)
        else:
            extractor = GodzillaDataExtractorBase64(self.pcap, self.ip)
            pl_data_ts = extractor.get_data_ts()
            pl_data_fs = extractor.get_data_fs()

            print(Fore.GREEN + ">> Decrypting data..\n")
            self._process_data(pl_data_ts, to_server, ex_slices=False)
            self._process_data(pl_data_fs, from_server, ex_slices=True)

        print(Fore.GREEN + ">> Done! Check output/godzilla_output.txt")

    def _decrypt(self, data, ex_slices: bool):
        def xor_decrypt(data, key):
            res = bytearray(len(data))
            for i in range(len(data)):
                c = key[(i + 1) & 15]
                res[i] = data[i] ^ c 
            return bytes(res) 
        
        encrypted = data 
        if ex_slices == True:
            encrypted = self._strip_md5_slices(encrypted)
            encrypted = self._strip_suffix(encrypted)
        if self.raw == False:
            encrypted = self._decode_b64(encrypted)
        if not encrypted:
            return None
        
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, self.key)
            decrypted = cipher.decrypt(encrypted)
            decrypted = unpad(decrypted, AES.block_size)
        except ValueError as e:
            try:
                decrypted = xor_decrypt(encrypted, self.key)
            except Exception as e:
                self.logger.error(f"Decryption failed: {e}")
                return None         
        try:
            decompressed = gzip.decompress(decrypted)
        except gzip.BadGzipFile as e:
            try:
                decompressed = self._alt_gzip_decomp(decrypted)
            except Exception as e:
                return decrypted
        return decompressed

    def _strip_md5_slices(self, data):
        if len(data) <= 32:
            return data 
        return data[16:-16]

    def _decode_b64(self, data):
        try:
            return base64.b64decode(data)
        except base64.binascii.Error as e:
            self.logger.error(f"Base64 decode error: {e}")
            return None
    
    def _alt_gzip_decomp(self, data):
        if len(data) == 0:
            return data 
        else:
            obj = io.BytesIO(data)
            with gzip.GzipFile(fileobj=obj) as file:
                res = file.read()
            return res

    def _strip_suffix(self, data):
        http = "HTTP"
        post = "POST"
        if data.lower().endswith(http.lower()):
            data = data[:-len(http)]
        if data.lower().endswith(post.lower()):
            data = data[:-len(post)]
        return data  
    
    def _process_data(self, pl_data, header, ex_slices: bool):
        cdt = datetime.datetime.now()
        ts = cdt.strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_path, f"godzilla_output_{ts}.txt")
        output_file_bin = os.path.join(output_path, f"godzilla_output_bin_{ts}.bin")
        
        try:
            with open(output_file, 'a') as file:
                file.write(header + '\n\n')
                for i, data in enumerate(pl_data):
                    try:
                        result = self._decrypt(data, ex_slices)
                        if result:
                            file.write(result.decode('utf-8') + '\n\n')
                    except Exception as e:
                        self.logger.error(f"Failed to process data segment: {i}: {e}")
        except IOError as e:
            self.logger.error(f"Failed to write to file {output_file}: {e}")  
        
        try:
            with open(output_file_bin, 'ab') as file:
                for i, data in enumerate(pl_data):
                    try:
                        result = self._decrypt(data, ex_slices)
                        if result:
                            file.write(result)
                    except Exception as e:
                        self.logger.error(f"Failed to process data segment: {i}: {e}")
        except IOError as e:
            self.logger.error(f"Failed to write to file {output_file_bin}: {e}")


class GodzillaDataExtractorRaw(BaseExtractor):
    def __init__(self, pcap, ip):
        super().__init__(pcap, ip)
        
    def get_data_ts(self):
        payloads_ts = self._extract_payloads()
        pl_data_ts = self._process_raw_pl_data(payloads_ts)
        return pl_data_ts

    def get_data_fs(self):
        pl_data_fs = self._extract_payloads_fs()
        return pl_data_fs
        
class GodzillaDataExtractorBase64(BaseExtractor):
    def __init__(self, pcap, ip):
        super().__init__(pcap, ip)
    
    def get_data_ts(self):
        payloads_ts = self._extract_payloads()
        pl_data_ts = self._extract_b64_pl_data_gz(payloads_ts, to_server=True, url_decode=True)
        return pl_data_ts
        
    def get_data_fs(self):
        payloads_fs = self._extract_payloads_fs()
        pl_data_fs = self._extract_b64_pl_data_gz(payloads_fs, to_server=False, url_decode=True)
        return pl_data_fs
    


