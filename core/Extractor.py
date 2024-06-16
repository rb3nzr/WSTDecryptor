from core.Config import *
from core.Utility import init_logger

from colorama import Fore
from scapy.all import TCP, IP, Raw, rdpcap
from typing import Union, List, Tuple, Dict
import urllib.parse
import logging 
import shutil
import datetime
import re 
import os 

class BaseExtractor:
    def __init__(self, pcap, ip):
        self.pcap = pcap 
        self.ip = ip 
        self.logger = init_logger(log_path)

        self.logger.info(f"Initialized pcap: {self.pcap} ip {self.ip}")
    
    # Extract the TCP segments/payloads from ip packets that match the ip arg passed
    def _extract_payloads(self) -> Dict[Tuple[str, int, str, int], bytes]:
        packets = rdpcap(self.pcap)
        payloads = {}
        try:
            for pkt in packets:
                self._print_header(pkt)
                if (pkt.haslayer(TCP) and pkt.haslayer(IP)):
                    if pkt[IP].src == self.ip or pkt[IP].dst == self.ip:
                        session_id = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                        if session_id in payloads:
                            payloads[session_id] += bytes(pkt[TCP].payload)
                        else:
                            payloads[session_id] = bytes(pkt[TCP].payload)
        except Exception as e:
            self.logger.error(f">> Error extracting payloads: {e}")
        return payloads
    
    def _extract_payloads_fs(self):
        packets = rdpcap(self.pcap)
        delimiter = b'\r\n\r\n'
        payloads = []
        try:
            for pkt in packets:
                if (pkt.haslayer(TCP) and pkt.haslayer(IP)):
                    if pkt[IP].src == self.ip or pkt[IP].dst == self.ip:
                        payload = bytes(pkt[TCP].payload)
                        idx = payload.find(delimiter) + len(delimiter)
                        slice_ = payload[idx:]
                        payloads.append(slice_)
        except Exception as e:
            print(e)
        return payloads
    
    def _extract_b64_pl_data(self, payloads, export: bool) -> List[Tuple[str, int]]:
        pl_data = ""
        b64_expression = r'(?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)'

        try:
            for session_id, data in payloads.items():
                self.logger.info(f"Session ID: {session_id}")
                pl_data += data.decode('utf-8', errors='ignore')
            
            matches = re.findall(b64_expression, pl_data)
            data = [(i, p) for i, p in enumerate(matches) if len(p) > 20]
        except Exception as e:
            self.logger.error(f"Error extracting payload data: {e}")

        if export == True:
            self._export_pl_data(data)
        return data
    
    def _extract_b64_pl_data_gz(self, payloads, to_server: bool, url_decode: bool):
        b64_data = []
        pl_data = ""

        if to_server:
            for session_id, data in payloads.items():
                pl_data += data.decode('utf-8', errors='ignore')
        else:
            for data in payloads:
                pl_data += data.decode('utf-8', errors='ignore')

        if url_decode == True:
            pl_data = urllib.parse.unquote(pl_data)

        b64_expression = r'(?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)'
        matches = re.findall(b64_expression, pl_data)
        data = [(i, p) for i, p in enumerate(matches) if len(p) > 10]

        for i, blob in data:
            b64_data.append(blob)
        return b64_data
    
    def _process_raw_pl_data(self, payloads):
        raw_data = []
        delimiter = b'\r\n\r\n'
        for session_id, data in payloads.items():
            idx = data.find(delimiter) + len(delimiter)
            slice_ = data[idx:]
            raw_data.append(slice_)
        return raw_data
    
    def _export_pl_data(self, pl_data) -> None:
        for i, blob in pl_data:
            try:
                path = os.path.join(ex_pl_data_path, f"pl_{i}.txt")
                with open(path, 'wb') as file:
                    file.write(blob)
            except Exception as e:
                self.logger.error(f">> Error writing payload to temp directory: {e}")
                continue
    
    def _print_header(self, pkt):
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt.haslayer(IP):
            payload = bytes(pkt[TCP].payload)
            if b"\r\n\r\n" in payload:
                headers, body = payload.split(b"\r\n\r\n", 1)
                line = headers.decode("utf-8").split("\r\n")
                if line:
                    self.logger.info(line)
    
    def _check_tmp_dir(self):
        tmp_dir = os.path.join(base_path, "ex_pl_data")
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        os.makedirs(tmp_dir)

class ShellSearcher:
    def __init__(self, pcap):
        self.pcap = pcap

        logging.basicConfig(filename=log_path, level=logging.INFO,
            format='%(asctime)s - %(name)s -%(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
    
    def run(self):
        self._extract_shells()
        self._extract_hex_key()

    def _extract_hex_key(self):
        print(Fore.GREEN + ">> Searching for keys..\n")
        hex_expression = r'["\']([0-9A-Fa-f]+)["\']'
        packets = rdpcap(self.pcap)
        for pkt in packets:
            if pkt.haslayer(Raw) and pkt.haslayer(TCP):
                payload = pkt[Raw].load
                pl_str = str(payload)
                matches = re.findall(hex_expression, pl_str)
                candidates = [(i, s) for i, s in enumerate(matches) if len(s) < 65]
                if candidates:
                    for i, key in enumerate(candidates):
                        print(Fore.CYAN + f">> Possible Key => {i}:{key}\n")

    def _extract_shells(self):
        cdt = datetime.datetime.now()
        ts = cdt.strftime("%Y%m%d_%H%M%S")
        os.makedirs(os.path.join(output_path, "ex_webshells"), exist_ok=True)
        output_file = os.path.join(ex_webshells_path, f"webshell_{ts}.txt")
        packets = rdpcap(self.pcap)
        payloads = {}

        # TODO: Cleanup strings/logic and add more for other webshells.
        # Currently will write out a copy of the payload that contains the webshell each time a string is found.

        ws_strings = [
            'string p =', 'string key', 'string md5', 'byte[] a =', 'byte[] data =', 'string pass =', 'string r = Request.Form["data"]', 
            'aS.CreateInstance("SharPy")', '<% Import Namespace="System.Reflection" %>', '0x2f,0x6e,0xf6,0x63,0x36,0x38,0x34',
            '\160\x68\141\x72\72\57\57', 'Context.Session["payload"] == null', 'stringBuilder.Append(md5.Substring(0, 16))', 
            '((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY")', '$c = $K[$i+1&15]', '$D[$i] = $D[$i]^$c',
            'stringBuilder.Append(md5.Substring(16))', '<%@ Page Language="Jscript"%><%eval(Request.Item["', '$payloadName=', 
            '$payload=encode($_SESSION[$payloadName],$key)'
        ]

        print(Fore.GREEN + ">> Searching for shell strings in payloads..")

        try:
            for pkt in packets:
                if (pkt.haslayer(TCP) and pkt.haslayer(IP)): 
                    session_id = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                    if session_id in payloads:
                        payloads[session_id] += bytes(pkt[TCP].payload)
                    else:
                        payloads[session_id] = bytes(pkt[TCP].payload)

            for string in ws_strings:
                for i, pl in payloads.items():
                    if string in str(pl):
                        print(Fore.YELLOW + f">> Potential webshell found from: {i}")
                        print(Fore.WHITE + f">> Check {ex_webshells_path}\n")
                        with open(output_file, "a") as ws_file:
                            ws_file.write(f"IP: {i}\n Payload: {pl.decode('utf-8', errors='ignore')}\n\n")
        except Exception as e:
            self.logger.error(f">> Error searching for shell strings: {e}")
        


