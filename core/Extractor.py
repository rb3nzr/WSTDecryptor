from core.Config import *
from core.Utility import init_logger

from scapy.all import TCP, IP, Raw, rdpcap
from typing import List, Tuple, Dict
import urllib.parse
import shutil
import datetime
import re 
import os 

class BaseExtractor:
    def __init__(self, pcap, ip, port):
        self.pcap = pcap 
        self.ip = ip
        self.port = port 
        self.logger = init_logger('BaseExtractor', log_path)

        self.logger.info(f"===============================================")
        self.logger.info(f">> Initialized pcap: {self.pcap} ip: {self.ip}")
    
    # Extract the TCP segments/payloads from ip packets that match the ip arg passed
    def _extract_payloads(self) -> Dict[Tuple[str, int, str, int], bytes]:
        packets = rdpcap(self.pcap)
        payloads = {}
        try:
            for pkt in packets:
                self._print_header(pkt)
                if (pkt.haslayer(TCP) and pkt.haslayer(IP)):
                    if pkt[IP].src == self.ip or pkt[IP].dst == self.ip:
                        if pkt[TCP].dport == self.port or pkt[TCP].sport == self.port:
                            session_id = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                            if session_id in payloads:
                                payloads[session_id] += bytes(pkt[TCP].payload)
                            else:
                                payloads[session_id] = bytes(pkt[TCP].payload)
                        if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                            self.logger.warning(">> HTTPS traffic found")
        except Exception as e:
            self.logger.error(f">> Error extracting payloads: {e}")
        return payloads
    
    def _extract_payloads_fs(self):
        packets = rdpcap(self.pcap)
        delimiter = b'\r\n\r\n'
        payloads = []
        try:
            for pkt in packets:
                self._print_header(pkt)
                if (pkt.haslayer(TCP) and pkt.haslayer(IP)):
                    if pkt[IP].src == self.ip or pkt[IP].dst == self.ip:
                        if pkt[TCP].dport == self.port or pkt[TCP].sport == self.port:
                            payload = bytes(pkt[TCP].payload)
                            idx = payload.find(delimiter) + len(delimiter)
                            slice_ = payload[idx:]
                            payloads.append(slice_)
                        if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                            self.logger.warning(">> HTTPS traffic found")
        except Exception as e:
            self.logger.error(f">> Error extracting payloads: {e}")
        return payloads
    
    def _extract_b64_pl_data(self, payloads) -> List[Tuple[str, int]]:
        pl_data = ""
        b64_expression = r'(?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)'
        
        try:
            for session_id, data in payloads.items():
                pl_data += data.decode('utf-8', errors='ignore')
            
            matches = re.findall(b64_expression, pl_data)
            data = [(i, p) for i, p in enumerate(matches) if len(p) > 20]
        except Exception as e:
            self.logger.error(f">> Error extracting b64 payload data: {e}")

        return data
    
    def _extract_b64_pl_data_gz(self, payloads, to_server: bool, url_decode: bool):
        b64_data = []
        pl_data = ""

        try:
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
        except Exception as e:
            self.logger.error(f">> Error extracting b64 payload data: {e}")

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
    
    def _print_header(self, pkt):
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt.haslayer(IP):
            payload = bytes(pkt[TCP].payload)
            if b"\r\n\r\n" in payload:
                headers, body = payload.split(b"\r\n\r\n", 1)
                line = headers.decode("utf-8").split("\r\n")
                if line:
                    self.logger.info("======================================")
                    self.logger.debug(f">> HEADER: {line}")
    
    def _check_tmp_dir(self):
        tmp_dir = os.path.join(base_path, "ex_pl_data")
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        os.makedirs(tmp_dir)

class ShellSearcher:
    def __init__(self, pcap):
        self.pcap = pcap
        self.logger = init_logger('ShellSearcher', log_path)

        self.logger.info(f"===============================================")
        self.logger.info(f">> Initialized pcap: {self.pcap}")
        
    def run(self):
        self._extract_shells()
        self._extract_hex_key()

    def _extract_hex_key(self):
        print(f"{cyan}>> Searching for keys..{end}")
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
                        print(f"{yellow}>> Possible Key => {key}{end}")

    def _extract_shells(self):
        cdt = datetime.datetime.now()
        ts = cdt.strftime("%Y%m%d_%H%M%S")
        os.makedirs(os.path.join(output_path, "ex_webshells"), exist_ok=True)
        output_file = os.path.join(ex_webshells_path, f"webshell_{ts}.txt")
        packets = rdpcap(self.pcap)
        payloads = {}
        ex_payloads = set()

        print(f"{cyan}>> Searching for webshells..{end}")

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
                        if pl not in ex_payloads:
                            print(f"{yellow}>> Potential webshell found from: {i}{end}")
                            print(f"{magenta}>> Check {ex_webshells_path}{end}")
                            with open(output_file, "a") as ws_file:
                                ws_file.write(f"IP: {i}\n Payload: {pl.decode('utf-8', errors='ignore')}\n\n")
                            ex_payloads.add(pl)
        except Exception as e:
            self.logger.error(f">> Error searching for shell strings: {e}")
        


