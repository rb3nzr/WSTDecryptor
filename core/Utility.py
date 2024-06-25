from core.Config import *

from colorama import Back, Fore
import subprocess
import platform 
import logging 

class CFormatter(logging.Formatter):
    COLORS = {
        "CRITICAL": Fore.RED + Back.WHITE,
        "WARNING": Fore.RED + Back.BLUE,
        "ERROR": Fore.YELLOW + Back.BLACK,
        "DEBUG": Fore.GREEN + Back.BLUE,
        "INFO": Fore.GREEN
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        if color:
            record.name = color + record.name + Fore.RESET + Back.RESET
            record.levelname = color + record.levelname + Fore.RESET + Back.RESET
            record.msg = color + str(record.msg) + Fore.RESET + Back.RESET 
        return super().format(record)

class CLogger(logging.Logger):
    def __init__(self, name, log_path, log_level=logging.DEBUG):
        super().__init__(name, log_level)

        file_handler = logging.FileHandler(log_path)
        file_formatter = CFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        self.addHandler(file_handler)

def init_logger(name, log_path):
    return CLogger(name, log_path)

def php_exists() -> bool:
    if platform.system() == 'Windows':
        try:
            subprocess.run(
                ['php', '-v'], 
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except subprocess.CalledProcessError:
            print(Fore.RED + ">> Install php cli and rerun")
            return False
        
    elif platform.system() == 'Linux':
        try:
            subprocess.run(
                ['php', '-v'], 
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except subprocess.CalledProcessError:
            print(Fore.RED + ">> Install php cli and rerun")
            return False
    else:
        return False 




        
        
