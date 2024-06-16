from core.Config import *

from colorama import Fore
import subprocess
import platform 
import logging 


def init_logger(log_path, log_level=logging.INFO):
    logging.basicConfig(
        filename=log_path, 
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

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





        
        