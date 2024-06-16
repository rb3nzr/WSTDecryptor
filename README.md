# WSTDecryptor

*WSTDecryptor is a tool to automatically extract and decrypt communications sent to a webshell/backdoor from a pcap(ng). [Heavy WIP]*

Currently only contains modules for [SharPyShell](https://github.com/antonioCoco/SharPyShell), [Godzilla](https://github.com/BeichenDream/Godzilla), and [Weevely3](https://github.com/epinna/weevely3). 

## Usage 

```
pip3 install -r requirements.txt
```
- `php-cli` must be installed if using the Weevely3 module.
- `powershell` must be on the machine if using `--extract` with the SharPyShell module.

```
     __     __     ______     ______   _____    
    /\ \  _ \ \   /\  ___\   /\__  _\ /\  __-.  
    \ \ \/ ".\ \  \ \___  \  \/_/\ \/ \ \ \/\ \ 
     \ \__/".~\_\  \/\_____\    \ \_\  \ \____- 
      \/_/   \/_/   \/_____/     \/_/   \/____/ 
                                            
      Web Shell Traffic Decryptor - @rb3nzr
         
usage: WSTDecryptor [-h] {findshell,weevely3,sharpyshell,godzilla} ...

positional arguments:
  {findshell,weevely3,sharpyshell,godzilla}
    findshell           Looks for keys and webshells in the capture file.                 
                        If any webshells are located then the payload is extracted to output/ex_webshells.
    weevely3            Extract and decrypt traffic sent to a Weevely3 webshell
    sharpyshell         Extract and decrypt traffic sent to a SharPyShell webshell
    godzilla            Extract and decrypt traffic sent to a Godzilla webshell

options:
  -h, --help            show this help message and exit

Examples:
        python WSTDecryptor.py [webshell type] -h
        python WSTDecryptor.py sharpyshell -p sample.pcapng -i X.X.X.X -k <key> --extract
        python WSTDecryptor.py findshell -p sample.pcapng
```


