# WSTDecryptor

WSTDecryptor is a tool to automatically extract and decrypt webshell/backdoor communications from a pcap(ng). **[Heavy WIP]**

Currently only contains modules for [SharPyShell](https://github.com/antonioCoco/SharPyShell), [Godzilla](https://github.com/BeichenDream/Godzilla), and [Weevely3](https://github.com/epinna/weevely3).

Included an unpacking script in `/scripts` for the v.1.4 [P.A.S. fork](https://github.com/cr1f/P.A.S.-Fork) webshell. Working on something to help with extraction and decoding from traffic. 

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


