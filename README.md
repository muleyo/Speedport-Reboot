## Speedport Reboot
    
This python script allows you to reboot your Speedport.  
You can set up cronjobs to reboot your Speedport on a daily basis.  

Obviously, you need to be in the same local network as your Speedport.  
    
## ✏️Install Instruction
**Make sure that your machine can ping `speedport.ip`. If your machine can't ping `speedport.ip`, add it to the HOSTS-File!**    

- 🐧**Linux**:
     - Install requirements:
         - Install Python (2.7):  `sudo apt-get install build-essential python`
         - Download PyCryptoDome: `wget -O pycryptodome-3.4.7.tar.gz https://git.io/fjqr0`
         - Install PyCryptoDome:  `sudo pip install /PATH/TO/pycryptodome-3.4.7.tar.gz`
     - Set Config in Python script!
     - Command to reboot your Speedport:  `python speedport-reboot.py`
        
- **Windows**:
     - Install requirements:
         - Install Python (2.7):  https://www.python.org/downloads/
         - Download PyCryptoDome: https://git.io/fjqrl (x86) // https://git.io/fjqrB (x64) and save it at `C:\`
         - Install PyCryptoDome: `cd C:\Python27\Scripts` -> `pip install C:\pycryptodome-3.4.7-cp27-cp27m-winXX.whl`
     - Set Config in Python script!
     - Command to reboot your Speedport:  `python speedport-reboot.py`
     
## Tested firmware versions
- Speedport Hybrid v050124.04.00.005
     
## 🤖 Credits
- Dordnung [(Link to his Repo)](https://github.com/dordnung/Speedport-Hybrid-Rebooter)
- Bizzy13 [(Link to his Repo)](https://github.com/Bizzy13/PYTHON-Speedport_Smart-Reconnect)
