# Raspberry Pi File Tree Editor

A set of tools to configure your raspberry pi's micro SD card before inserting it into raspberry for the first time. 

You can already setup wireless name and password, ssh parameters like port, generate and see ssh fingerprints before boot, change timezone, pi user password and place a script to run at first boot. More other improvements are coming, and I invite you to help.

PS: it might also work with other debian based distros, it all depends on what you want to do.

# How to

Just clone, edit the `setup_my_pi.py` with your configurations and run it. Don't forget to install paramiko:

```
sudo apt install -y python3-paramiko
git clone https://github.com/lucaszanella/raspberry_script_setup
cd raspberry_script_setup
#Edit setup_my_pi.py here
sudo ./setup_my_pi.py
```
