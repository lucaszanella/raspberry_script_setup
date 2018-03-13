#!/usr/bin/env python3
#Lucas Zanella
#Automatic wifi, shh, etc setup of a recently burned raspibian SD image
from ImageEditorClass import * #The class that will deal with the file tree of a linux image

#---------------------BEGIN USER SCRIPT---------------------
from io_utils import *

#TODO: implement this:
#download_file("https://downloads.raspberrypi.org/raspbian_latest")

#Where is your SD card with a burnt Raspbian image located?
raspbian_root = "/media/lz/rootfs/"
raspbian_boot = "/media/lz/boot/"
#raspbian_root = "/home/lz/Coding/zanella_raspberry_addons/raspberrypi_tree_tests/"

raspbian = ImageEditor(raspbian_root)
raspbian_boot = ImageEditor(raspbian_boot)

#Changes user´s password - VERY IMPORTANT! PICK SECURE PASSWORD (LONG AND RANDOM)
raspbian.change_user_password(user="pi", password="raspberry123")

#Look at zones.txt in this diretory to know your zone, or just navigate through /usr/share/zoneinfo on any linux to find your timezone
raspbian.change_timezone("America/Sao_Paulo")

#Creates ssh keys on raspbian and generates SHA256 fingerprints
fingerprints = raspbian.ssh_keygen(save_to = "etc/ssh/")

#Configures the SSH file of raspbian
sshd_config = read_file("file_models/sshd_config")
sshd_config = replace(sshd_config, [
	      	["Port [0-9]*", "Port 2323"],
		["HostKey /etc/ssh/ssh_host_ed25519_key", "#HostKey /etc/ssh/ssh_host_ed25519_key"]
		])
ssh_config_sd_location = "etc/ssh/sshd_config"
raspbian.create_file(ssh_config_sd_location, sshd_config)
raspbian.modify_file_permissions(ssh_config_sd_location, 0o600)

#Removes script that generates ssh keys on first boot
raspbian.remove_file("etc/systemd/system/multi-user.target.wants/regenerate_ssh_host_keys.service", do_backup=False) 

#Activate and start ssh daemon on first boot, in the next boots it'll just start
commands = ("/usr/sbin/update-rc.d ssh enable && /usr/sbin/invoke-rc.d ssh start"
	    " && sudo apt-get update && sudo apt-get install -y curl git python-pip python3-pip screen" #Space before && is important
	    " && export DEBIAN_FRONTEND=noninteractive && curl -fsSL get.docker.com -o get-docker.sh && sudo sh get-docker.sh"
            " && sudo pip install docker-compose ")
raspbian.run_once_at_boot(commands)

#Configures wifi
raspbian.add_new_wifi_network(network_ssid = "wifi_name_here", 
		  network_password = "wifi_password_here",
		  country = "US")
'''
#You can add more than one network!
raspbian.add_new_wifi_network(network_ssid = "NetworkNumber2", 
		  network_password = "password",
		  country = "BR")
'''

print(fingerprints)
