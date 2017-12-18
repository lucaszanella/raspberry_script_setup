#!/usr/bin/env python3
#Lucas Zanella
#Automatic wifi, shh, etc setup of a recently burned raspibian SD image
from ImageEditorClass import * #The class that will deal with the file tree of a linux image

#---------------------BEGIN USER SCRIPT---------------------
from io_utils import *
download_file("https://downloads.raspberrypi.org/raspbian_latest")
#Where is your SD card with Raspbian image located?
raspbian_root = "/home/lz/Coding/zanella_raspberry_addons/raspberrypi_tree_tests/"
raspbian_root = "/media/lz/b4ea8e46-fe87-4ddd-9e94-506c37005ac53/"
#raspbian_root = "/home/lz/Coding/etc_tests/"

raspbian = ImageEditor(raspbian_root)

#Changes user´s password - VERY IMPORTANT! PICK SECURE PASSWORD (LONG AND RANDOM)
raspbian.change_user_password(user="pi", password="woryuor2398dbddbx3#&")

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
raspbian.remove_file(raspbian_root + "etc/systemd/system/multi-user.target.wants/regenerate_ssh_host_keys.service", do_backup=False) 

#Activate and start ssh daemon on first boot, in the next boots it'll just start
raspbian.run_once_at_boot(raspbian_root, "/usr/sbin/update-rc.d ssh enable && /usr/sbin/invoke-rc.d ssh start")

#Configures wifi
raspbian.add_new_wifi_network(network_ssid = "NetworkNumber1", 
		  network_password = "password",
		  country = "BR")
'''
#You can add more than one network!
raspbian.add_new_wifi_network(network_ssid = "NetworkNumber2", 
		  network_password = "password",
		  country = "BR")
'''

print(fingerprints)
