#!/usr/bin/env python3
#Lucas Zanella
#Automatic wifi, shh, etc setup of a recently burned raspibian SD image
from functions import * #file editing, ssh generation and other functions

#----------BEGIN USER SCRIPT----------
#Where is your SD card with Raspbian image located?
raspbian_root = "/home/lucas/Coding/zanella_raspberry_addons/raspberrypi_tree_tests/"
raspbian_root = "/media/lz/b4ea8e46-fe87-4ddd-9e94-506c37005ac51/"
#raspbian_root = "/home/lz/Coding/etc_tests/"

#Creates ssh keys on raspbian and generates SHA256 fingerprints
fingerprints = ssh_keygen(save_to = raspbian_root + "etc/ssh/")

#Configures the SSH file of raspbian
sshd_config = replace_in_file("file_models/sshd_config", [
	      	["Port [0-9]*", "Port 2323"],
		["HostKey /etc/ssh/ssh_host_ed25519_key", "#HostKey /etc/ssh/ssh_host_ed25519_key"]
		])
ssh_config_sd_location = raspbian_root + "etc/ssh/sshd_config"
create_file(ssh_config_sd_location, sshd_config)
modify_file_permissions(ssh_config_sd_location, 0o600)

#SSH service comes deactivated by default on raspibian 
#Raspibian currently uses RC services for SSH, but the startup process is systemd. A compatibility trick is used: https://unix.stackexchange.com/questions/233468/how-does-systemd-use-etc-init-d-scripts
enable_rc_service(raspbian_root, "ssh")

#Configures wifi password
network_ssid = ""
network_password = ""
#network_proto = "RSN"
#network_key_mgmt = "WPA-PSK"
#network_pairwise = "CCMP"
#network_auth_alg = "OPEN"

newline = "\n"

create_file(
    raspbian_root + "etc/wpa_supplicant/wpa_supplicant.conf",
    "country=BR" + newline +
    "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev" + newline +
    "update_config=1" + newline + 
    "network = {" + newline +
    "    ssid=" + add_quotation(network_ssid) + newline +
    "	 psk=" + add_quotation(network_password) + newline +
    "}",
    permission=0o600
)

print(fingerprints)
