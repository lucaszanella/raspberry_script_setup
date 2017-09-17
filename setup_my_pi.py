#!/usr/bin/env python3
#Lucas Zanella
#Automatic wifi, shh, etc setup of a recently burned raspibian SD image
from functions import * #file editing, ssh generation and other functions

#----------BEGIN USER SCRIPT----------
#Where is your SD card with Raspbian image located?
raspbian_root = "/home/lucas/Coding/zanella_raspberry_addons/raspberrypi_tree_tests/"

#Creates ssh keys on raspbian and generates SHA256 fingerprints
fingerprints = ssh_keygen(save_to = raspbian_root + "etc/ssh/")
#print(fingerprints)

#Configures the SSH file of raspbian
sshd_config = replace_in_file("file_models/sshd_config", [["Port [0-9]*", "Port 2323"]])
ssh_config_sd_location = raspbian_root + "etc/ssh/sshd_config"
create_file(ssh_config_sd_location, sshd_config)
modify_file_permissions(ssh_config_sd_location, stat.S_IRUSR | stat.S_IWUSR) #Equivalent to 0600. Read: Permissions: https://docs.python.org/3/library/stat.html#stat.S_IRWXU

#SSH service comes deactivated by default on raspibian 
#Raspibian currently uses RC services for SSH, but the startup process is systemd. A compatibility trick is used: https://unix.stackexchange.com/questions/233468/how-does-systemd-use-etc-init-d-scripts
enable_rc_service(raspbian_root, "ssh")

#Configures wifi password
network_ssid = "My_SSID"
network_password = "123456789"
network_proto = "RSN"
network_key_mgmt = "WPA-PSK"
network_pairwise = "CCMP"
network_auth_alg = "OPEN"

create_file(
    raspbian_root + "etc/wpa_supplicant/wpa_supplicant.conf",
    "country=GB\n\
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n\
update_config=1\n\
network = {\n\
    ssid=" + add_quotation(network_ssid) + "\n\
    psk=" + add_quotation(network_password) + "\n\
    proto=" + network_proto + "\n\
    key_mgmt=" + network_key_mgmt + "\n\
    pairwise=" + network_pairwise + "\n\
    auth_alg=" + network_auth_alg + "\n\
}",
    permission = stat.S_IRUSR | stat.S_IWUSR
)