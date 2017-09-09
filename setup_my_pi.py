#!/usr/bin/env python3
#Lucas Zanella
#Automatic wifi, shh, etc setup of a recently burned raspibian SD image

from functions import * #file editing, ssh generation and other functions

#----------BEGIN USER SCRIPT----------
#Where is your SD card with Raspbian image located?
raspbian_root = "/home/lucas/Coding/zanella_raspberry_addons/raspberrypi_tree_tests/"

#Creates ssh keys on raspbian and generates SHA256 fingerprints
fingerprints = ssh_keygen(save_to = raspbian_root + "etc/ssh/")
print(fingerprints)

#Configures the SSH file of raspbian
sshd_config = replace_in_file("file_models/sshd_config", [["Port [0-9]*", "Port 2323"]])
create_file(raspbian_root + "etc/ssh/sshd_config", sshd_config)

#Configures wifi password
network_ssid = "My_SSID"
network_password = "123456789"
network_proto = "RSN"
network_key_mgmt = "WPA-PSK"
network_pairwise = "CCMP"
network_auth_alg = "OPEN"

create_file(
    raspbian_root + "etc/wpa_supplicant/wpa_supplicant.conf",
    "network = {\n\
    ssid=" + add_quotation(network_ssid) + "\n\
    psk=" + add_quotation(network_password) + "\n\
    proto=" + network_proto + "\n\
    key_mgmt=" + network_key_mgmt + "\n\
    pairwise=" + network_pairwise + "\n\
    auth_alg=" + network_auth_alg + "\n\
}"
)
