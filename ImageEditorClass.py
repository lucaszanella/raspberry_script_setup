import fileinput
import os
import stat
import re #regex
import sys
import paramiko
from hashlib import sha256 #Forget MD5 and SHA1, they're broken
import base64
import hashlib, binascii
import crypt

from io_utils import *

newline = "\n"

class ImageEditor:
	def __init__(self, raspbian_root):
	    self.raspbian_root = raspbian_root

	#https://www.aychedee.com/2012/03/14/etc_shadow-password-hash-formats/ #https://repl.it/MloY
	def change_user_password(self, user=None, password=None): 
	    if user and password:
		log("Changing password for user \"" + user + "\"")
		shadow_file_location = self.raspbian_root + "etc/shadow"
		shadow_file = read_file(shadow_file_location)
		shadow_regex = "(?P<user>" + user + "):(?P<hash_function>\$\w+\$)(?P<salt>\w+\$)(?P<hash>\w+[^:]+):(\d*):(\d*):(\d*):(\d*):(\d*):(\d*):(\d*)"
		salt = "weuKU796Fef2234"
		hashed_password_with_salt = crypt.crypt(password, '$6$' + salt)
		#print("hashed_password_with_salt: " + hashed_password_with_salt)
		shadow_file = re.sub(shadow_regex, r"\g<user>:" + hashed_password_with_salt + r":\5:\6:\7:\8:\9:\10:\11", shadow_file)
		#print(shadow_file)
		create_file(shadow_file_location, shadow_file)
		modify_file_permissions(shadow_file_location, 0o640)
	    else:
		log("Something gone wrong while changing password")  

	#https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access#Target_users_.28authentication_key_distribution.29
	def wpa_psk(ssid, password):
		dk = hashlib.pbkdf2_hmac('sha1', str.encode(password), str.encode(ssid), 4096)
		return(binascii.hexlify(dk))

	#https://raspberrypi.stackexchange.com/a/8083/74564
	def run_once_at_boot(self, commands):
	    log("Adding commands \"" + commands + "\" to run in the first boot")  
	    touch(self.raspbian_root + "/etc/RUNONCEFLAG")
	    rc_local = read_file("file_models/rc.local")
	    run_once_command = "if [ -e /etc/RUNONCEFLAG ]; then" + newline + commands + newline + "/bin/rm /etc/RUNONCEFLAG" + newline + "fi"
	    rc_local = replace(rc_local, [["exit 0", run_once_command + newline + "exit 0"]])
	    create_file(self.raspbian_root + "etc/rc.local", rc_local)

	def sha256_fingerprint(bytes):
	    return base64.b64encode(sha256(bytes).digest()).decode("utf-8")

	def ssh_keygen(self, save_to="etc/ssh/", password=None, user="root", host="raspberrypi"):
	    keys = {}
	    fingerprints = {"sha256": {}}
	    rsa_key_bits = 4096
	    dsa_key_bits = 2048
	    ecdsa_key_bits = 521
	    log("Generating " + str(rsa_key_bits) + " RSA key")
	    keys["rsa"] = paramiko.RSAKey.generate(rsa_key_bits)
	    log("Generating " + str(dsa_key_bits) + " DSA key")
	    keys["dsa"] = paramiko.DSSKey.generate(2048)
	    log("Generating " + str(ecdsa_key_bits) + " ECDSA key")
	    keys["ecdsa"] = paramiko.ECDSAKey.generate(bits=521)

	    for key, value in keys.items():
		make_path(self.raspbian_root + save_to)
		f = open(self.raspbian_root + save_to + "ssh_host_" + key + "_key",'w')
		value.write_private_key(f)
		f.close()
		modify_file_permissions(self.raspbian_root + save_to + "ssh_host_" + key + "_key", 0o600)
		f = open(save_to + "ssh_host_" + key + "_key.pub",'w')
		f.write(value.get_name() + " " + value.get_base64() + " " + user + "@" + host)
		f.close()
		modify_file_permissions(self.raspbian_root + save_to + "ssh_host_" + key + "_key.pub", 0o644)
		#f = open(self.raspbian_root + save_to + "ssh_host_" + key + "_key.pub.sha256fingerprint",'w')
		#f.write(sha256_fingerprint(value.asbytes()))
		#f.close()
		fingerprints["sha256"][key] = sha256_fingerprint(value.asbytes())
	    
	    f = open(self.raspbian_root + save_to + "sha256fingerprints",'w')
	    for key_type, fingerprint in fingerprints["sha256"].items():
		f.write(key_type + ": " + fingerprint + "\n")
	    f.close()
	    
	    return fingerprints
	def add_new_wifi_network(self, 
				network_ssid = "LucasZanella.com"
				network_password = "risadaenviarcolunafevereirodescobrirpequeno"
				country = "BR"
				network_proto = "RSN"
				network_key_mgmt = "WPA-PSK"
				network_pairwise = "CCMP"
				network_auth_alg = "OPEN"):
		if network_ssid and network_password and country:
			self.create_file(
			    "etc/wpa_supplicant/wpa_supplicant.conf",
			    "country=" + country + newline +
			    "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev" + newline +
			    "update_config=1" + newline + 
			    "network={" + newline +
			    "    ssid=" + add_quotation(network_ssid) + newline +
			    "    psk=" + add_quotation(network_password) + newline +
			    "}",
			    permission=0o600
			)
		else:
			log("\"network_ssid\", \"network_password\" and \"country\" are mandatory")
	
	#Wrappers for io utils inside the tree that this ImageEditor is editing
	#Yeah, I could do it with an interation through the functions of io_utils.py,
	#but this code is meant to be readable by everyone :)
	def read_file(self, path): read_file(self.raspbian_root + path)

	def touch(self, path): touch(self.raspbian_root + path)

	def remove_file(self, path, do_backup=False): remove_file(self.raspbian_root + path, do_backup)

	def backup_file(self, path): backup_file(self.raspbian_root + path)

	def is_symlink(self, path): is_symlink(self.raspbian_root + path)

	def list_files(self, path): list_files(self.raspbian_root + path)

	def modify_file_permissions(self, path, new_permission): modify_file_permissions(self.raspbian_root + path, new_permission)

	def rename_file(self, path, new_name): rename_file(self.raspbian_root + path, new_name)

	def create_file(self, path, content, permission=None): create_file(self.raspbian_root + path, content, permission)

	def edit_file(self, path, rules, backup=True): edit_file(self.raspbian_root + path, rules, backup)

	def make_path(self, path): make_path(self.raspbian_root + path)


'''
	#Old code
	#Messing with rc_services directly was a mess, it's better to use update-rc in the first boot
	#RC services are old, but raspibian uses a compatiblity trick: https://unix.stackexchange.com/questions/233468/how-does-systemd-use-etc-init-d-scripts 
	def disable_rc_service(self, service_name, runlevel=None):
	    log("Disabling " + service_name + " service")  
	    modify_rc_service(self.raspbian_root, service_name, runlevel, action="disable")
	  
	def enable_rc_service(self, service_name, runlevel=None):
	    log("Enabling " + service_name + " service")
	    modify_rc_service(self.raspbian_root, service_name, runlevel, action="enable")
	  
	def modify_rc_service(self, service_name, runlevel=None, action=None):
	    for i in range(0,6):
		rc_folder = self.raspbian_root + "etc/rc"+str(i)+".d/"
		for file in list_files(rc_folder):
		    #print(file)
		    if re.match('[SK][0-9][0-9]' + service_name, file):
		        if runlevel: 
		            number = runlevel
		        else:
		            number = file[1:3]
		        if action=="enable":
		            rename_file(rc_folder + file, "S" + number + service_name)
		            log(service_name + " enabled in folder " + "etc/rc"+str(i)+".d/")
		        elif action=="disable":
		            rename_file(rc_folder + file, "K" + file[1:3] + service_name)
		            log(service_name + " disabled in folder " + "etc/rc"+str(i)+".d/")

	#def from_file_replace(file, rules):
	#    log("Replacing content of  " + file + " with rules " + str(rules))    
	#    return replace(read_file(file), rules)
'''
