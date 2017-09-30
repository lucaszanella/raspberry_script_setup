import fileinput
import os
import stat
import re #regex
import sys
import paramiko
from hashlib import sha256 #Forget MD5, its broken
import base64
import hashlib, binascii

#FILE EDITING TOOLS -------------------------------------
def log(message):
    print(message + "...")

def read_file(path):
    f = open(path,'r')
    filedata = f.read()
    f.close()
    return filedata

def wpa_psk(ssid, password): #https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access#Target_users_.28authentication_key_distribution.29
	dk = hashlib.pbkdf2_hmac('sha1', str.encode(password), str.encode(ssid), 4096)
	return(binascii.hexlify(dk))

#https://stackoverflow.com/a/22876912
def backup_file(path):
    log("Creating backup of " + path)
    f = open(path,'r')
    filedata = f.read()
    f.close()
    f = open(path+".backup",'w')
    f.write(newdata)
    f.close()

def replace(content, rules):
    for rule in rules:
        #https://stackoverflow.com/a/1687663
        content = re.sub(re.compile('^(?!#)' + rule[0] + '$', re.MULTILINE), rule[1], content, 0)
    return content

def is_symlink(path):
    return os.path.islink(path)
      
def list_files(path):
    listOfFiles = [f for f in os.listdir(path) if is_symlink(path.rpartition("/")[0]+"/"+f)]
    return listOfFiles

#RC services are old, but raspibian uses a compatiblity trick: https://unix.stackexchange.com/questions/233468/how-does-systemd-use-etc-init-d-scripts 
def disable_rc_service(raspbian_root, service_name):
    log("Disabling " + service_name + " service")  
    modify_rc_service(raspbian_root, service_name, action="disable")
  
def enable_rc_service(raspbian_root, service_name):
    log("Enabling " + service_name + " service")
    modify_rc_service(raspbian_root, service_name, action="enable")
  
def modify_rc_service(raspbian_root, service_name, action=None):
    for i in range(0,6):
        rc_folder = raspbian_root + "etc/rc"+str(i)+".d/"
        for file in list_files(rc_folder):
            #print(file)
            if re.match('[SK][0-9][0-9]' + service_name, file):
                if action=="enable":
                    rename_file(rc_folder + file, "S" + file[1:3] + service_name)
                    log(service_name + " enabled in folder " + "etc/rc"+str(i)+".d/")
                elif action=="disable":
                    rename_file(rc_folder + file, "K" + file[1:3] + service_name)
                    log(service_name + " disabled in folder " + "etc/rc"+str(i)+".d/")

def replace_in_file(file, rules):
    log("Replacing content of  " + file + " with rules " + str(rules))    
    return replace(read_file(file), rules)

def modify_file_permissions(file, new_permission):
    log("Modifying permissions from " + file + " to " + str(new_permission))
    os.chmod(file, new_permission) #Read about python permissions nomenclature: https://docs.python.org/3/library/stat.html#stat.S_IRWXU

'''
Usage: 
rename_file("path/to/my/old_file_name", "new_file_name") will change path/to/my/old_file_name to path/to/my/new_file_name
or
rename_file("old_file_name", "new_file_name") will change old_file_name to new_file_name (locally)
'''
def rename_file(file, new_name):
    log("Renaming " + file + " to " + new_name)
    partition = file.rpartition("/") #https://docs.python.org/3/library/stdtypes.html#str.rpartition
    new_file = partition[0] + partition[1] + new_name
    os.rename(file, new_file)
    #print("should rename " + file + " to " + new_file) #https://docs.python.org/3/library/os.html#os.rename

#Creates OR rewrites a file if it exists
def create_file(path, content, permission=None):
    log("Creating " + path)    
    make_path(path)
    f = open(path,'w')
    f.write(content)
    f.close()
    if permission:
        modify_file_permissions(path, permission)

def edit_file(path, rules, backup=True):
    log("Editing " + path)    
    backup_file(path)
    content = replace(read_file(path), rules)
    create_file(path, content)

#https://stackoverflow.com/a/12517490
def make_path(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)

#SSH TOOLS --------------------------------------------
def sha256_fingerprint(bytes):
    return base64.b64encode(sha256(bytes).digest()).decode("utf-8")

def ssh_keygen(save_to="etc/ssh/", password=None, user="root", host="raspberrypi"):
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
        make_path(save_to)
        f = open(save_to + "ssh_host_" + key + "_key",'w')
        value.write_private_key(f)
        f.close()
        f = open(save_to + "ssh_host_" + key + "_key.pub",'w')
        f.write(value.get_name() + " " + value.get_base64() + " " + user + "@" + host)
        f.close()
        #f = open( save_to + "ssh_host_" + key + "_key.pub.sha256fingerprint",'w')
        #f.write(sha256_fingerprint(value.asbytes()))
        #f.close()
        fingerprints["sha256"][key] = sha256_fingerprint(value.asbytes())
    '''
    f = open(save_to + "fingerprints",'w')
    for key_type, fingerprint in fingerprints["sha256"].items():
        f.write(key_type + ": " + fingerprint + "\n")
    f.close()
    '''
    return fingerprints

def add_quotation(string):
    return "\"" + string + "\""
