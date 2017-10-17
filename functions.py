import fileinput
import os
import stat
import re #regex
import sys
import paramiko
from hashlib import sha256 #Forget MD5, its broken
import base64
import hashlib, binascii
import crypt

newline = "\n"

#LINUX MODIFYING TOOLS -------------------------------------
def change_user_password(raspbian_root, user=None, password=None): #https://www.aychedee.com/2012/03/14/etc_shadow-password-hash-formats/
    if user and password:
        log("Changing password for user \"" + user + "\"")
        shadow_file_location = raspbian_root + "etc/shadow"
        shadow_file = read_file(shadow_file_location)
        shadow_regex = "(?P<user>" + user + " ):(?P<hash_function>\$\w+\$)(?P<salt>\w+\$)(?P<hash>\w+[^:]+):(\d*):(\d*):(\d*):(\d*):(\d*):(\d*):(\d*)"
        salt = "weuKU796Fef2234"
        password = password
        hashed_password_with_salt = crypt.crypt(password, '$6$' + salt)
        shadow_file = re.sub(shadow_regex, "\g<user>:" + hashed_password_with_salt + ":\5:\6:\7:\8:\9:\10:\11", shadow_file)
        #print(shadow_file)
        create_file(shadow_file_location, shadow_file)
        modify_file_permissions(shadow_file_location, 0o640)
    else:
        log("Something gone wrong while changing password")  

def wpa_psk(ssid, password): #https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access#Target_users_.28authentication_key_distribution.29
	dk = hashlib.pbkdf2_hmac('sha1', str.encode(password), str.encode(ssid), 4096)
	return(binascii.hexlify(dk))

def run_once_at_boot(raspbian_root, commands): #https://raspberrypi.stackexchange.com/a/8083/74564
    log("Adding commands \"" + commands + "\" to run in the first boot")  
    touch(raspbian_root + "/etc/RUNONCEFLAG")
    rc_local = read_file("file_models/rc.local")
    run_once_command = "if [ -e /etc/RUNONCEFLAG ]; then" + newline + commands + newline + "/bin/rm /etc/RUNONCEFLAG" + newline + "fi"
    rc_local = replace(rc_local, [["exit 0", run_once_command + newline + "exit 0"]])
    create_file(raspbian_root + "etc/rc.local", rc_local)

#RC services are old, but raspibian uses a compatiblity trick: https://unix.stackexchange.com/questions/233468/how-does-systemd-use-etc-init-d-scripts 
def disable_rc_service(raspbian_root, service_name, runlevel=None):
    log("Disabling " + service_name + " service")  
    modify_rc_service(raspbian_root, service_name, runlevel, action="disable")
  
def enable_rc_service(raspbian_root, service_name, runlevel=None):
    log("Enabling " + service_name + " service")
    modify_rc_service(raspbian_root, service_name, runlevel, action="enable")
  
def modify_rc_service(raspbian_root, service_name, runlevel=None, action=None):
    for i in range(0,6):
        rc_folder = raspbian_root + "etc/rc"+str(i)+".d/"
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

#SSH KEY GENERATION TOOLS --------------------------------------------
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
        modify_file_permissions(save_to + "ssh_host_" + key + "_key", 0o600)
        f = open(save_to + "ssh_host_" + key + "_key.pub",'w')
        f.write(value.get_name() + " " + value.get_base64() + " " + user + "@" + host)
        f.close()
        modify_file_permissions(save_to + "ssh_host_" + key + "_key.pub", 0o644)
        #f = open( save_to + "ssh_host_" + key + "_key.pub.sha256fingerprint",'w')
        #f.write(sha256_fingerprint(value.asbytes()))
        #f.close()
        fingerprints["sha256"][key] = sha256_fingerprint(value.asbytes())
    
    f = open(save_to + "sha256fingerprints",'w')
    for key_type, fingerprint in fingerprints["sha256"].items():
        f.write(key_type + ": " + fingerprint + "\n")
    f.close()
    
    return fingerprints

#INPUT/OUTPUT TOOLS -------------------------------------
def log(message):
    print(message + "...")

def read_file(path):
    f = open(path,'r')
    filedata = f.read()
    f.close()
    return filedata

def touch(path): #https://stackoverflow.com/a/6222692
    if os.path.exists(path):
        os.utime(path, None)
    else:
        open(path, 'a').close()


def remove_file(path, do_backup=False):
    if do_backup:
        backup_file(path)
    log("Removing file " + path)
    try:
        os.remove(path)
    except:
        log("Something went wrong or file doesn't exist anymore")

#https://stackoverflow.com/a/22876912
def backup_file(path):#Todo: do backup of symlinks. Actually, modify read_file() to always follow symlinks
    log("Creating backup of " + path)
    f = open(path,'r')
    filedata = f.read()
    f.close()
    f = open(path+".backup",'w')
    f.write(newdata)
    f.close()

def is_symlink(path):
    return os.path.islink(path)
      
def list_files(path):
    listOfFiles = [f for f in os.listdir(path) if is_symlink(path.rpartition("/")[0]+"/"+f)]
    return listOfFiles

def modify_file_permissions(file, new_permission):
    log("Modifying permissions of " + file + " to " + oct(new_permission))
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

def replace(content, rules):
    for rule in rules:
        #https://stackoverflow.com/a/1687663
        content = re.sub(re.compile('^(?!#)' + rule[0] + '$', re.MULTILINE), rule[1], content, 0)
    return content

def add_quotation(string):
    return "\"" + string + "\""
