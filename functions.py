import fileinput
import os
import re #regex
import sys
import paramiko
from hashlib import sha256 #Forget MD5, its broken
import base64

#FILE EDITING TOOLS -------------------------------------
def read_file(path):
    f = open(path,'r')
    filedata = f.read()
    f.close()
    return filedata

#https://stackoverflow.com/a/22876912
def backup_file(path):
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

def replace_in_file(file, rules):
    return replace(read_file(file), rules)

#Creates OR rewrites a file if it exists
def create_file(path, content):
    make_path(path)
    f = open(path,'w')
    f.write(content)
    f.close()

def edit_file(path, rules, backup=True):
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
    print("generating RSA, DSA, ECDSA keys...")
    keys["rsa"] = paramiko.RSAKey.generate(4096)
    keys["dsa"] = paramiko.DSSKey.generate(2048)
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
    f = open(save_to + "fingerprints",'w')
    for key_type, fingerprint in fingerprints["sha256"].items():
        f.write(key_type + ": " + fingerprint + "\n")
    f.close()
    return fingerprints

def add_quotation(string):
    return "\"" + string + "\""

def activate_raspberry_ssh():
    pass