import re

def read_file(path):
    f = open(path,'r')
    filedata = f.read()
    f.close()
    return filedata

def replace(content, rules):
    for rule in rules:
        content = re.sub(re.compile(rule[0], re.MULTILINE), rule[1], content, 0)
    return content

sshd_config = read_file("file_models/sshd_config")

sshd_config = replace(sshd_config, [
	      	["^Port [0-9]*", "Port 2323"],
			["^HostKey /etc/ssh/ssh_host_ed25519_key", "#HostKey /etc/ssh/ssh_host_ed25519_key"],
			["^#*\s*PasswordAuthentication \w+", "PasswordAuthentication no"],
			["^#*\s*PubkeyAuthentication \w+", "PubkeyAuthentication yes"]])
sshd_config += "\nAuthorizedKeysFile     %h/.ssh/authorized_keys_2"

print(sshd_config)