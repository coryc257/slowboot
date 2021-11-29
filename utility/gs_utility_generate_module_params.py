#!/usr/bin/python3

import sys
import os
import fnmatch



if __name__ == '__main__':
	
	if len(sys.argv) != 2:
		print(sys.argv[0] + " <output file>")

	f_slowboot_file = sys.argv[1]
	j = 0
	pwd = os.getcwd()
	blacklist = ["/usr/lib/modules/5.14.0-60.fc35.x86_64","/usr/lib/modules/5.14.12-300.fc35.x86_64","/usr/lib/modules/5.14.13+","vmlinuz", "slowboot.ko","/var/cache/PackageKit/35/metadata", "/home/", "/usr/lib/systemd/user/app-","/etc/cups/subscriptions.conf","device-timeout.conf","/mnt/vm"]
	

	#os.remove("./init.param")
	os.system("find / -type f -executable -exec sha512sum {} \; | awk '{print $1,$2;}' > "+pwd+"/slowboot.param.temp")
	os.system("find / -type f -name *.ko -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/slowboot.param.temp")
	os.system("find / -type f -name *.conf -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/slowboot.param.temp")
	os.system("find / -type f -name *.cfg -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/slowboot.param.temp")
	#? configuration files? anything else?
	try:
		os.system("rm " + pwd + "/slowboot.param")
	finally:
		os.system("touch " + pwd + "/slowboot.param")
	f = open(pwd+"/slowboot.param.temp")
	fl = f.readlines()
	f.close()
	
	for l in fl:
		filtered = 0
		for m in blacklist:
			if m in l:
				filtered = 1
		if filtered == 0:
			os.system("printf \"%s\n\" \""+l.strip().replace("\\","\\\\")+"\" >> "+pwd+"/slowboot.param")
			
	os.system("mv \""+pwd+"/slowboot.param\" \""+f_slowboot_file+"\"")
	
	exit(0)
				
