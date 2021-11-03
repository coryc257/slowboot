#!/usr/bin/python3

import sys
import os
import fnmatch



if __name__ == '__main__':
	j = 0
	pwd = os.getcwd()
	blacklist = ["/usr/lib/modules/5.14.0-60.fc35.x86_64","/usr/lib/modules/5.14.12-300.fc35.x86_64","/usr/lib/modules/5.14.13+","vmlinuz", "slowboot.ko","/var/cache/PackageKit/35/metadata", "/home/", "/usr/lib/systemd/user/app-","/etc/cups/subscriptions.conf","device-timeout.conf","/mnt/vm"]
	

	#os.remove("./init.param")
	os.system("find / -type f -executable -exec sha512sum {} \; | awk '{print $1,$2;}' > "+pwd+"/module.param.temp")
	os.system("find / -type f -name *.ko -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/module.param.temp")
	os.system("find / -type f -name *.conf -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/module.param.temp")
	os.system("find / -type f -name *.cfg -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/module.param.temp")
	#? configuration files? anything else?
	try:
		os.system("rm " + pwd + "/module.param")
	finally:
		os.system("touch " + pwd + "/module.param")
	f = open(pwd+"/module.param.temp")
	fl = f.readlines()
	f.close()
	
	for l in fl:
		filtered = 0
		for m in blacklist:
			if m in l:
				filtered = 1
		if filtered == 0:
			os.system("printf \"%s\n\" \""+l.strip().replace("\\","\\\\")+"\" >> "+pwd+"/module.param")
	
	#TODO, remake module.param removing items from a blacklist
	
	os.system("./generate_init_count.py ./module.param > module.CT")
	os.system("./generate_init_data.py ./module.param > module.DT")
	
	template = open("./template_slowboot.c","r")
	t_CT = open("./module.CT","r")
	t_DT = open("./module.DT","r")
	
	t_CT_s = t_CT.read()
	t_CT.close()
	t_DT_s = t_DT.read()
	t_DT.close()
	
	
	tstr = template.read()
	template.close()

	tstr = tstr.replace("//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$CT",t_CT_s)
	tstr = tstr.replace("//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$DT",t_DT_s)
	
	print(tstr)
	
	exit(0)
				
