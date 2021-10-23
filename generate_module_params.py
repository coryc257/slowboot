#!/usr/bin/python3

import sys
import os
import fnmatch



if __name__ == '__main__':
	j = 0
	pwd = os.getcwd()
	blacklist = ["slowboot.ko","/var/cache/PackageKit/35/metadata", "/home/", "/usr/lib/systemd/user/app-"]
	

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
	
	os.system("./generate_init_foil.py ./module.param > module.FN")
	os.system("./generate_init_call.py ./module.param > module.SP")
	os.system("./generate_init_setup.py ./module.param > module.ST")
	
	template = open("./slowboot.ct","r")
	t_FN = open("./module.FN","r")
	t_SP = open("./module.SP","r")
	t_ST = open("./module.ST","r")
	fillin = open("./slowboot.c","w")
	t_FN_s = t_FN.read()
	t_FN.close()
	t_SP_s = t_SP.read()
	t_SP.close()
	t_ST_s = t_ST.read()
	t_ST.close()
	tstr = template.read()
	template.close()

	tstr = tstr.replace("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$FN",t_FN_s)
	tstr = tstr.replace("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$SP",t_SP_s)
	tstr = tstr.replace("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ST",t_ST_s)
	
	print(tstr)
	
	exit(0)
				
