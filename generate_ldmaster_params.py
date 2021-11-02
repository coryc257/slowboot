#!/usr/bin/python3

import sys
import os
import fnmatch



if __name__ == '__main__':
	j = 0
	pwd = os.getcwd()
	blacklist = ["/proc","/mnt","/home", "/var", "/run", "/media", "/boot", ".cfg", ".conf", "/usr/sbin/nc", "/etc/alternatives/nc"]
	whitelist = ["ld-linux"]
	

	#os.remove("./init.param")
	os.system("find /lib/ -type f -name \"*.so\" -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' > "+pwd+"/ldm.param.temp")
	os.system("find /lib/ -type f -name \"*.so.*\" -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/ldm.param.temp")
	os.system("find /lib64/ -type f -name \"*.so\" -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' > "+pwd+"/ldm.param.temp")
	os.system("find /lib64/ -type f -name \"*.so.*\" -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/ldm.param.temp")
	#os.system("find /etc/ -type f -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	#os.system("find /lib/ -type f -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	#os.system("find /lib64/ -type f -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	#os.system("find /opt/ -type f -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	#os.system("find /usr/ -type f -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	############
	os.system("find /lib/ -type l -name \"*.so\" -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/ldm.param.temp")
	os.system("find /lib/ -type l -name \"*.so.*\" -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/ldm.param.temp")
	os.system("find /lib64/ -type l -name \"*.so\" -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/ldm.param.temp")
	os.system("find /lib64/ -type l -name \"*.so.*\" -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/ldm.param.temp")
	#os.system("find /bin/ -type l -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	#os.system("find /etc/ -type l -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	#os.system("find /lib/ -type l -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	#os.system("find /lib64/ -type l -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	#os.system("find /opt/ -type l -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	#os.system("find /usr/ -type l -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	############
	#os.system("find / -type f -name \"*ld-linux*.so*\" 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	#os.system("find / -type l -name \"*ld-linux*.so*\" 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	#os.system("sha512sum /usr/bin/sudo | awk '{print $1,$2;}' > "+pwd+"/exec.param.temp")	
	#? configuration files? anything else?
	try:
		os.system("rm " + pwd + "/ldm.param")
	finally:
		os.system("touch " + pwd + "/ldm.param")
	f = open(pwd+"/ldm.param.temp")
	fl = f.readlines()
	f.close()
	
	for l in fl:
		filtered = 0
		for m in blacklist:
			if m in l:
				filtered = 1
				for w in whitelist:
					if w in l:
						filtered = 0
		if filtered == 0:
			os.system("printf \"%s\n\" \""+l.strip().replace("\\","\\\\")+"\" >> "+pwd+"/ldm.param")
	
	#TODO, remake module.param removing items from a blacklist
	
	os.system("./generate_ldmaster_foil.py ./ldm.param > ldm.FN")
	os.system("./generate_ldmaster_call.py ./ldm.param > ldm.SP")
	os.system("./generate_ldmaster_setup.py ./ldm.param > ldm.ST")
	os.system("./generate_ldmaster_data.py ./ldm.param > ldm.DT")
	
	template = open("./template_ldmaster.c","r")
	t_FN = open("./ldm.FN","r")
	t_SP = open("./ldm.SP","r")
	t_ST = open("./ldm.ST","r")
	t_DT = open("./ldm.DT","r")
	#fillin = open("./exec_control.c","w")
	t_FN_s = t_FN.read()
	t_FN.close()
	t_SP_s = t_SP.read()
	t_SP.close()
	t_ST_s = t_ST.read()
	t_ST.close()
	t_DT_s = t_DT.read()
	t_DT.close()
	tstr = template.read()
	template.close()

	#tstr = tstr.replace("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$FN",t_FN_s)
	#tstr = tstr.replace("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$SP",t_SP_s)
	tstr = tstr.replace("//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ST",t_ST_s)
	tstr = tstr.replace("//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$DT",t_DT_s)
	
	print(tstr)
	
	exit(0)
				
