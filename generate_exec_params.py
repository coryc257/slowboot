#!/usr/bin/python3

import sys
import os
import fnmatch



if __name__ == '__main__':
	j = 0
	pwd = os.getcwd()
	blacklist = ["/proc","/mnt","/home", "/var", "/run", "/media", "/boot", ".cfg", ".conf", "/usr/sbin/nc", "/etc/alternatives/nc", ".so"]
	whitelist = ["ld-linux"]
	

	#os.remove("./init.param")
	os.system("find / -type f -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' > "+pwd+"/exec.param.temp")
	os.system("find / -type l -executable 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	os.system("find / -type f -name \"*ld-linux*.so*\" 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")
	os.system("find / -type l -name \"*ld-linux*.so*\" 2>/dev/null -exec sha512sum {} \; | awk '{print $1,$2;}' >> "+pwd+"/exec.param.temp")	
	#? configuration files? anything else?
	try:
		os.system("rm " + pwd + "/exec.param")
	finally:
		os.system("touch " + pwd + "/exec.param")
	f = open(pwd+"/exec.param.temp")
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
			os.system("printf \"%s\n\" \""+l.strip().replace("\\","\\\\")+"\" >> "+pwd+"/exec.param")
	
	#TODO, remake module.param removing items from a blacklist
	
	os.system("./generate_exec_foil.py ./exec.param > exec.FN")
	os.system("./generate_exec_call.py ./exec.param > exec.SP")
	os.system("./generate_exec_setup.py ./exec.param > exec.ST")
	os.system("./generate_exec_data.py ./exec.param > exec.DT")
	
	template = open("./template_exec_control.c","r")
	t_FN = open("./exec.FN","r")
	t_SP = open("./exec.SP","r")
	t_ST = open("./exec.ST","r")
	t_DT = open("./exec.DT","r")
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
	tstr = tstr.replace("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ST",t_ST_s)
	tstr = tstr.replace("//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$DT",t_DT_s)
	
	print(tstr)
	
	exit(0)
				
