#!/usr/bin/python3

import sys
import os

if __name__ == '__main__':
	j = 0
	pwd = os.getcwd()

	#os.remove("./init.param")
	os.system("find / -type f -executable -exec sha512sum {} \; | awk '{print $1,$2;}' > "+pwd+"/module.param")
	os.system("find / -type f -name *.ko -exec sha512sum {} \; | awk '{print $1,$2;}' > "+pwd+"/module.param")
	#? configuration files? anything else?
	
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
				
