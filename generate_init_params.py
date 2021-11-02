#!/usr/bin/python3

import sys
import os
import tempfile
import shutil

if __name__ == '__main__':
	j = 0
	td = tempfile.mkdtemp()
	f = sys.argv[1]
	fp = os.path.split(f)
	t = td+"/"+fp[1]
	pwd = os.getcwd()

	os.chdir(td)
	
	shutil.copyfile(f,t)
	os.system("lsinitrd --unpack ./"+fp[1])
	os.remove(t)

	#os.remove("./init.param")
	os.system("find ./ -type f -executable -exec sha512sum {} \\; | awk '{print $1,$2;}' > "+pwd+"/init.param")
	os.system("find ./ -type f -name *.ko -exec sha512sum {} \\; | awk '{print $1,$2;}' >> "+pwd+"/init.param")
	#shutil.copyfile("./init.param",pwd+"/init.param")	
	shutil.rmtree(td)
	os.chdir(pwd)
	
	#os.system("./generate_init_foil.py ./init.param > init.FN")
	#os.system("./generate_init_call.py ./init.param > init.SP")
	#os.system("./generate_init_setup.py ./init.param > init.ST")
	
	os.system("./generate_init_count.py ./init.param > init.CT")
	os.system("./generate_init_data.py ./init.param > init.DT")
	
	template = open("./template_slowboot.c","r")
	t_CT = open("./init.CT","r")
	t_DT = open("./init.DT","r")
	
	t_CT_s = t_CT.read()
	t_CT.close()
	t_DT_s = t_DT.read()
	t_DT.close()
	
	#t_FN = open("./init.FN","r")
	#t_SP = open("./init.SP","r")
	#t_ST = open("./init.ST","r")
	#fillin = open("./slowboot.c","w")
	#t_FN_s = t_FN.read()
	#t_FN.close()
	#t_SP_s = t_SP.read()
	#t_SP.close()
	#t_ST_s = t_ST.read()
	#t_ST.close()
	tstr = template.read()
	template.close()

	#tstr = tstr.replace("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$FN",t_FN_s)
	#tstr = tstr.replace("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$SP",t_SP_s)
	#tstr = tstr.replace("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ST",t_ST_s)
	tstr = tstr.replace("//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$CT",t_CT_s)
	tstr = tstr.replace("//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$DT",t_DT_s)
	
	print(tstr)
	
	exit(0)

