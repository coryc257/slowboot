#!/usr/bin/python3

import sys
import os
import tempfile
import shutil

def generate_output(h,f,j):
	print("static void svir_"+str(j+1)+"(void) \n{")
	print("\tsvi_reg(&(tinfoil.validation_items["+str(j)+"]),")
	print("\t        \""+h+"\",")
	print("\t        \""+f+"\"")
	print("\t);\n}")

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
	os.system("find ./ -type f -exec sha512sum {} \\; | awk '{print $1,$2;}' > "+pwd+"/init.param")
	#shutil.copyfile("./init.param",pwd+"/init.param")	
	shutil.rmtree(td)
	os.chdir(pwd)
	
	os.system("./generate_init_foil.py ./init.param > init.FN")
	os.system("./generate_init_call.py ./init.param > init.SP")
	os.system("./generate_init_setup.py ./init.param > init.ST")
	
	template = open("./slowboot.ct","r")
	t_FN = open("./init.FN","r")
	t_SP = open("./init.SP","r")
	t_ST = open("./init.ST","r")
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
	
	with open(sys.argv[1]) as f:
		for l in f.readlines():
			h = os.popen("sha512sum "+l.strip() + " | awk '{print $1;}'").read().strip()
			f = l.strip()
			generate_output(h,f,j)
			j = j + 1
				
