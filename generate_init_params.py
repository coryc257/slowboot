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
	os.system("find ./ -type f -exec sha512sum {} \\; | awk '{print $1,$2;}' > init.param")
	shutil.copyfile("./init.param",pwd+"/init.param")	
	shutil.rmtree(td)
	os.chdir(pwd)
	
	os.system("./generate_init_foil.py ./init.param > init.FN")
	os.system("./generate_init_call.py ./init.param > init.SP")
	os.system("./generate_init_setup.py ./init.param > init.ST")
	exit(0)
	
	with open(sys.argv[1]) as f:
		for l in f.readlines():
			h = os.popen("sha512sum "+l.strip() + " | awk '{print $1;}'").read().strip()
			f = l.strip()
			generate_output(h,f,j)
			j = j + 1
				
