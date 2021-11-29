#!/usr/bin/python3

import sys
import os
import tempfile
import shutil

if __name__ == '__main__':
	if len(sys.argv) != 3:
		print(sys.argv[0] + " <initramfs file> <output file>")
		exit(1)

	p_initramfs_file = sys.argv[1]
	p_output_file = sys.argv[2]
	
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

	os.system("find ./ -type f -executable -exec sha512sum {} \\; | awk '{print $1,substr($2,2);}' > \""+pwd+"/init.param\"")
	os.system("find ./ -type f -name *.ko -exec sha512sum {} \\; | awk '{print $1,substr($2,2);}' >> \""+pwd+"/init.param\"")
	
	shutil.rmtree(td)
	os.chdir(pwd)
	os.system("mv \""+pwd+"/init.param\" \""+p_output_file+"\"")
	
	exit(0)