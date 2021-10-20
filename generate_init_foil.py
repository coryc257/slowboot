#!/usr/bin/python3

import sys
import os

def generate_output(h,f,j):
	print("static void svir_"+str(j+1)+"(void) \n{")
	print("\tsvi_reg(&(tinfoil.validation_items["+str(j)+"]),")
	print("\t        \""+h+"\",")
	print("\t        \""+f+"\"")
	print("\t);\n}")

if __name__ == '__main__':
	j = 0
	with open(sys.argv[1]) as f:
		for l in f.readlines():
			h = os.popen("sha512sum "+l.strip() + " | awk '{print $1;}'").read().strip()
			f = l.strip()
			generate_output(h,f,j)
			j = j + 1
				
