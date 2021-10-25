#!/usr/bin/python3

import sys
import os

def generate_output(h,f,j):
	print("static void svir_"+str(j+1)+"(void) \n{")
	print("\tsvi_reg(&(tinfoil.validation_items["+str(j)+"]),")
	print("\t        \""+h.replace("\\","\\\\")+"\",")
	print("\t        \""+f+"\"")
	print("\t);\n}")

if __name__ == '__main__':
	j = 0
	with open(sys.argv[1]) as f:
		for l in f.readlines():
			
			h = l[0:128]
			f = ((l[129:],l[130:])[l[129] == "."]).strip()
			generate_output(h,f,j)
			j = j + 1
				
