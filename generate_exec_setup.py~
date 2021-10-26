#!/usr/bin/python3

import sys
import os

def generate_output(ct):
	print("typedef struct slowboot_tinfoil {")
	print("\tstruct kstat *st;")
	print("\tslowboot_validation_item validation_items["+str(ct)+"];")
	print("\tint failures;")
	print("} slowboot_tinfoil;")

if __name__ == '__main__':
	j = 0
	with open(sys.argv[1]) as f:
		ls = f.readlines()
		generate_output(len(ls))
