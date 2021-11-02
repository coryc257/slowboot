#!/usr/bin/python3

import sys
import os

def generate_output(ct):
	print("#define LD_MASTER_CT "+str(ct))

if __name__ == '__main__':
	j = 0
	with open(sys.argv[1]) as f:
		ls = f.readlines()
		generate_output(len(ls))
