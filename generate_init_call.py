#!/usr/bin/python3

import sys
import os

def generate_output(j):
	print("\tsvir_"+str(j+1)+"();")

if __name__ == '__main__':
	j = 0
	with open(sys.argv[1]) as f:
		ls = f.readlines()
		print("\tint validation_count = " +str(len(ls)) +";")
		for l in ls:
			generate_output(j)
			j = j + 1
				
