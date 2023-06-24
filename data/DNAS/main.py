#!/bin/env python3

import os
from sympy.ntheory.factor_ import smoothness_p, pollard_pm1
from sympy import *

def readModulo(file_path):
	with open(file_path, mode="rb") as f:
		return int.from_bytes(f.read(), byteorder='big')
	return -1

def readExponent(file_path):
	with open(file_path, mode="rb") as f:
		return int.from_bytes(f.read(), byteorder='big')
	return -1

def readSignature(file_path):
	with open(file_path, mode="rb") as f:
		f.read(0x48)
		
		return int.from_bytes(f.read(0x80), byteorder='big')
	return -1


def testModulos(modulos):
	g = 1;
	for modulo in modulos:
		## Test A: common factors
		d = gcd(g, modulo)
		
		if(d != 1):
			print(modulo)
			print(d)
		
		g *= modulo
		
		## Test B: check if modulo has small factors
		v = pollard_pm1(modulo, B=100000)
		if(v != None):
			print(v)

def getCollectedSignatures():
	root_dir = '../packets/00'
	
	signatures = []
	
	for dir_path, _, file_names in os.walk(root_dir):
		for file_name in file_names:
			file_path = "{}/{}".format(dir_path, file_name)
			
			signature = readSignature(file_path)
			
			signatures.append(signature)
	
	return signatures

def main():
	modulos = []
	signatures = getCollectedSignatures()
	
	root_dir = "./"
	game_names = [name for name in os.listdir(root_dir) if os.path.isdir(os.path.join(root_dir, name)) and name != "patch"]
	game_names.sort() 
	
	for game_name in game_names:
		print("{}:".format(game_name))
		
		game_path = "{}{}/".format(root_dir, game_name)
		game_versions = [name for name in os.listdir(game_path) if os.path.isdir(os.path.join(game_path, name))]
		
		for game_version in game_versions:
			print("	{}:".format(game_version))
			
			version_path = "{}{}/".format(game_path, game_version)
			
			n = readModulo(version_path + "modulo")
			e = readExponent(version_path + "exponent")
			
			modulos.append(n)
			
			print("		n      : {}".format(n))
			print("		e      : {}".format(e))
			
			for signature in signatures:
				message = hex(pow(signature, e, n))
				
				#if(message.startswith('0x1ffffffffffffffff')):
				if(message.startswith('0x1fffffffff')):
					print("		sig      : {}".format(signature))
					print("		sig (hex): {}".format(hex(signature)))
					print("		message  : {}".format(message))
				
		print("----------------------------------")
	
	## Do tests
	#testModulos(modulos)

main()