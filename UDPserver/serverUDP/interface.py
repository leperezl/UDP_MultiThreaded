#!/usr/bin/env python3
import os

# funcion Clear 
clf = 'clear'
if os.name == 'posix': clf = 'clear'
if os.name == 'nt': clf = 'cls'
clear = lambda: os.system(clf)

# Pantalla principal (text user interface)
def Refresh(ports):
	clear()
	print(' - Python Control Server\n')
	print('Welcome! ' + str(len(ports)) + ' Clients active;\n')
	print('Listening for clients...\n')
	if len(ports) > 0:
		for j in range(0, len(ports)):
			print('[' + str((j)) + '] ClientPort: ' + str(ports[j]) + '\n')
	else:
		print('...\n')
	print('---\n')
	print('Please enter the following information\n')
	print('Desired Clients\n')
	print('File local path\n')
	print('Press Ctrl+C to interact.\n')
	print('------------------------------\n')

# status de clientes
def Status(clients):
	clear()
	print(' - Python Control Server\n')
	print('Welcome! ' + str(len(clients)) + ' Clients active;\n')
	print('---------- Clients -----------\n')
	if len(clients) > 0:
		for j in range(0, len(clients)):
			print('[' + str((j+3)) + '] Client: ' + str(clients[j]) + '\n')
	else:
		print('No clients.\n')
