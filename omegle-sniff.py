#!/usr/bin/python3
import os
import sys
import requests
import pyshark
import socket
import signal
import json

API_KEY = 'YOUR_API_KEY'
my_ip = [(s.connect(('1.1.1.1', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
path = os.path.dirname(os.path.abspath(__file__))

def clear():
	if os.name == 'nt':
		os.system('cls')
	else:
		os.system('clear')

def style(text,style):
    if style == 'black':
        return f'\033[0;30m{text}\033[0m'
    elif style == 'red':
        return f'\033[0;31m{text}\033[0m'
    elif style == 'green':
        return f'\033[0;32m{text}\033[0m'
    elif style == 'yellow':
        return f'\033[1;33m{text}\033[0m'
    elif style == 'blue':
        return f'\033[0;34m{text}\033[0m'
    elif style == 'purple':
        return f'\033[0;35m{text}\033[0m'
    elif style == 'cyan':
        return f'\033[0;36m{text}\033[0m'
    elif style == 'white':
        return f'\033[1;37m{text}\033[0m'
    else:
        return text

def ipinfo(ip):
	r = requests.get(f'https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={ip}')
	response = r.json()
	return response

def save(ip,pid):
	filepath = os.path.join(path,'strangers.json')
	with open(filepath,'r') as f:
		master_data = json.load(f)
	nickname = input(f'Nickname for {ip}: ')
	data = {ip: nickname}
	master_data.append(data)
	print(style(f'Saving {nickname} to {filepath}...','green'))
	with open(filepath,'w') as f:
		f.write(json.dumps(master_data))
	action = input('[C]ontinue/[Q]uit: ').upper()
	if action == 'C':
		main()
	elif action == 'Q':
		print(style('Exiting...'),'red')
		os.kill(pid, signal.SIGTERM)

def search(ip):
	filepath = os.path.join(path,'strangers.json')
	with open(filepath,'r') as f:
		master_data = json.load(f)
	for stranger in master_data:
		if ip in stranger:
			return stranger[ip]
	return None

def main():
	try:
		pid = os.getpid()
		clear()
		banner = '''
 ██████╗ ███╗   ███╗███████╗ ██████╗ ██╗     ███████╗    ███████╗███╗   ██╗██╗███████╗███████╗
██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██║     ██╔════╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝
██║   ██║██╔████╔██║█████╗  ██║  ███╗██║     █████╗      ███████╗██╔██╗ ██║██║█████╗  █████╗
██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██║     ██╔══╝      ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝
╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝███████╗███████╗    ███████║██║ ╚████║██║██║     ██║
 ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝
			'''
		print(style(banner,'red'))
		print(style('Listening for connections...','yellow'))
		last_ip = ''
		stranger_ip = ''
		# f'ip.src == {my_ip} && !(ip.dst == 10.0.0.0/8) && !(ip.dst == 192.168.0.0/16) && !(ip.dst == 127.0.0.0/8) && dtls && udp'
		capture = pyshark.LiveCapture(display_filter=f'ip.src == {my_ip} && !(ip.dst == 10.0.0.0/8) && !(ip.dst == 192.168.0.0/16) && !(ip.dst == 127.0.0.0/8) && dtls')
		for packet in capture.sniff_continuously():
			stranger_ip = packet['ip'].dst
			while stranger_ip != last_ip or last_ip == '':
				last_ip = stranger_ip
				header = '\n' + '='*10 + style(stranger_ip,'green') + '='*10
				print(header)
				print(style('Nickname:','green'), search(stranger_ip))
				ip_info = ipinfo(stranger_ip)
				print(style('Country:','green'), ip_info['country_name'])
				print(style('State:','green'), ip_info['state_prov'])
				print(style('City:','green'), ip_info['city'])
				print(style('ISP:','green'), ip_info['isp'])
				google_maps = 'https://www.google.com/maps/@' + ip_info['latitude'] + ',' + ip_info['longitude'] + ',12z'
				print(style('Map:','green'), style(google_maps,'cyan'))
	except KeyboardInterrupt:
		try:
			option = input('[C]ontinue/[S]ave/[Q]uit: ').upper()
			if option == 'C' or option == 'CONTINUE' or option == 'CONT':
				main()
			elif option == 'S' or option == 'SAVE':
				save_ip = stranger_ip
				save(save_ip,pid)
				
			elif option == 'Q' or option == 'QUIT':
				print(style('Exiting...','red'))
				os.kill(pid, signal.SIGTERM)
			else:
				print(style('Exiting...','red'))
				os.kill(pid, signal.SIGTERM)
		except:
			print(style('\nExiting...','red'))
			os.kill(pid, signal.SIGTERM)
			
if __name__ == '__main__':
	main()
