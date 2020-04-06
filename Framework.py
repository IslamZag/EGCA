import socket,sys,os,time,pyshark,urllib,requests,re 
from prettytable import *
from urllib.request import urlopen
from urllib.parse import urlsplit
from bs4 import BeautifulSoup

b = PrettyTable()
b.field_names = ["Function", "Selection number"]
b.add_row(["For IP/Port Scanning", 1])
b.add_row(["For Network sniffer", 2])
b.add_row(["To Cracking password using Johny", 3])
b.add_row(["To Collect Email/phones/URLs from a given URL", 4])
b.add_row(["For vulnerability scanner on given IP", 5])
b.add_row(["To display running services on a given host", 6])
print(b)

def mainfun():
	x = input('Enter your selection here:\n')
	print ('You entered %s' %(x))
	if x == '1': Task_1()
	elif x == '2': Task_2()
	elif x == '3': Task_3()
	elif x == '4': Task_4()
	elif x == '5': Task_5()
	elif x == '6': Task_6()
	else: print('Enter a valid number')

def Task_1():
	ip = input('Enter the ip to scan\n')
	port = input('Enter the port to scan\n')

	command1 = "nmap -sA -p %s %s --system-dns > temp.txt" %(port, ip)
	command2 = "nmap -sX -p %s %s --system-dns > temp.txt" %(port, ip)
	command3 = "nmap -sF -p %s %s --system-dns > temp.txt" %(port, ip)
	command3 = "nmap -sN -p %s %s --system-dns > temp.txt" %(port, ip)

	print ("Ack_scanner output")
	print ("------------------")
	try:
		os.popen(command1)
	except: pass

	f = open ("temp.txt", "r")
	for x in f:
		if x.startswith('Starting'): continue
		print(f.read())
	time.sleep(2)

	print ("xmass_scanner output")
	print ("--------------------")
	try:
		os.popen(command2)
	except:
		pass
	f = open ("temp.txt", "r")
	print(f.read())
	time.sleep(2)

	print ("Fin_scanner output")
	print ("------------------")
	try:
		os.popen(command3)
	except:
		pass
	f = open ("temp.txt", "r")
	print(f.read())
	time.sleep(2)

	print ("SYN_scanner output")
	print ("------------------")
	try:
		os.popen(command4)
	except:
		pass
	f = open ("temp.txt", "r")
	print(f.read())
	time.sleep(2)
	exit(0)

def Task_2():
	cap = pyshark.LiveCapture(interface='eth0', output_file='./output.pcap')
	cap.sniff(packet_count=10)

def Task_3():
	import socket,sys,os,time
	file1 = input('Enter the MD5 hash file\n')
	file2 = input('Enter the wordlist file\n')

	command = "john --format=raw-md5 --wordlist=%s %s > cmdout.txt" %(file2, file1)
	print(command)
	os.popen(command)
	time.sleep(5)


	fhand = open ('cmdout.txt')
	print (fhand)
	for line in fhand:
		line = line.rstrip()
		if line.startswith('Loaded'): continue
		if line.startswith('No'): 
			os.system('clear')
			print('that password was detected previously kindly check /root/.john/*.pot')
			exit()
		words = line.split()
		os.system('clear')
		print('password:',words[0])
	exit()

def Task_4():
	x = PrettyTable()
	x.field_names = ["Email", "phones", "URLs"]
	#x.add_row(["cairo", 2, 1])
	#print(x)

	link = input('Enter URL\n')

	page = requests.get(link)
	soup = BeautifulSoup(page.content, 'html.parser')

	emails = set()
	phones = set()
	other_links = set()



	new_email = set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", page.text,re.I))
	emails.update(new_email)


	for Email in emails:
		x.add_row([Email,0,0])
	print(x)

	new_phone = set(re.findall(r"tel:[0-9]+", page.text,re.I))
	phones.update(new_phone)

	for phone in phones:
		x.add_row([0,phone,0])
	print(x)

	new_link = set(re.findall(r"https://[a-z0-9\.\-+_]+\.[a-z]+", page.text,re.I))
	other_links.update(new_link)

	for new in other_links:
		x.add_row([0,0,new])
	print(x)

	x.add_row([emails,phones,other_links])
	print(x)

def Task_5():
	ip = input('Enter the ip to scan\n')
	port = input('Enter the port to scan\n')

	command1 = "nmap -sV -p22 %s --system-dns > temp.txt" %(ip)
	command2 = "nmap --script nmap-vulners,vulscan -sV -p%s %s --system-dns > temp.txt" %(port, ip)

	print ("---Nmap version---")
	print ("------------------")
	try:
		os.popen(command1)
	except: pass
	f = open ("temp.txt", "r")
	print(f.read())
	time.sleep(2)

	print ("---Nmap scan using both nmap-vulners and vulscan---")
	print ("---------------------------------------------------")
	try:
		os.popen(command2)
	except: pass
	f = open ("temp.txt", "r")
	print(f.read())
	time.sleep(2)

	exit(0)

def Task_6():
	x = PrettyTable()
	counts =dict()
	x.field_names = ["Opened Port", "Service", "Version"]

	ip = input('Enter the ip to scan\n')
	port1 = input('Enter the starting port range\n')
	port2 = input('Enter the ending port range\n')

	command = "nmap -sV -O -p%s-%s %s --system-dns > temp.txt" %(port1, port2, ip)

	try:
		os.popen(command)
	except:
		pass


	fhand = open ('temp.txt')
	for line in fhand:
		
#		print (line)
		line = line.rstrip()
		if line.find('open') == -1: continue 	
		if line.startswith('Warning'): 
			print ('Host Down OR No open ports')
			exit(0)
		words = line.split()
		x.add_row([words[0],words[2],words[3]])

	print (x)


mainfun()