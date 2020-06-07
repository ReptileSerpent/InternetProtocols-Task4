import argparse
import socket
import time
import dnslib
import keyboard
import copy
import _thread
import pickle

def remove_expired_entries():
	global dns_cache
	dns_cache_copy = copy.deepcopy(dns_cache)	# otherwise can't pop labels in for loop
	for dns_label in dns_cache:
		dictionary = dns_cache[dns_label]
		should_break = False
		for key in dictionary:
			responses_plus_expiration_time = dns_cache[dns_label][key]
			for entry in dns_cache[dns_label][key]:
				responses, expiration_time = entry
				if (time.time() > expiration_time):
					dns_cache_copy.pop(dns_label, None)
					print(str(dns_label) + " expired. Labels in cache now: " + str(dns_cache_copy.__len__()))
					should_break = True
					break
			if (should_break):
				break

	dns_cache = dns_cache_copy

def look_for_new_service_requests():
	print("Looking for new service requests")
	global dns_cache
	try:
		packet, user_info = service_socket.recvfrom(1024)		# user request
		parsed = dnslib.DNSRecord.parse(packet)
		_thread.start_new_thread(respond_to_service_request, (packet, user_info[0]))

	except Exception:
		pass

def respond_to_service_request(packet, user_address):
	parsed = dnslib.DNSRecord.parse(packet)
	questions = parsed.questions
	reply_for_user = parsed.reply()		# preparing a reply skeleton

	for question in questions:
		if question.qname in dns_cache:
			print (" " + str(question.qname) + " already in cache")
			
			fitting_responses_plus_ttl = dns_cache[question.qname][question.qtype]
			for response, unused_ttl in fitting_responses_plus_ttl:
				reply_for_user.add_answer(response)
		else:
			print(" " + str(question.qname) + " not yet in cache")
			forwarder_socket.sendto(dnslib.DNSRecord.question(question.qname).pack(), (forwarder, 53))

			attempts = 0
			forwarder_response = None
			while (True):
				forwarder_response = look_for_response_from_forwarder(packet)
				time.sleep(0.5)
				if (forwarder_response != "Failure to get response"):
					break

				attempts += 1
				if (attempts > 10):		# timeout
					print("Unable to reply to user, forwarder not responding")
					return

			# the responses should be in the cache by now
			if question.qname in dns_cache:
				fitting_responses_plus_ttl = dns_cache[question.qname][question.qtype]
				for response, unused_ttl in fitting_responses_plus_ttl:
					reply_for_user.add_answer(response)
			else:
				raise Exception("Response from forwarder wasn't found in the cache")	# should never happen

	reply_as_string = str(reply_for_user)

	# send formed reply back to user
	service_socket.sendto(bytes(reply_for_user.pack()), (user_address, 53))
		
	print(" Sent a dns reply to " + user_address)

def look_for_response_from_forwarder(packet):
	global dns_cache
	try:
		packet, unused = forwarder_socket.recvfrom(1024)

		# putting new things into cache
		parsed = dnslib.DNSRecord.parse(packet)
		for question in parsed.rr:
			rr_to_cache = (question, int(time.time()) + question.ttl)
			try:
				dns_cache[question.rname][question.rtype].append(rr_to_cache)
			except KeyError:
				dns_cache[question.rname] = {}
				dns_cache[question.rname].setdefault(question.rtype, [])
				dns_cache[question.rname][question.rtype].append(rr_to_cache)

		print("  Contacting forwarder: success")
		return packet

	except Exception:
		print("  Contacting forwarder: failure")
		return ("Failure to get response")


parser = argparse.ArgumentParser()		# example arguments: dns_cache 1.1.1.1
parser.add_argument("cache_filepath", type=str)
parser.add_argument("forwarder", type=str)
args = parser.parse_args()
cache_filepath = args.cache_filepath
forwarder = socket.gethostbyname(args.forwarder)	# gets the ip

print("Starting the DNS server.")
service_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	# for talking to clients
service_socket.bind(('localhost', 53))
forwarder_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	# for talking to, say, a public dns
service_socket.settimeout(0)
forwarder_socket.settimeout(0)

dns_cache = {}
cache_file = None
try:
	cache_file = open(cache_filepath, 'r+b')
	dns_cache = pickle.load(cache_file)
	cache_file.close()
except Exception as exception:
	print ("Failed to read dns cache from " + cache_filepath + ". Proceeding with an empty cache. Will later attempt to write the cache to the specified filepath during server shutdown. Exception: " + str(exception))

test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)		# for testing

should_shutdown = False
while not(should_shutdown):
	# for testing
	test_socket.sendto(dnslib.DNSRecord.question("vk.com").pack(), ("127.0.0.1", 53))

	remove_expired_entries()
	look_for_new_service_requests()
	time.sleep(1)	# for looking at printed info in the terminal

	if keyboard.is_pressed("e"):
		should_shutdown = True

service_socket.close()
forwarder_socket.close()
test_socket.close()				# for testing
try:
	cache_file = open(cache_filepath, 'w+b')
	pickle.dump(dns_cache, cache_file)
	cache_file.close()
except Exception as exception:
	print ("Failed to write dns cache to " + cache_filepath + ". Exception: " + str(exception))
