import json
import csv
from collections import Counter

def main():
	# parse json file
	with open('siemens-s7.json') as data_file:    
		devices = json.load(data_file)
	
	# print data of all devices
	#inspectData(devices)
	
	# used to find strings that can be linked to vulnerabilities
	#exploreDataContainingString(devices, "vipa")
	#exploreDataContainingString(devices, "winac")
	
	# input rules that can detect vulnerabilities in the dataset
	#addVulnerabilities("s7-vulnerabilities.json")
	
	# detect vulnerabilities for each device
	vulnerable_devices = detectVulnerabilities('siemens-s7.json', "s7-vulnerabilities.json")
	
	# aggregate CVE scores
	aggregateScores(vulnerable_devices)


# print data of all devices
def inspectData(devices):
	for ics in devices:
		data = ics['data'].splitlines()
		for line in data:
			print line
		print ""
		raw_input()


# explore data of the devices that contain a certain string
def exploreDataContainingString(devices, string):
	for ics in devices:
		if string in ics['data'].lower():
			data = ics['data'].splitlines()
			for line in data:
				print line
			print ""
			raw_input()


# add a vulnerability to the known vulnerabilities file
def addVulnerabilities(file):
	with open(file) as f:
		data = json.load(f)

	while True:
		print "Add vulnerability [A] or Quit [Q]"
		command = raw_input()
		if command == 'A':
			vuln = {}
			print "Vulnerability ID"
			vuln['id'] = raw_input()
			vuln['variants'] = []
			while True:
				print "Add variant [A] or Finish [F]"
				command = raw_input()
				if command == 'A':
					variant = {}
					print "Define comma separated strings indicating that the device is vulnerable if these strings matched"
					variant['matches'] = raw_input().split(',')
					print "CVSS Severity"
					variant['score'] = raw_input()
					vuln['variants'].append(variant)
				elif command == 'F':
					break
			data.append(vuln)
		elif command == 'Q':
			break

	with open(file, 'w') as f:
		json.dump(data, f)


# add vulnerabilities to the data of all devices
def detectVulnerabilities(devices_file, vulnerabilities_file):
	with open(devices_file) as f:    
		devices = json.load(f)
	
	with open(vulnerabilities_file) as f:
		vulnerabilities = json.load(f)
	
	count = 0
	for ics in devices:
		data = ics['data']
		if data == '':
			count += 1
		ics['vulnerabilities'] = []
		for vulnerability in vulnerabilities:
			id = vulnerability['id']
			for variant in vulnerability['variants']:
				match = True
				for rule in variant['matches']:
					if rule not in data:
						match = False
						break
				if match:
					ics['vulnerabilities'].append({
						'id': id,
						'score': variant['score']
					})
	print "Devices without data: " + str(count)
	return devices


# aggregate CVE scores
def aggregateScores(vulnerable_devices):
	cve_scores = []
	for ics in vulnerable_devices:
		cve_max = 0
		for vulnerability in ics['vulnerabilities']:
			cve_max = max(cve_max, round(float(vulnerability['score'])))
		cve_scores.append(cve_max)

	counts = Counter(cve_scores).items()
	print counts
	
	file = open('counts.csv', 'wb')
	wr = csv.writer(file)
	wr.writerows(counts)


if __name__ == "__main__":
    main()