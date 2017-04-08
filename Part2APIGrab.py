#!/usr/bin/python

import slumber

# This part defines the API we will be using
# api.blacklist().ip('malware').get(limit=100) is the query essenntially it will take us to
# https://cymon.io:443/api/nexus/v1/blacklist/ip/malware/
api = slumber.API("https://cymon.io/api/nexus/v1/")
ipblacklist = api.blacklist().ip('malware').get(limit=100)

#IPlist will be our list with all of IPs we first need to extract it out of JSON
# which is what ipblacklist['results'] is for 
iplist = []
for ip in ipblacklist['results']:
	iplist.append(ip['addr'])

#im defining the top line of the CSV i will be making
toCsv = [["ipNum","ip","NumOfSources","NumOfUrls"]]


# the ips i grabbed will go through 2 different lookups to grab other information
# it will grab the IP, the number of sources that reported the malware, and the number of urls assoicated with that IP
y=1
for x in iplist:
	newlist = []
	iplookup = api.ip(x).get()
	urllookup = api.ip(x).urls().get()
	
	# the appending goes into new list so i can have multiple lists within a list
	newlist.append(str(y))
	newlist.append(str(iplookup['addr']))
	newlist.append(len(iplookup['sources']))
	newlist.append(len(urllookup['results']))
	#this part sends it all to the first list i defined
	toCsv.append(newlist)

	y+=1
	
#this is what exports the list of lists I made into a csv or atleast a csv format
with open("APIcymon.csv", "a") as myfile:
	for x in toCsv:
		row = x[0] + "," + x[1] + ',' + str(x[2]) + "," + str(x[3]) + "\n"
		myfile.write(row)
