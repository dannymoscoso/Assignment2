#!/usr/bin/python

import slumber

api = slumber.API("https://cymon.io/api/nexus/v1/")
ipblacklist = api.blacklist().ip('malware').get(limit=100)


iplist = []
for ip in ipblacklist['results']:
	iplist.append(ip['addr'])

toCsv = [["ipNum","ip","NumOOfSources","NumOfUrls"]]

y=1
for x in iplist:
	newlist = []
	iplookup = api.ip(x).get()
	urllookup = api.ip(x).urls().get()
	newlist.append(str(y))
	newlist.append(str(iplookup['addr']))
	newlist.append(len(iplookup['sources']))
	newlist.append(len(urllookup['results']))
	toCsv.append(newlist)

	y+=1
	
with open("APIcymon.csv", "a") as myfile:
	for x in toCsv:
		row = x[0] + "," + x[1] + ',' + str(x[2]) + "," + str(x[3]) + "\n"
		myfile.write(row)
