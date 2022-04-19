import os
from re import I 
import requests
import json

class Analysis: 

    def __init__(self, apiResponse): 
        self.data = apiResponse['data']
        self.sha256 =  apiResponse['data']['attributes']['sha256']
    
    def getAvDetectionScore(self):
        return self.data['attributes']['last_analysis_stats']['malicious']

    def filecreation(self):
        attributes = self.data['attributes']
        if 'creation_date'not in attributes:
            return 'no data'
        else:
            return self.data['attributes']['creation_date']

    def first_submission(self):
        return self.data['attributes']['first_submission_date']

    def tt(self):
        attributes = self.data['attributes']

        if 'popular_threat_classification' not in attributes or 'suggested_threat_label' not in attributes['popular_threat_classification']:
            return 'no data'
        
        return self.data['attributes']['popular_threat_classification']['suggested_threat_label']

    def dest_ip(self):
        attributes = self.data['attributes']
        if 'dest_ip'not in attributes:
            return 'no destination ip' 
        else:
            return self.data['attributes']['dest_ip']


    def show(self):
        return '%-70s | %10s |  %10s | %10s | %40s | %10s'%(analysis.sha256, analysis.getAvDetectionScore(), analysis.filecreation(), analysis.first_submission(), analysis.tt(), analysis.dest_ip())


url = "https://www.virustotal.com/api/v3/files/%s"
categories = os.listdir("categories")

headers = {
    "Accept": "application/json", 
    "X-Apikey": "2cf5ef3b81d9a41c399fadcd2fb3085af09e547320a40d28c5dcee49f7865144"
}

os.mkdir("output")

for categoryFile in categories:
  file1 = open("categories/" + categoryFile, "r")
  lines = file1.readlines()
  os.mkdir(f"output/{categoryFile}")

  stats = []

  for hash in lines:

    current_url = url %hash 
    response = requests.request("GET", current_url, headers=headers)


    if response.status_code == 200:
        analysis = Analysis(response.json())
        stats.append(analysis.show())
        
        with open(f"output/{categoryFile}/{hash}.json", 'w') as outfile:
            json.dump(response.json(), outfile, indent = 2 )

    else: 
        print(f'Data not found for {hash} belonging to {categoryFile}')


  with open(f"output/{categoryFile}/stats.txt", 'w') as statfile:
    for line in stats:
        statfile.write(line + "\n")