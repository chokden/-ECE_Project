import os 
import requests
import json

class Analysis: 

    def __init__(self, apiResponse): 
        self.data = apiResponse['data']
        self.sha256 =  apiResponse['data']['attributes']['sha256']
        

    ## ['tag1', 'tag2']
    def get_tags(self):
        return self.data['attributes']['tags']

    def show(self):
        return '%-70s %10s'%(analysis.sha256, analysis.get_tags()) 


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