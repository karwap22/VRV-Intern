# %% [markdown]
# # Parsing File and Taking Input

# %%
import os
from tkinter import Tk
from tkinter.filedialog import askopenfilename
import pandas as pd
import fileinput
import csv

# %%


def get_log_file():
    Tk().withdraw()

    file_path = askopenfilename(
        title="Select a .log file",
        filetypes=[("Log Files", "*.log"), ("All Files", "*.*")]
    )

    # Use sample.log if no file is selected
    if not file_path:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir, "sample.log")
        
    return file_path


log_file = get_log_file()
print(f"Selected file: {log_file}")


# %%
def sortDictionary(freq:dict,reverse=False):
    return {k: v for k, v in sorted(freq.items(), key=lambda item: item[1],reverse=reverse)}

# %%
def makeDFfromDict(freq:dict,columns:list):
    return pd.DataFrame(list(freq.items()),columns=columns)

# %%

filename = log_file
fileContent = []

for line in fileinput.input(files=filename):
    stringAdded = line.split(' ')
    stringAdded.remove('-')
    stringAdded.remove('-')
    stringAdded[1] += ' '+stringAdded[2]
    stringAdded.pop(2)
    if stringAdded[len(stringAdded)-2] == '"Invalid':
        stringAdded[len(stringAdded)-2] += ' '+stringAdded[len(stringAdded)-1]
    stringAdded.pop(len(stringAdded)-1)
    fileContent.append(stringAdded)

fileContent


# %% [markdown]
# # 1. Count Requests per IP Address:

# %%
freq = {}
for stringAdded in fileContent:
    if stringAdded[0] in freq.keys():
        freq[stringAdded[0]] +=1
    else:
        freq[stringAdded[0]] = 1
reqIPfreq = sortDictionary(freq,reverse=True)





# %%
print("\nIP Address","\t","Request Count")
for i in reqIPfreq:
    print(i,"\t",reqIPfreq[i])

# %% [markdown]
# # 2. Identify the Most Frequently Accessed Endpoint:

# %%
urlFreq = {}


for req in fileContent:
    url = req[3]
    if url in urlFreq.keys():
        urlFreq[url] +=1
    else:
        urlFreq[url] = 1
urlFreq = sortDictionary(urlFreq,reverse=True)
ls = list(urlFreq.keys())
for i in range(1,len(ls)):
    urlFreq.pop(ls[i])
print("\nMost Frequently Accessed Endpoint:")
print(list(urlFreq.keys())[0],"Accessed",urlFreq[list(urlFreq.keys())[0]],"times")


# %% [markdown]
# # 3. Detect Suspicious Activity:

# %%
def getSuspiciousActivity(fileContent:list,threshold=10):
    ipFreq = {}

    for req in fileContent:
        
        if req[5] == "401" or req[len(req)-1]=='"Invalid credentials"\n':
            if req[0] in ipFreq.keys():
                ipFreq[req[0]] +=1 
            else:
                ipFreq[req[0]] =1 
    newIpFreq = {}
    for i in ipFreq.keys():
        if ipFreq[i] > threshold:
            newIpFreq[i] = ipFreq[i]
    
    
    print("\nSuspicious Activity Detected:")
    print("IP Address","\t", "Failed Login Attempts")
    for i in newIpFreq.keys():
        print(i,"\t",newIpFreq[i])
    
    return newIpFreq


IpFreq = getSuspiciousActivity(fileContent)

# %% [markdown]
# # Making CSV File:

# %%
max_rows = max(len(reqIPfreq), len(urlFreq), len(IpFreq))

requests_per_ip_list = list(reqIPfreq.items())
most_accessed_endpoint_list = list(urlFreq.items())
suspicious_activity_list = list(IpFreq.items())

while len(requests_per_ip_list) < max_rows:
    requests_per_ip_list.append(("-", "-"))
while len(most_accessed_endpoint_list) < max_rows:
    most_accessed_endpoint_list.append(("-", "-"))
while len(suspicious_activity_list) < max_rows:
    suspicious_activity_list.append(("-", "-"))

output_file = "log_analysis_results.csv"

with open(output_file, mode="w", newline="") as file:
    writer = csv.writer(file)
    
    writer.writerow([
        "IP Address (Requests)", "Request Count",
        "Endpoint", "Access Count",
        "IP Address (Suspicious)", "Failed Login Count"
    ])
    
    for i in range(max_rows):
        writer.writerow([
            requests_per_ip_list[i][0], requests_per_ip_list[i][1],
            most_accessed_endpoint_list[i][0], most_accessed_endpoint_list[i][1],
            suspicious_activity_list[i][0], suspicious_activity_list[i][1]
        ])


# %%
df = pd.read_csv(output_file)

print("\n",df)


