'''
Created on Feb 15, 2018

@author: Abhishek Shah
'''

# coding: utf-8

# In[16]:


import requests
import pandas as pd
import json
from IPython.display import display, HTML

'''
Function to fetch data from url
'''
def get_data(cve,result):
    req = requests.get('http://cve.circl.lu/api/cve/{}'.format(cve))
    if req.status_code == 200:
        result[cve] = json.loads(req.text)
    return result

'''
Method to find vulnerable devices
'''
def find_vulnerables(id,computers,vul_computers):
#     vul_computers = {}
    for computer in computers:
        name_parts = computer.split()
        res = list(filter(lambda part: part in id, name_parts))
        if res and len(res) == len(name_parts):
            vul_computers.setdefault(computer,[])
            vul_computers[computer].append(id)
    return vul_computers

'''
function from get data in dataframe
'''
def read_data(content):
    my_dict={}
    capec={}
    reference={}
    rank={}
    if 'nessus' in content:
        for d in content['nessus']:
            for k,v in d.items():
                if k in my_dict.keys():
                    my_dict[k].append(v)
                else:
                    my_dict[k]=[v]
    if 'capec' in content:
        for d in content['capec']:
            for k,v in d.items():
                if k in capec.keys():
                    capec[k].append(v)
                else:
                    capec[k]=[v]
    #print(content)
    df=pd.DataFrame.from_dict(my_dict, orient='index')
    nessus=df.transpose()
    capec_df=pd.DataFrame.from_dict(capec, orient='index')
    capec_df=capec_df.transpose()
    if 'ranking' in content:
        rank=pd.DataFrame(content['ranking'][0])
    if 'references' in content:
        reference=pd.Series(content['references'])
    references=pd.DataFrame({'references':reference})
    df2= pd.DataFrame({
        'Modified':pd.Series(content['Modified']),
        'Published':pd.Series(content['Published']),
        'cvss':pd.Series(content['cvss']),
        'id':pd.Series(content['id']),
        'last-modified':pd.Series(content['last-modified']),
        'summary':pd.Series(content['summary']),

    })

    refmap=pd.DataFrame(content['refmap'])
    vul_report=pd.DataFrame(content['vulnerable_configuration'])   
    vul_config_cpe_2_2=pd.Series(content['vulnerable_configuration_cpe_2_2'])
    vul_config_cpe_2_2=pd.DataFrame({'vulnerable_configuration_cpe_2_2':vul_config_cpe_2_2})
    common_data=df2.transpose()
    return common_data,nessus,capec_df,rank,references,refmap,vul_report,vul_config_cpe_2_2



if __name__ == "__main__":
    urls=['CVE-2017-11305','CVE-2017-15103','CVE-2017-11913','CVE-2017-11826']
    for url in urls:
        response=''
        result={}
        cve_vul_computers={}
        try:
            response = get_data(url, result)
#             print(response)
        except :
            print('no data found')

        devices_test=['Windows 10','internet explorer 11','Office 2010','Adobe Flash Player 27','Visual Studio 2015','Windows 7','IE 10','Office 2010',
                      'Adobe Flash 28','Google Chrome 60','Windows Server 2012R2','AD Domain Services','IE 10','IIS 7.0','RHEL 7',
                      'Google Chrome 63','Apache Tomcat 9.0.4','NGINX 1.12.2','RHEV 4.1','BIND DNS 9.12']
        devices_test = [ i.lower() for i in devices_test]
        if url in response:
            vulnerables = result[url]['vulnerable_configuration']
            filtered_vul_computers = {}
            for vulnerable in vulnerables:
                filtered_vul_computers = find_vulnerables(vulnerable["id"], devices_test, filtered_vul_computers)
            cve_vul_computers[url] = filtered_vul_computers 
        df=pd.DataFrame.from_dict(response, orient='index')
        df.transpose()
        df.to_csv('{}.csv'.format(url))
        common_data,nessus,capec_df,rank,references,refmap,vul_report,vul_config_cpe_2_2=read_data(response[url])
        display(common_data)
        display(nessus)
        nessus.to_csv('nesus.csv')
        display(rank)
        display(references)
        references.to_csv('references.csv')
        display(refmap)
        refmap.to_csv('refmap.csv')
        display(vul_report)
        display(vul_config_cpe_2_2)
        vul_computers=pd.DataFrame.from_dict(cve_vul_computers, orient='index')
        vul_computers.transpose()
        vul_computers.to_csv('vulnerable_devices.csv')
        display(vul_computers)
    #     pd.concat([common_data,nessus,capec_df,rank,references,refmap,vul_report,vul_config_cpe_2_2],axis=1,ignore_index = True).to_csv('foo.csv')
    #    break

