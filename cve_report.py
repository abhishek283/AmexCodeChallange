import urllib.request
import json

json_obj1 = urllib.request.urlopen("https://cve.circl.lu/api/cve/CVE-2017-11305")
json_obj2 = urllib.request.urlopen("https://cve.circl.lu/api/cve/CVE-2017-15103")
json_obj3 = urllib.request.urlopen("https://cve.circl.lu/api/cve/CVE-2017-11913")
json_obj4 = urllib.request.urlopen("https://cve.circl.lu/api/cve/CVE-2017-11826")

html = '<html>'

# ===========Report for first file=================
string1 = json_obj1.read().decode('utf-8')
data1json = json.loads(string1)
keys = []
for key in data1json.keys():
    keys.append(key)
html += '<h1>CVE-2017-11305</h1>'
html += '<table border="1"><tr><th>' + '</th>'
for key in keys:
    html += '<th>' + key + '</th>'
html += '</tr>'
html += '<tr><td>' + '</td>'
for key in keys:
    html += '<td>' + json.dumps(data1json[key]) + '</td>'
html += '</tr>'
html += '</table>'

# ==========Report for second file =====
string2 = json_obj2.read().decode('utf-8')
data2json = json.loads(string2)
keys = []
for key in data2json.keys():
    keys.append(key)
html += '<h1>CVE-2017-15103</h1>'
html += '<table border="1"><tr><th>' + '</th>'
for key in keys:
    html += '<th>' + key + '</th>'
html += '</tr>'
html += '<tr><td>' + '</td>'
for key in keys:
    html += '<td>' + json.dumps(data2json[key]) + '</td>'
html += '</tr>'
html += '</table>'

# =============Report for 3rd file=================
string3 = json_obj3.read().decode('utf-8')
data3json = json.loads(string3)
keys = []
for key in data3json.keys():
    keys.append(key)
html += '<h1>CVE-2017-11913</h1>'
html += '<table border="1"><tr><th>' + '</th>'
for key in keys:
    html += '<th>' + key + '</th>'
html += '</tr>'
html += '<tr><td>' + '</td>'
for key in keys:
    html += '<td>' + json.dumps(data3json[key]) + '</td>'
html += '</tr>'
html += '</table>'

# ===================Report for 4th file==============
string4 = json_obj4.read().decode('utf-8')
data4json = json.loads(string4)
keys = []
for key in data4json.keys():
    keys.append(key)
html += '<h1>CVE-2017-11826</h1>'
html += '<table border="1"><tr><th>' + '</th>'
for key in keys:
    html += '<th>' + key + '</th>'
html += '</tr>'
html += '<tr><td>' + '</td>'
for key in keys:
    html += '<td>' + json.dumps(data4json[key]) + '</td>'
html += '</tr>'
html += '</table>'

# ===============To get the Vulnerable computers==============
cve_content = [data1json, data2json, data3json, data4json]
comp_sys = ["Windows 10", "IE 11","Office 2010","Adobe Flash 27","Visual Studio 2015","Windows 7","IE 10","Office 2010",
            "Adobe Flash 28","Google Chrome 60","Windows Server 2012R2","AD Domain Services", "IE 10","IIS 7.0","RHEL 7",
            "Google Chrome 63","Apache Tomcat 9.0.4","NGINX 1.12.2","RHEV 4.1","BIND DNS 9.12"]
vulnerable = {}
for comp in comp_sys:
      vulnerable[comp] = []
for comp in comp_sys:
     for cve in cve_content:
          if comp in json.dumps(cve):
             vulnerable[comp].append(cve["id"])

# ===================Vulnerable Report==============
keys = []
for key in vulnerable.keys():
    keys.append(key)
html += '<h1>Vulnerable Report</h1>'
html += '<table border="1"><tr><th>' + '</th>'
for key in keys:
    html += '<th>' + key + '</th>'
html += '</tr>'
html += '<tr><td>' + '</td>'
for key in keys:
    html += '<td>' + json.dumps(vulnerable[key]) + '</td>'
html += '</tr>'
html += '</table>'
# ========================================

html += '</html>'
file_ = open('report.html', 'w')
file_.write(html)
file_.close()