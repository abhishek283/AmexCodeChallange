import urllib.request
import json
# =============Report for 3rd file=================
def show_data(datajson,url):
    keys = []
    html=''
    for key in datajson.keys():
        keys.append(key)import urllib.request
import json
# =============Report for 3rd file=================
def show_data(datajson,url):
    keys = []
    html=''
    for key in datajson.keys():
        keys.append(key)
    html += '<h1>{}</h1>'.format(url)
    html += '<table border="1"><tr><th>' + '</th>'
    for key in keys:
        html += '<th>' + key + '</th>'
    html += '</tr>'
    html += '<tr><td>' + '</td>'
    for key in keys:
        html += '<td>' + json.dumps(datajson[key]) + '</td>'
    html += '</tr>'
    html += '</table>'
    return html

# ===============To get the Vulnerable computers==============
def find_vulnerable(datajson,vulnerable):

    for comp in comp_sys:
        if comp in json.dumps(datajson):
            vulnerable[comp].append(datajson["id"])
    return vulnerable


# ===================Vulnerable Report==============
def show_vulnerable(vulnerable):
    keys = []
    html=''
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
    return html

if __name__ == "__main__":

    urls=['CVE-2017-11305','CVE-2017-15103','CVE-2017-11913','CVE-2017-11826']
    html='<html>'
    vulnerable={}
    comp_sys = ["Windows 10", "IE 11","Office 2010","Adobe Flash 27","Visual Studio 2015","Windows 7","IE 10","Office 2010",
                "Adobe Flash 28","Google Chrome 60","Windows Server 2012R2","AD Domain Services", "IE 10","IIS 7.0","RHEL 7",
                "Google Chrome 63","Apache Tomcat 9.0.4","NGINX 1.12.2","RHEV 4.1","BIND DNS 9.12"]

    for comp in comp_sys:
          vulnerable[comp] = []

    for url in urls:
        json_obj = urllib.request.urlopen("https://cve.circl.lu/api/cve/{}".format(url))
        string1 = json_obj.read().decode('utf-8')
        data1json = json.loads(string1)
        html+= show_data(data1json,url)
        vulnerable= find_vulnerable(data1json,vulnerable)
    html  += show_vulnerable(vulnerable)
    html += '</html>'

    # ========================================
    with open('report.html', 'w') as file_:
        file_.write(html)

    html += '<h1>{}</h1>'.format(url)
    html += '<table border="1"><tr><th>' + '</th>'
    for key in keys:
        html += '<th>' + key + '</th>'
    html += '</tr>'
    html += '<tr><td>' + '</td>'
    for key in keys:
        html += '<td>' + json.dumps(datajson[key]) + '</td>'
    html += '</tr>'
    html += '</table>'
    return html

# ===============To get the Vulnerable computers==============
def find_vulnerable(datajson,vulnerable):

    comp_sys = ["Windows 10", "IE 11","Office 2010","Adobe Flash 27","Visual Studio 2015","Windows 7","IE 10","Office 2010",
                "Adobe Flash 28","Google Chrome 60","Windows Server 2012R2","AD Domain Services", "IE 10","IIS 7.0","RHEL 7",
                "Google Chrome 63","Apache Tomcat 9.0.4","NGINX 1.12.2","RHEV 4.1","BIND DNS 9.12"]

    for comp in comp_sys:
          vulnerable[comp] = []
    for comp in comp_sys:
        if comp in json.dumps(datajson):
            vulnerable[comp].append(datajson["id"])
    return vulnerable


# ===================Vulnerable Report==============
def show_vulnerable(vulnerable):
    keys = []
    html=''
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
    return html

if __name__ == "__main__":

    urls=['CVE-2017-11305','CVE-2017-15103','CVE-2017-11913','CVE-2017-11826']
    html='<html>'
    vulnerable={}
    for url in urls:
        json_obj = urllib.request.urlopen("https://cve.circl.lu/api/cve/{}".format(url))
        string1 = json_obj.read().decode('utf-8')
        data1json = json.loads(string1)
        html+= show_data(data1json,url)
        vulnerable= find_vulnerable(data1json,vulnerable)
    html  += show_vulnerable(vulnerable)
    html += '</html>'

    # ========================================
    with open('report.html', 'w') as file_:
        file_.write(html)
