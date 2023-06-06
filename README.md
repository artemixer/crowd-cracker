# crowd-cracker

CrowdCracker is an offensive tool meant for enumerating and attacking vulnerable WordPress login forms

It operates in 3 stages:

1.  Using WPScan it enumerates the possible usernames for the login form
2.  Then, it makes a call to DeHashed.com for these usernames to check for exising password leaks
    It then takes the passwords from DeHashed and applies rules to them to create more password variations
3. Finally, it uses the created password dictionary to bruteforce the login form

Crowdcracker supports using proxies, custom rulesets and allows the user to specify the number of threads to use

Usage:
  Example: crowdCracker.py --url "https://example.com" --threads 50 --users-enum 10 --ruleset-size 2
  
  --url (--url-file)                Target url(s) to analyse
  --proxy (--proxy-file)            Proxies to use during the scan (ip:port@login:pass)
  --proxy-protocol                  Protocol for the proxies provided (HTTP, HTTPS, SOCKS4, SOCKS5)
  --no-proxy-check                  Disables checking proxies on startup
  --threads THREADS                 Set the amount of threads to be used per bruteforce (default: 50)
  --users-enum USERS                Amount of author IDs to be enumerated
  --no-password-gen                 Disables generating extra passwords with rules, if original passwords dont work
  --ruleset-size [1,2,3]            Set the size of built-in ruleset to be used, bigger ruleset will generate more passwords (default: 2)
  --ruleset FILE                    Specify a custom ruleset
  --no-colors                       Disables colored output
