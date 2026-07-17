# netrecon

TCP port scanner with banner grabbing. Exports JSON or HTML reports.

Python 3.10+, standard library only.

```
git clone https://github.com/aladinturgay/netrecon.git
cd netrecon
python -m netrecon scanme.nmap.org
python -m netrecon 192.168.1.5 -p 22,80,443
python -m netrecon scanme.nmap.org --html report.html -o report.json
```

Use only on systems you are allowed to test.

Alaaddin Turgay
