# Nmap Port Scanner In Python

This is just a demo application to use Nmap in Python using python-nmap package


## Requirements

1. Python3

2. python-nmap package [**https://pypi.python.org/pypi/python-nmap**](https://pypi.python.org/pypi/python-nmap)


## Usage
```python
	python3 nmap_portscanner.py -h
```

To get the help menu
```python
	python3 nmap_portscanner.py 127.0.0.1 -p 80,21,4444
```
It will check the ports 80,21,4444 of the host 127.0.0.1 and will display the result

	==============================
	Starting Nmap Scan
	==============================
	[+] 127.0.0.1 tcp/80 closed
	[+] 127.0.0.1 tcp/21 closed
	[+] 127.0.0.1 tcp/4444 closed

Output


## Contribute

If you have any idea you want to implement or think that there is a better way to implement any part of the code please create a fork and I will do my best to merge appropriately. Thank you.

Hope you will like the application.
