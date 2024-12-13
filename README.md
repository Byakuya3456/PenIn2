# PenIn2 Pentesting Tool

## Description
PenIn2 is a penetration testing and vulnerability scanning tool designed to help security researchers identify potential weaknesses in web applications. It includes modules for SQL Injection, XSS, directory brute-forcing, Local File Inclusion (LFI), and open port scanning.

## Features
- SQL Injection detection
- Cross-Site Scripting (XSS) vulnerability testing
- Directory brute-forcing using custom wordlists
- Local File Inclusion (LFI) detection
- Open port scanning for common ports
- Generates comprehensive reports in JSON and XML formats

## Prerequisites
- Python 3.x
- Required Python libraries:
  - `requests`
  - `socket`
  - `urllib`
  - `concurrent.futures`

You can install the dependencies using:
```bash
pip install -r requirements.txt
