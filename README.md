<<<<<<< HEAD
PenIn2 Pentesting Tool

Description
-----------
PenIn2 is a penetration testing and vulnerability scanning tool designed to help security professionals identify potential weaknesses in web applications. It includes modules for SQL Injection, XSS, directory brute-forcing, Local File Inclusion (LFI), and open port scanning. The tool generates detailed reports in JSON and XML formats for comprehensive analysis.

Features
--------
=======
# PenIn2 Pentesting Tool

## Description
PenIn2 is a penetration testing and vulnerability scanning tool designed to help security researchers identify potential weaknesses in web applications. It includes modules for SQL Injection, XSS, directory brute-forcing, Local File Inclusion (LFI), and open port scanning.

## Features

- SQL Injection detection
- Cross-Site Scripting (XSS) vulnerability testing
- Directory brute-forcing using custom wordlists
- Local File Inclusion (LFI) detection
- Open port scanning for common ports
<<<<<<< HEAD
- Comprehensive reports in JSON and XML formats

Prerequisites
-------------
- Python 3.x
- Required Python libraries:
  - requests
  - urllib3

Install dependencies using the following command: `pip install -r requirements.txt`


How to Use
----------
1. Organize Payload Files:  
   Ensure that each payload file is stored in its respective folder:
   - SQL Injection payloads: Place in the `sqlpayloads` folder.
   - XSS payloads: Place in the `xss_payloads` folder.
   - LFI payloads: Place in the `lfi_payloads` folder.
   - Wordlists for directory brute-forcing: Place in the `wordlists` folder.  
   These folders are already included in the project structure. Simply add the appropriate files to the correct folder.

2. Extract the Zip File:  
   Download and extract the `PenIn2.zip` file into a folder of your choice. This will create a directory containing the project files and the payload folders.

3. Run the Tool:  
   Open a terminal or command prompt and navigate to the extracted directory:`cd path/to/extracted/folder`

Execute the tool based on your environment:
- For Windows:  
  Run:
  ```
  python t6.py
  ```
- For Termux/Linux:  
  Run:
  ```
  python tm.py
  ```

4. Verify the Setup:  
Ensure that all required payloads are present in their respective folders. Missing payloads may cause certain modules to function improperly.

Folder Structure
----------------
- sqlpayloads: Contains payloads for SQL Injection testing.
- xss_payloads: Contains payloads for Cross-Site Scripting (XSS) testing.
- lfi_payloads: Contains payloads for Local File Inclusion (LFI) testing.
- wordlists: Wordlists for directory brute-forcing.

Contributing
------------
- **Byakuya3456**: Lead Developer and Project Manager. Designed the core functionality, architecture, and implementation.
- **RakRox**: Assisted with testing and debugging.
- **Pallavimurthy73**: Helped with refining the reporting module and overall project review.
- **TeamMember3**: Provided feedback and suggested improvements.

Contributions are welcome! Feel free to fork the repository and submit pull requests for new features, bug fixes, or improvements.


License
-------
This project is licensed under the MIT License with Credit Restriction. See the LICENSE file for details.
=======
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

