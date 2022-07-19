Meraki API Scripts to Find Clients Matching MAC Addresses
=========================================================

How to run...
=============

> It is recommend to use a Python 3.8.X virtualenv to avoid installing packages in system Python.
> Please consult the Python [Official Docs](https://docs.python.org/3/library/venv.html). 

- Open a terminal and Clone the repo.
  ```bash
  git clone https://github.com/dgswilkins/fhi360_MerakiBlocker.git
  cd fhi360_MerakiBlocker
  ```

- Install requirements.
  ```bash
  pip install -r requirements.txt
  ```

- Create environment variable MERAKI_DASHBOARD_API with **your** key *or* update the scripts manually with **your** Meraki API Key.

- If you wish to **block** clients, you must update the script manually and change the following:
  ```python
  BLOCK_BAD_CLIENTS = True
  ```

- Run the script in "src" directory as required. See details below.
  ```bash
  ./src/mac_blocker.py
  ```

File Explanations
-----------------

- **bad_macs.txt**
  This file is used to locate MACs you wish to report or block on.

- **bad_companies.txt**
  This file is used to locate companies you wish to report or block on. The manufacturer for each client determined using *manuf* and what's listed in Meraki are both processed. If either manufacturer is matched to one in this file, it is reported and/or blocked. The match does *not* have to exact. Uses: "if bad_company in mac_manufacturer"
  Example:
    - "Apple" will match manufacturer "Apple Corp.", "Apple Inc.", "Red Apple Distillery"

- **mac_blocker.py**
  This script will write a report for *BAD* clients within the last 30 days for each network in seperate "network" folders. Also adds a column "blocked" which reports True if client has been blocked or False otherwise. Then it will write a final report of clients in a single CSV report.

> Distribute freely and credit me,
> make money and share with me,
> lose money and don't ask me.

