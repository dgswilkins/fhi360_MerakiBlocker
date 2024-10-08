#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: noai:et:tw=80:ts=4:ss=4:sts=4:sw=4:ft=python

'''
Title:              mac_blocker.py
Description:        Find and block unauthorized clients from FHI-360 Meraki networks
Author:             Ricky Laney
'''
import csv
from datetime import datetime
import os
import re
import time
import meraki
from typing import Tuple, Union

import smtplib
from email.message import EmailMessage
from email.headerregistry import Address

# only print if we are testing. Set the condition to False for production
verboseprint = print if True else lambda *a, **k: None

# Set the SMTP Server address from the environment
SMTPSRV = os.environ.get('MBSMTPSERVER','your.smtp.server')
# Set the Email address to send from
sender_name = os.environ.get('MBSNAME', 'sender')
sender_prefix = os.environ.get('MBSPREFIX','user')
sender_suffix  = os.environ.get('MBSSUFFIX','domain.com')
EmailFrom = Address(sender_name, sender_prefix, sender_suffix)
# Set the Email address to send the email to
rcpt_name = os.environ.get('MBRNAME', 'Recipient')
rcpt_prefix = os.environ.get('MBRPREFIX','rcpt')
rcpt_suffix  = os.environ.get('MBRSUFFIX','domain.com')
EmailTo = Address(rcpt_name, rcpt_prefix, rcpt_suffix)

# Either input your API key below, or set an environment variable
# for example, in Terminal on macOS:  export MERAKI_DASHBOARD_API_KEY=093b24e85df15a3e66f1fc359f4c48493eaa1b73
YOUR_API_KEY = 'YOUR_API_KEY_GOES_HERE_DO_NOT_USE_THIS_ONE'
api_key = os.environ.get('MB_API_KEY', YOUR_API_KEY)

# Changing this will change the policy for bad clients to "Blocked"
BLOCK_BAD_CLIENTS = False

# Catch errors and continue processing
CATCH_ERRORS = True

HERE = os.path.dirname(os.path.abspath(__file__))
base_url = 'https://api.meraki.com/api/v1'


class FHI360ClientError(Exception):
    """ Custom error class
    """


class ClientValidator:
    """ Class that validates clients on the network

    :param: use_manuf = True (default)
    :return: bool = represents valid (True) and invalid (False) clients
    """

    def __init__(self, use_manuf: bool=True) -> None:
        self._use_manuf = use_manuf
        self._mac_file = os.path.join(HERE, 'bad_macs.txt')
        self._com_file = os.path.join(HERE, 'bad_companies.txt')

        if self._use_manuf:
            from manuf.manuf import MacParser
            try:
                mac_parser = MacParser()
                mac_parser.update(manuf_url="https://www.wireshark.org/download/automated/data/manuf")
            except Exception as e:
                verboseprint(f"Unable to update manuf database due to {e}")
                mac_parser = MacParser()
            self.parser = mac_parser
        # Load these from file once and use throughout
        self.bad_macs = self._get_bad_macs()
        self.bad_coms = self._get_bad_companies()

    def _get_bad_macs(self) -> list:
        with open(self._mac_file) as mf:
            bad_macs = mf.read().splitlines()
        return bad_macs or None

    def _get_bad_companies(self) -> list:
        with open(self._com_file) as cf:
            bad_coms = cf.read().splitlines()
        return bad_coms or None

    def is_bad_company(self, company: str) -> bool:
        if self.bad_coms and company:
            for bad_com in self.bad_coms:
                if bad_com in company:
                    return True
        return False

    def is_bad_mac(self, mac: str) -> bool:
        if self.bad_macs:
            for bad_mac in self.bad_macs:
                if mac.startswith(bad_mac):
                    return True
        if self._use_manuf:
            mac_com = self.parser.get_manuf(mac)
            return self.is_bad_company(mac_com)
        return False

    def is_bad_client(self, client: dict) -> bool:
        if self.is_bad_mac(client['mac']):
            return True
        if self.is_bad_company(client['manufacturer']):
            return True
        return False


class FHI360:
    """ Class that takes action on clients on FHI-360's Meraki network

    :param:str:  meraki_api = instance of Meraki API (required)
    :param:int:  num_days = number of days to look back (default 30)
    """

    def __init__(self, meraki_api: meraki.DashboardAPI,
                 num_days: int = 30) -> None:
        self.timespan = 60 * 60 * 24 * num_days
        self.org_id = os.environ.get('MBORGID', '123456')
        self.api = meraki_api
        self.org = self.api.organizations.getOrganization(
            self.org_id
        )
        assert self.org_id == self.org[
            'id'], f"Org ids not identical: {self.org_id} != {self.org['id']}"
        self.org_name = self.org['name']

    def get_networks(self, catch_errors: bool=True) -> Tuple[bool, Union[list, str, Exception]]:
        resp = None
        error_msg = None
        try:
            resp = self.api.organizations.getOrganizationNetworks(
                    self.org_id
                )
        except meraki.APIError as e:
            error_msg = f"""
                Meraki API error: {e}
                status code = {e.status}
                reason = {e.reason}
                error = {e.message}
            """
        except Exception as e:
            error_msg = e
        finally:
            if error_msg:
                if catch_errors:
                    resp = error_msg
                else:
                    raise FHI360ClientError(error_msg)
        if isinstance(resp, list):
            # Return a sorted list?
            resp.sort(key=lambda x: x.get('name'))
            return True, resp
        return False, resp

    def get_clients(self, network_id: str,
        catch_errors: bool=True) -> Tuple[bool, Union[list, str, Exception]]:
        resp = None
        error_msg = None
        try:
            resp = self.api.networks.getNetworkClients(
                network_id,
                timespan=self.timespan,
                perPage=1000,
                total_pages='all',
            )
        except meraki.APIError as e:
            error_msg = f"""
                Meraki API error: {e}
                status code = {e.status}
                reason = {e.reason}
                error = {e.message}
            """
        except Exception as e:
            error_msg = e
        finally:
            if error_msg:
                if catch_errors:
                    resp = error_msg
                else:
                    raise FHI360ClientError(error_msg)
        if isinstance(resp, list):
            return True, resp
        return False, resp

    def block_client(
        self,
        net_id: str,
        client_id: str,
        catch_errors: bool=True,
    ) -> Tuple[bool, Union[str, None]]:
        resp = None
        error_msg = None
        try:
            resp = self.api.networks.updateNetworkClientPolicy(
                net_id,
                client_id,
                'Blocked',
            )
        except meraki.APIError as e:
            error_msg = f"""
                Meraki API error: {e}
                status code = {e.status}
                reason = {e.reason}
                error = {e.message}
            """
        except Exception as e:
            error_msg = e
        finally:
            if error_msg:
                if catch_errors:
                    resp = error_msg
                else:
                    raise FHI360ClientError(error_msg)
        if isinstance(resp, dict) and resp['devicePolicy'] == 'Blocked':
            return True, None
        return False, resp

def purge(dir, pattern, days):
    # number of seconds in a day 
    day = 86400
    current_time = time.time() 
    regexObj = re.compile(pattern)
    for root, dirs, files in os.walk(dir, topdown=False):
        # iterate over the files in the current directory and remove old files
        for name in files:
            verboseprint(f"Checking file [{name}]")
            path = os.path.join(root, name)
            if bool(regexObj.search(name)):
                # file_time is the time when the file was modified 
                file_time = os.stat(path).st_mtime 
            
                # if a file is older than N days then delete it 
                if(file_time < current_time - day*days): 
                    verboseprint(f"removing file [{path}]")
                    os.remove(path)
        # iterate over the directories in the current directory and remove empty directories            
        for name in dirs:
            verboseprint(f"Checking folder [{name}]")
            path = os.path.join(root, name)
            if len(os.listdir(path)) == 0:
                verboseprint(f"removing folder [{path}]")
                os.rmdir(path)

def main():
    tday = f"{datetime.now():%Y-%m-%d-%H%M}"
    log_file_prefix = "FHI-360"
    log_dir = os.path.join(HERE, "logs")
    if "logs" not in os.listdir(HERE):
        os.mkdir(log_dir)
    # Instantiate a new ClientValidator with defaults
    validator = ClientValidator()
    # Instantiate a Meraki dashboard API session
    api = meraki.DashboardAPI(
        api_key=api_key,
        base_url=base_url,
        maximum_retries=4,
        output_log=True,
        log_file_prefix=log_file_prefix,
        log_path=log_dir,
        print_console=False
    )
    # Instantiate a FHI360 class
    fhi = FHI360(api, 1)
    verboseprint(f"\nAnalyzing organization {fhi.org_name}:")
    folder_name = f"FHI-360_clients_{tday}"
    folder_dir = os.path.join(HERE, folder_name)
    if folder_name not in os.listdir(HERE):
        os.mkdir(folder_dir)
    msg = EmailMessage()
    msg['Subject'] = 'Meraki Bad client Report'
    msg['From'] = EmailFrom
    msg['To'] = EmailTo
    success, networks = fhi.get_networks()
    if success:
        total = len(networks)
        counter = 1
        verboseprint(f"Found {total} networks in organization {fhi.org_name}")
        for net in networks:
            verboseprint(f"Searching clients in network {net['name']} ({counter} of {total})")
            success, clients = fhi.get_clients(net['id'])
            if success:
                bad_clients = [client for client in clients if \
                                validator.is_bad_client(client)]
                if bad_clients:
                    verboseprint(f"Found {len(bad_clients)} bad clients total")
                    for client in bad_clients:
                        # Reformat usage for readability
                        sent_usage = client['usage']['sent']
                        recv_usage = client['usage']['recv']
                        client['usage'] = f"sent={sent_usage} recv={recv_usage}"
                        client['blocked'] = 'Unknown'
                        if BLOCK_BAD_CLIENTS:
                            verboseprint(f"Now trying to block bad client: {client['id']}")
                            success, error_msg = fhi.block_client(
                                net['id'],
                                client['id'],
                                catch_errors=CATCH_ERRORS,
                            )
                            if success:
                                client['blocked'] = True
                                verboseprint(f"Successfully blocked: {client['id']}")
                            else:
                                client['blocked'] = 'Failed'
                                verboseprint(f"FAILED to block: {client['id']}\n\n{error_msg}")
                    file_name = f"{net['name'].replace(' ', '')}.csv"
                    output_file = open(f"{folder_dir}/{file_name}",
                                        mode='w', newline='\n')
                    field_names = bad_clients[0].keys()
                    csv_writer = csv.DictWriter(output_file, field_names,
                                                delimiter=',', quotechar='"',
                                                quoting=csv.QUOTE_ALL)
                    csv_writer.writeheader()
                    csv_writer.writerows(bad_clients)
                    output_file.close()
            else:
                verboseprint(f"get_clients failed for network {net['id']}\n\n{clients}")
            counter += 1
        # Stitch together one consolidated CSV report of all bad clients
        total_file = os.path.join(HERE, f"{folder_name}.csv")
        output_file = open(total_file, mode='w', newline='\n')
        field_names = ['id', 'mac', 'description', 'ip', 'ip6', 'ip6Local', 'user',
                    'firstSeen', 'lastSeen', 'manufacturer', 'os',
                    'recentDeviceSerial', 'recentDeviceName', 'recentDeviceMac', 'recentDeviceConnection',
                    'ssid', 'vlan', 'switchport', 'usage', 'status', 'notes', 'pskGroup', 'namedVlan',
                    'smInstalled', 'groupPolicy8021x', 'adaptivePolicyGroup', 'blocked', 'deviceTypePrediction', 'wirelessCapabilities']
        field_names.insert(0, "Network Name")
        field_names.insert(1, "Network ID")
        csv_writer = csv.DictWriter(output_file, field_names, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
        csv_writer.writeheader()
        for net in networks:
            file_name = f"{net['name'].replace(' ', '')}.csv"
            if file_name in os.listdir(folder_dir):
                with open(f"{folder_dir}/{file_name}") as input_file:
                    csv_reader = csv.DictReader(input_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
                    for row in csv_reader:
                        row['Network Name'] = net['name']
                        row['Network ID'] = net['id']
                        csv_writer.writerow(row)
        os.fsync(output_file)
        output_file.close()
        msg.set_content('Report attached')
        with open(total_file, 'rb') as content_file:
            content = content_file.read()
            msg.add_attachment(content, maintype='application', subtype='octet-stream', filename=f"{folder_name}.csv")
    else:
        verboseprint(f"get_networks failed \n\n{networks}")
        msg.set_content('No Networks found')
    verboseprint(f"\nsending report for {fhi.org_name} from {sender_name} [{sender_prefix}@{sender_suffix}] to {rcpt_name} [{rcpt_prefix}@{rcpt_suffix}]")
    s = smtplib.SMTP(SMTPSRV)
    s.send_message(msg)
    purge(HERE, r".*\.csv", 30)
    purge(HERE, r".*\.log", 30)
    s.quit()


if __name__ == '__main__':
    start_time = datetime.now()
    main()
    end_time = datetime.now()
    verboseprint(f"\nScript complete, total runtime {end_time - start_time}")
