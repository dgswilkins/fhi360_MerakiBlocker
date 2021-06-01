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
import meraki
from typing import Tuple, Union

import smtplib
from email.message import EmailMessage
from email.headerregistry import Address

# Set the SMTP Server address from the environment
SMTPSRV = os.environ.get('SMTPSERVER','your.smtp.server')
# Set the Email address to send from
sender_name = os.environ.get('SNAME', 'sender')
sender_prefix = os.environ.get('SPREFIX','user')
sender_suffix  = os.environ.get('SSUFFIX','domain.com')
EmailFrom = Address(sender_name, sender_prefix, sender_suffix)
# Set the Email address to send the email to
rcpt_name = os.environ.get('RNAME', 'Recipient')
rcpt_prefix = os.environ.get('RPREFIX','rcpt')
rcpt_suffix  = os.environ.get('RSUFFIX','domain.com')
EmailTo = Address(rcpt_name, rcpt_prefix, rcpt_suffix)

# Either input your API key below, or set an environment variable
# for example, in Terminal on macOS:  export MERAKI_DASHBOARD_API_KEY=093b24e85df15a3e66f1fc359f4c48493eaa1b73
YOUR_API_KEY = 'YOUR_API_KEY_GOES_HERE_DO_NOT_USE_THIS_ONE'
api_key = os.environ.get('MERAKI_DASHBOARD_API_KEY', YOUR_API_KEY)

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
                mac_parser = MacParser(update=True)
            except Exception as e:
                print(f"Unable to update manuf database due to {e}")
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
        self.org_id = os.environ.get('ORGID', '123456')
        self.api = meraki_api
        self.org = self.api.organizations.getOrganization(
            self.org_id
        )
        assert self.org_id == self.org[
            'id'], f"Org ids not identical: {self.org_id} != {self.org['id']}"
        self.org_name = self.org['name']

    def get_networks(self, catch_errors: bool=True) -> Tuple[bool, Union[list, None]]:
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
            return True, resp
        return False, resp

    def get_clients(self, network_id: str,
        catch_errors: bool=True) -> Tuple[bool, Union[list, None]]:
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


def main():
    tday = f"{datetime.now():%m-%d-%Y}"
    log_file_prefix = f"fhi-360_{tday}_"
    log_dir = os.path.join(HERE, "logs")
    if "logs" not in os.listdir(HERE):
        os.mkdir(log_dir)
    # Instantiate a new ClientValidator with defaults
    validator = ClientValidator()
    # Instantiate a Meraki dashboard API session
    api = meraki.DashboardAPI(
        api_key=api_key,
        base_url=base_url,
        output_log=True,
        log_file_prefix=log_file_prefix,
        log_path=log_dir,
        print_console=False
    )
    # Instantiate a FHI360 class
    fhi = FHI360(api)
    print(f"\nAnalyzing organization {fhi.org_name}:")
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
        print(f"Found {total} networks in organization {fhi.org_name}")
        for net in networks:
            print(f"Searching clients in network {net['name']} ({counter} of {total})")
            success, clients = fhi.get_clients(net['id'])
            if success:
                bad_clients = [client for client in clients if \
                                validator.is_bad_client(client)]
                if bad_clients:
                    print(f"Found {len(bad_clients)} bad clients total")
                    for client in bad_clients:
                        # Reformat usage for readability
                        sent_usage = client['usage']['sent']
                        recv_usage = client['usage']['recv']
                        client['usage'] = f"sent={sent_usage} recv={recv_usage}"
                        client['blocked'] = 'Unknown'
                        if BLOCK_BAD_CLIENTS:
                            print(f"Now trying to block bad client: {client['id']}")
                            success, msg = fhi.block_client(
                                net['id'],
                                client['id'],
                                catch_errors=CATCH_ERRORS,
                            )
                            if success:
                                client['blocked'] = True
                                print(f"Successfully blocked: {client['id']}")
                            else:
                                client['blocked'] = 'Failed'
                                print(f"FAILED to block: {client['id']}\n\n{msg}")
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
                print(f"get_clients failed for network {net['id']}\n\n{msg}")
            counter += 1
        # Stitch together one consolidated CSV report of all bad clients
        total_file = os.path.join(HERE, f"{folder_name}.csv")
        output_file = open(total_file, mode='w', newline='\n')
        field_names = ['id', 'mac', 'description', 'ip', 'ip6', 'ip6Local', 'user',
                    'firstSeen', 'lastSeen', 'manufacturer', 'os',
                    'recentDeviceSerial', 'recentDeviceName', 'recentDeviceMac', 'recentDeviceConnection',
                    'ssid', 'vlan', 'switchport', 'usage', 'status', 'notes',
                    'smInstalled', 'groupPolicy8021x', 'adaptivePolicyGroup', 'blocked']
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
            msg.add_attachment(content, maintype='application', subtype='octet-stream', filename=total_file)
    else:
        msg.set_content('No Networks found')
    s = smtplib.SMTP(SMTPSRV)
    s.send_message(msg)
    s.quit()


if __name__ == '__main__':
    start_time = datetime.now()
    main()
    end_time = datetime.now()
    print(f"\nScript complete, total runtime {end_time - start_time}")
