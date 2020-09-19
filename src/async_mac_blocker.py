#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: noai:et:tw=80:ts=4:ss=4:sts=4:sw=4:ft=python

'''
Title:              async_mac_blocker.py
Description:        Find and block unauthorized clients from FHI-360 Meraki networks
Author:             Ricky Laney
Version:            0.0.2
'''
import csv
from datetime import datetime
import os
import asyncio
import meraki.aio
from typing import Union
# Typing shortcuts
AIO = meraki.aio.AsyncDashboardAPI


# Either input your API key below, or set an environment variable
# for example, in Terminal on macOS:  export MERAKI_DASHBOARD_API_KEY=093b24e85df15a3e66f1fc359f4c48493eaa1b73
YOUR_API_KEY = 'YOUR_API_KEY_GOES_HERE_DO_NOT_USE_THIS_ONE'
api_key = os.environ.get('MERAKI_DASHBOARD_API_KEY', YOUR_API_KEY)

# Changing this will change the policy for bad clients to "Blocked"
BLOCK_BAD_CLIENTS = False

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

# Initialize a global ClientValidator
CV = ClientValidator()

def clean_usage(clients: list) -> list:
    # Reformat usage for readability
    for client in clients:
        sent_usage = client['usage']['sent']
        recv_usage = client['usage']['recv']
        client['usage'] = f"sent={sent_usage} recv={recv_usage}"
        client['blocked'] = False
    return clients

async def block_client(meraki_aio: AIO, network: dict, client: dict):
    resp = await meraki_api.networks.updateNetworkClientPolicy(
        network['id'],
        client['id'],
        'Blocked',
    )
    if resp and resp['devicePolicy'] == 'Blocked':
        return client, True
    return client, False

async def get_clients(meraki_aio: AIO, network: dict, dir_name: str) -> str:
    print(f"Searching clients in network {network['name']}")
    try:
        clients = await meraki_aio.networks.getNetworkClients(
            network['id'],
            total_pages='all',
            timespan=60*60*24*30,
            perPage=1000,
        )
    except meraki.aio.AsyncAPIError as e:
        print(f"ERROR: get_clients: Meraki API error: {e}")
    except Exception as e:
        print(f"ERROR: get_clients: Unknown error: {e}")
    else:
        if clients:
            bad_clients = [client for client in clients if \
                           CV.is_bad_client(client)]
            if bad_clients:
                clients = clean_usage(bad_clients)
                print(f"Found {len(clients)} bad clients total")
                if BLOCK_BAD_CLIENTS:
                    # Create a list to call concurrently
                    block_tasks = [block_client(
                        meraki_aio,
                        network,
                        client
                    ) for client in clients]
                    for task in asyncio.as_completed(block_tasks):
                        client, success = await task
                        if success:
                            client['blocked'] = True
                            print(f"Successfully blocked: {client['id']}")
                        else:
                            print(f"FAILED to block: {client['id']}")
                file_name = f"{network['name'].replace(' ', '')}.csv"
                output_file = open(f"{dir_name}/{file_name}", mode='w',
                                    newline='\n')
                field_names = clients[0].keys()
                csv_writer = csv.DictWriter(output_file, field_names,
                                            delimiter=',', quotechar='"',
                                            quoting=csv.QUOTE_ALL)
                csv_writer.writeheader()
                csv_writer.writerows(clients)
                output_file.close()
                print(f"Successfully output {len(clients)} clients' data to \
                      file {file_name}")
            else:
                print(f"No bad clients found in {network['name']}")
    return network['name']

async def get_networks(meraki_aio: AIO, org: dict) -> str:
    org_id = org['id']
    org_name = org['name']
    print(f"\nAnalyzing organization {org_name}:")
    try:
        nets = await meraki_aio.organizations.getOrganizationNetworks(
            org_id,
            total_pages='all',
        )
    except meraki.aio.AsyncAPIError as e:
        print(f"ERROR: get_networks: Meraki API error: {e}")
        raise e
    except Exception as e:
        print(f"ERROR: get_networks: Unknown error: {e}")
        raise e

    tday = f"{datetime.now():%m-%d-%Y}"
    folder_name = f"{org_name}_clients_{tday}"
    dir_name = os.path.join(HERE, folder_name)
    if folder_name not in os.listdir(HERE):
        os.mkdir(dir_name)
    total = len(nets)
    counter = 1
    print(f"Found {total} networks in organization {org_name}")
    # create a list of all networks in the organization so we can get clients concurrently
    get_clients_tasks = [get_clients(meraki_aio, net, dir_name) for net in nets]
    for task in asyncio.as_completed(get_clients_tasks):
        net_name = await task
        print(f"Finished network: {net_name}")

    # Stitch together one consolidated CSV for this org
    output_file = open(f"{folder_name}.csv", mode="w", newline="\n")
    field_names = ['id', 'mac', 'description', 'ip', 'ip6', 'ip6Local', 'user', 'firstSeen', 'lastSeen', 'manufacturer', 'os', 'recentDeviceSerial', 'recentDeviceName', 'recentDeviceMac', 'ssid', 'vlan', 'switchport', 'usage', 'status', 'notes', 'smInstalled', 'groupPolicy8021x']
    field_names.insert(0, 'Network Name')
    field_names.insert(1, 'Network ID')
    field_names.append('blocked')
    csv_writer = csv.DictWriter(
        output_file,
        field_names,
        delimiter=',',
        quotechar='"',
        quoting=csv.QUOTE_ALL,
    )
    csv_writer.writeheader()
    for net in nets:
        file_name = f"{net['name'].replace(' ', '')}.csv"
        if file_name in os.listdir(dir_name):
            with open(f"{dir_name}/{file_name}") as input_file:
                csv_reader = csv.DictReader(
                    input_file,
                    delimiter=',',
                    quotechar='"',
                    quoting=csv.QUOTE_ALL,
                )
                try:
                    next(csv_reader)
                except StopIteration:
                    continue
                else:
                    for row in csv_reader:
                        row['Network Name'] = net['name']
                        row['Network ID'] = net['id']
                        csv_writer.writerow(row)
    return org_name


async def main():
    start_time = datetime.now()
    tday = f"{datetime.now():%m-%d-%Y}"
    log_file_prefix = f"fhi-360_{tday}_"
    log_dir = os.path.join(HERE, "logs")
    if "logs" not in os.listdir(HERE):
        os.mkdir(log_dir)
    # Instantiate a Meraki Async dashboard API session
    async with meraki.aio.AsyncDashboardAPI(
            api_key=api_key,
            base_url=base_url,
            output_log=True,
            log_file_prefix=log_file_prefix,
            log_path=log_dir,
            print_console=False
        ) as meraki_aio:
        fhi_id = '324893'
        org = await meraki_aio.organizations.getOrganization(fhi_id)
        org_name = await get_networks(meraki_aio, org)
    end_time = datetime.now()
    print(f"Completed org: {org_name}")
    print(f"\nScript complete, total runtime {end_time - start_time}")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
