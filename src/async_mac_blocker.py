#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: noai:et:tw=80:ts=4:ss=4:sts=4:sw=4:ft=python

'''
Title:              async_mac_blocker.py
Description:        Find and block unauthorized clients from FHI-360 Meraki networks
Author:             Ricky Laney
Version:            0.0.2
'''
import asyncio
from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime
import os
from manuf.manuf import MacParser
import meraki.aio
from typing import Union
# Typing shortcuts
AIO = meraki.aio.AsyncDashboardAPI


# Either input your API key below, or set an environment variable
# for example, in Terminal on macOS:  export MERAKI_DASHBOARD_API_KEY=093b24e85df15a3e66f1fc359f4c48493eaa1b73
YOUR_API_KEY = 'YOUR_API_KEY_GOES_HERE_DO_NOT_USE_THIS_ONE'
API_KEY = os.environ.get('MERAKI_DASHBOARD_API_KEY', YOUR_API_KEY)

# Changing this will change the policy for bad clients to "Blocked"
BLOCK_BAD_CLIENTS = False

HERE = os.path.dirname(os.path.abspath(__file__))
TODAY = f"{datetime.now():%m-%d-%Y}"
LOG_DIR = os.path.join(HERE, 'logs')
LOG_FILE_PREFIX = f"fhi-360_{TODAY}_"
BASE_URL = 'https://api.meraki.com/api/v1'
MAC_FILE = os.path.join(HERE, 'bad_macs.txt')
COM_FILE = os.path.join(HERE, 'bad_companies.txt')

CLIENT_FIELD_NAMES = [
    'id',
	'mac',
	'description',
	'ip',
	'ip6',
	'ip6Local',
	'user',
	'firstSeen',
	'lastSeen',
	'manufacturer',
	'os',
	'recentDeviceSerial',
	'recentDeviceName',
	'recentDeviceMac',
	'ssid',
	'vlan',
	'switchport',
	'usage',
	'status',
	'notes',
	'smInstalled',
	'groupPolicy8021x',
]

# Load mac_parser globally as it takes a while
try:
    mac_parser = MacParser(update=True)
except Exception as e:
    print(f"Unable to update manuf database due to {e}")
    mac_parser = MacParser()


class FHI360ClientError(Exception):
    """ Custom error class
    """


def get_bad_macs(mac_file=MAC_FILE) -> Union[list, None]:
    with open(mac_file) as mf:
        bad_macs = mf.read().splitlines()
    return bad_macs or None


def get_bad_companies(com_file=COM_FILE) -> Union[list, None]:
    with open(com_file) as cf:
        bad_coms = cf.read().splitlines()
    return bad_coms or None


async def is_bad_client(client: dict, bad_macs: Union[dict, None],
                  bad_coms: Union[list, None] ) -> dict:
    company = client['manufacturer'] or None
    mac = client['mac'] or None
    manuf_company = mac_parser.get_manuf(mac)
    if bad_coms and any([company, manuf_company]):
        for bad_com in bad_coms:
            if company and bad_com in company:
                return client
            if manuf_company and bad_com in manuf_company:
                return client
    if bad_macs and mac:
        for bad_mac in bad_macs:
            if mac.startswith(bad_mac):
                return client


async def clean_client(client: dict) -> dict:
    # Flatten and reformat usage for readability
    if client['usage']:
        sent_usage = client['usage']['sent']
        recv_usage = client['usage']['recv']
        client['usage'] = f"sent={sent_usage} recv={recv_usage}"
    client['blocked'] = False
    return client


async def get_bad_clients(clients: list, clean: bool=True) -> Union[list, None]:
    """ Function that runs ourasync and non-async functions for determining bad
        clients.
    """
    num_workers = os.cpu_count() * 4
    executor = ThreadPoolExecutor(max_workers=num_workers)
    loop = asyncio.get_event_loop()
    bad_macs = await loop.run_in_executor(executor, get_bad_macs)
    bad_coms = await loop.run_in_executor(executor, get_bad_companies)
    bad_clients = []
    client_tasks = [is_bad_client(client, bad_macs, bad_coms) for client in clients]
    for task in asyncio.as_completed(client_tasks):
        bad_client = await task
        if bad_client:
            if clean:
                bad_client = await clean_client(bad_client)
            bad_clients.append(bad_client)
    return bad_clients

# bad_clients = [yield from await is_bad_client(client, bad_macs, bad_coms) for client in clients]


async def block_client(meraki_aio: AIO, network: dict, client: dict) -> str:
    resp = await meraki_api.networks.updateNetworkClientPolicy(
        network['id'],
        client['id'],
        'Blocked',
    )
    if resp and resp['devicePolicy'] == 'Blocked':
        client['blocked'] = True
        return f"SUCCESS blocking: {client['id']}"
    return f"FAILED blocking: {client['id']}"


async def write_final_report(folder_name: str, nets: list) -> str:
    # Stitch together one consolidated CSV for this org
    final_report = os.path.join(HERE, f"{folder_name}.csv")
    output_file = open(final_report, mode="w", newline="\n")
    field_names = CLIENT_FIELD_NAMES
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
        dir_name = os.path.join(HERE, folder_name)
        if file_name in os.listdir(dir_name):
            with open(os.path.join(dir_name, file_name)) as input_file:
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
    return f"Final report written to {final_report}"


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
            print(f"Found {len(clients)} clients in {network['name']}")
            bad_clients = await get_bad_clients(clients)
            if bad_clients:
                print(f"Found {len(bad_clients)} bad clients")
                if BLOCK_BAD_CLIENTS:
                    # Create a list to call concurrently
                    block_tasks = [block_client(
                        meraki_aio,
                        network,
                        client
                    ) for client in bad_clients]
                    for task in asyncio.as_completed(block_tasks):
                        result = await task
                        print(result)
                file_name = f"{network['name'].replace(' ', '')}.csv"
                output_file = open(f"{dir_name}/{file_name}", mode='w',
                                    newline='\n')
                field_names = bad_clients[0].keys()
                csv_writer = csv.DictWriter(output_file, field_names,
                                            delimiter=',', quotechar='"',
                                            quoting=csv.QUOTE_ALL)
                csv_writer.writeheader()
                csv_writer.writerows(bad_clients)
                output_file.close()
                print(f"Successfully output {len(bad_clients)} clients' data to \
                      file {file_name}")
            else:
                print(f"No bad clients found in {network['name']}")
    return network['name']


async def get_networks(meraki_aio: AIO, org: dict) -> str:
    org_id = org['id']
    org_name = org['name']
    nets = None
    print(f"\nAnalyzing organization {org_name}:")
    try:
        nets = await meraki_aio.organizations.getOrganizationNetworks(
            org_id,
            total_pages='all',
        )
    except meraki.aio.AsyncAPIError as e:
        print(f"ERROR: get_networks: Meraki API error: {e}")
    except Exception as e:
        print(f"ERROR: get_networks: Unknown error: {e}")
    if not nets:
        raise FHI360ClientError(f"Failed to get networks from {org_name}")
    folder_name = f"{org_name}_clients_{TODAY}"
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
    results = await write_final_report(folder_name, nets)
    print(results)
    return org_name


async def main():
    start_time = datetime.now()
    if "logs" not in os.listdir(HERE):
        os.mkdir(LOG_DIR)
    # Instantiate a Meraki Async dashboard API session
    async with meraki.aio.AsyncDashboardAPI(
            api_key=API_KEY,
            base_url=BASE_URL,
            output_log=True,
            log_file_prefix=LOG_FILE_PREFIX,
            log_path=LOG_DIR,
            print_console=False
        ) as meraki_aio:
        fhi360 = '324893'
        org = await meraki_aio.organizations.getOrganization(fhi360)
        org_name = await get_networks(meraki_aio, org)
    end_time = datetime.now()
    print(f"Completed org: {org_name}\n")
    print(f"Total runtime: {end_time - start_time}")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
