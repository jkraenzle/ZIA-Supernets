"""
Helper Python script to find the aggregated subnets used by Zscaler Internet Access (ZIA).
This script pulls down the set of IP address ranges for hubs and enforcement nodes.
It also considers future IP address ranges as documented on the Zscaler site as of 6/10/2023.
"""
""" 
Incorporated supernets code under The MIT License from https://github.com/grelleum/supernets

The MIT License (MIT)

Copyright (c) 2015 Greg Mueller

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
"""

import argparse
from collections import defaultdict

import logging as log
import logging.handlers
import os
from datetime import date

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import ipaddress

### Update these values to include additional ZIA Data Centers
ZIA_CLOUDS = ["zscaler", "zscalerone", "zscalertwo", "zscalerthree", "zscloud", "zscalerbeta", "zscalergov", "zscalerten"]
ZIA_CONTINENTS = ["Americas", "APAC", "EMEA"]

COMMERCIAL_REGIONAL_SURCHARGE_CITIES = [
	"Auckland",
	"Auckland II",
	"Beijing",
	"Beijing III",
	"Bogota I",
	"Buenos Aires I",
	"Canberra I",
	"Capetown",
	"Capetown IV",
	"Dubai I",
	"Johannesburg II",
	"Johannesburg III",
	"Lagos II",
	"Melbourne II",
	"Perth I",
	"Rio de Janeiro I",
	"Santiago I",
	"Sao Paulo II",
	"Sao Paulo IV",
	"Seoul I",
	"Shanghai",
	"Shanghai II",
	"Sydney III",
	"Taipei",
	"Tianjin"
	]

### Logging

LOG_MSG_FORMAT = '[%(asctime)s] %(levelname)s <pid:%(process)d> %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H-%M-%S'
LOG_LEVELS_TXT = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
LOG_LEVELS_ENUM = [log.DEBUG, log.INFO, log.WARNING, log.ERROR, log.CRITICAL]

def log_namer(log_path):
	base_path_with_base_name = log_path.split('.')[0]
	new_path = base_path_with_base_name + '.' + str(date.today()) + '.log'
	return new_path

def init_logs(log_base_name, log_level_txt, logs_dir=None):

	# Function requirements include validating directory path, setting formatting, rotating, and
	# setting log level
	try:
		# Check that supplied logging directory is valid and can be written
		valid_path = False
		if logs_dir != None:
			# Confirm path exists and can be created
			if os.path.exists(logs_dir) == False:
				os.makedirs(logs_dir)
			valid_path = os.access(logs_dir, os.W_OK)
	except Exception as e:
		raise Exception(f"Unexpected error while initializing logs: {e}")

	# If valid path does not exist, try to default to script directory
	if valid_path == False:
		logs_dir = os.path.dirname(os.path.realpath(__file__))
		if os.access(logs_dir, os.W_OK) == False:
			raise Exception(f"Error: Unable to write to backup log directory '{logs_dir}'")

	try:
		log_name = log_namer(log_base_name)
		log_path = os.path.join(logs_dir, log_name)
		log_level = LOG_LEVELS_ENUM[LOG_LEVELS_TXT.index(log_level_txt)]

		root_log = log.getLogger()
		formatter = log.Formatter(fmt=LOG_MSG_FORMAT, datefmt=LOG_DATE_FORMAT)
		handler = logging.handlers.TimedRotatingFileHandler(log_path, when='midnight', interval=1, backupCount=7)
		handler.namer = log_namer
		handler.setFormatter(formatter)
		handler.setLevel(log_level)
		root_log.addHandler(handler)
		root_log.setLevel(log_level)
	except Exception as e:
		raise Exception(f"Unexpected error while configuring log format: {e}")

	return log_path

### Class definition

class Supernets:

	def __init__(self, log):
		self.networks = {}
		self.prefixes = defaultdict(list)
		self.networks_ipv6 = {}
		self.prefixes_ipv6 = defaultdict(list)
		self.log = log
		self.class_name = 'Supernets'

	def ipv4_only(self):
		output = ""
		for network in sorted(self.networks, key=lambda ip: ip.network_address.packed):
			output = output + str(network) + "\n"
		return output

	def __str__(self):
		output = self.ipv4_only()
		for network in sorted(self.networks_ipv6, key=lambda ip: ip.network_address.packed):
			output = output + str(network) + "\n"
		return output

	def add_network(self, *args):
		for network in args:
			if network.version == 4:
				if network not in self.networks:
					self.networks[network] = network.prefixlen
					self.add_network_to_prefixes(network)
			elif network.version == 6:
				if network not in self.networks_ipv6:
					self.networks_ipv6[network] = network.prefixlen
					self.add_network_to_prefixes(network, 6)

	def delete_network(self, *args):
		for network in args:
			if network.version == 4:
				self.networks.pop(network, None)
			elif network.version == 6:
				self.networks_ipv6.pop(network, None)

	def add_network_to_prefixes(self, network, version=4):
		prefix = network.prefixlen
		if version == 4:
			self.prefixes[prefix].append(network)
		elif version == 6:
			self.prefixes_ipv6[prefix].append(network) 
			
	def process_prefixes(self, prefix=0):
		if prefix < 128:
			self.process_prefixes(prefix + 1)
		if prefix in self.prefixes:
			self.aggregate_networks_of_same_prefix_length(sorted(self.prefixes[prefix]))
		if prefix in self.prefixes_ipv6:
			self.aggregate_networks_of_same_prefix_length(sorted(self.prefixes_ipv6[prefix]))

	def aggregate_networks_of_same_prefix_length(self, prefix_list):
		previous_network = None
		for current_network in prefix_list:
			existing_supernet = self.find_existing_supernet(current_network)
			if existing_supernet != None:
				self.delete_network(current_network)
				self.log.info(f"[{self.class_name}] {current_network} found in {existing_supernet}")
			elif previous_network is None:
				previous_network = current_network
			else:
				supernet1 = previous_network.supernet(prefixlen_diff=1)
				supernet2 = current_network.supernet(prefixlen_diff=1)
				if supernet1 == supernet2:
					self.add_network(supernet1)
					self.delete_network(previous_network, current_network)
					previous_network = None
				else:
					previous_network = current_network

	def find_existing_supernet(self, network):
		result = None
		for prefix in range(network.prefixlen - 1, 0, -1):
			super_network = network.supernet(new_prefix=prefix)
			if super_network in self.networks:
				result = super_network
				break
			if super_network in self.networks_ipv6:
				result = super_network
				break
		return result

### Functions

def cloud_check(cloud):
	# Confirm that the passed in cloud exists in Zscaler Internet Access
	if cloud in ZIA_CLOUDS:
		return True

	return False

def continent_check(continent):
	# Confirm that the passed in continent exists in Zscaler Internet Access definitions
	if continent in ZIA_CONTINENTS:
		return True

	return False

def cloud_enforcement_node_ranges_get(cloud, log):

	url = f"https://config.zscaler.com/api/{cloud}.net/cenr/json"
	result = requests.get(url, verify=False)

	if result.status_code in [200]:
		result_json = result.json()
		return result_json
	else:
		log.warning(f"[zia_supernets] Failed to pull cloud IP address ranges")
		return None

def hub_ip_addresses_get(cloud, log):
	# Use required or recommended?
	url = f"https://config.zscaler.com/api/{cloud}.net/hubs/cidr/json/recommended"
	result = requests.get(url, verify=False)

	if result.status_code in [200]:
		result_json = result.json()
		return result_json
	else:
		log.warning(f"Failed to pull hub IP address ranges")
		return None

def future_ip_addresses_get(cloud, log):
	url = f"https://config.zscaler.com/api/{cloud}.net/future/json"
	result = requests.get(url, verify=False)
	
	if result.status_code in [200]:
		result_json = result.json()
		return result_json
	else:
		log.warning(f"Failed to pull future IP address ranges")
		return None

def cloud_ranges_to_aggregate_subnets(aggregates, cloud_ranges, skip_surcharge, include_continent, log):
	if cloud_ranges == None:
		return aggregates

	# One-time check to see if the code should run a continent check
	check_continent = continent_check(include_continent)

	for cloud in cloud_ranges:
		continents = cloud_ranges[cloud]
		for continent in continents:
			continent_name = continent.replace("continent : ", "")
			if check_continent == True and continent_name != include_continent:
				log.info(f"[zia_supernets] Skipping continent '{continent_name}'")
				continue
			cities = continents[continent]
			for city in cities:
				if skip_surcharge == True:
					city_name = city.replace("city : ", "")
					if city_name in COMMERCIAL_REGIONAL_SURCHARGE_CITIES:
						log.info(f"[zia_supernets] Skipping regional surcharge city '{city_name}'")
						continue
				subnets = cities[city]
				for subnet in subnets:
					for subnet in subnets:
						if "range" in subnet:
							range_str = subnet["range"]
							if range_str.strip() == "":
								continue

							try:
								ip_network = ipaddress.ip_network(range_str, strict=False)
								aggregates.add_network(ip_network)
							except:
								log.warning(f"[zia_supernets] '{range_str}' is not a valid network in '{city}'")
								continue

	
	return aggregates

def hub_ranges_to_aggregate_subnets(aggregates, hub_ranges, log):
	if hub_ranges == None:
		return aggregates

	if "hubPrefixes" in hub_ranges:
		ranges = hub_ranges["hubPrefixes"]
		for range_str in ranges:
			try:
				ip_network = ipaddress.ip_network(range_str, strict=False)
				aggregates.add_network(ip_network)
			except:
				log.warning(f"[zia_supernets] '{range_str}' is not a valid network")
				pass
	return aggregates

def future_ranges_to_aggregate_subnets(aggregates, future_ranges, log):
	if future_ranges == None:
		return aggregates
	
	if "prefixes" in future_ranges:
		ranges = future_ranges["prefixes"]
		for range_str in ranges:
			try:
				ip_network = ipaddress.ip_network(range_str, strict=False)
				aggregates.add_network(ip_network)
			except:
				log.warning(f"[zia_supernts] '{range_str} is not a valid network")
				pass

	return aggregates

def add_cloud_ranges(aggregates, cloud, skip_surcharge, include_continent, log):

	cloud_ranges = cloud_enforcement_node_ranges_get(cloud, log)
	log.info(cloud_ranges)
	aggregates = cloud_ranges_to_aggregate_subnets(aggregates, cloud_ranges, skip_surcharge, include_continent, log)
	aggregates.process_prefixes()

	return aggregates

def add_hub_ranges(aggregates, cloud, log):

	hub_ranges = hub_ip_addresses_get(cloud, log)
	aggregates = hub_ranges_to_aggregate_subnets(aggregates, hub_ranges, log)
	aggregates.process_prefixes()

	return aggregates

def add_future_cloud_ranges(aggregates, cloud, log):

	future_cloud_ranges = future_ip_addresses_get(cloud, log)
	aggregates = future_ranges_to_aggregate_subnets(aggregates, future_cloud_ranges, log)
	aggregates.process_prefixes()

	return aggregates
	
def main():

	# Pulling settings for script
	parser = argparse.ArgumentParser(description="Script to export aggregated IP supernets for ZIA to use in allow list configurations")
	parser.add_argument("--cloud", help="ZIA cloud (i.e., zscloud, zscalerone, zscalertwo, zscalerthree)", required=True)
	parser.add_argument("--exclude_future", default=False, action='store_true', help="Flag to exclude future ranges from output", required=False)
	parser.add_argument("--exclude_hub", default=False, action='store_true', help="Flag to exclude hub ranges from output", required=False)
	parser.add_argument("--exclude_ipv6", default=False, action='store_true', help="Flag to exclude IPv6 ranges", required=False)
	parser.add_argument("--exclude_surcharge", default=False, action='store_true', help="Flag to exclude regional surcharge data centers", required=False)
	parser.add_argument("--include_continent", help="Continent (i.e., APAC, Americas, EMEA)", required=False)
	parser.add_argument("--log_level", default="INFO", help="Setting for details (DEBUG, INFO, WARNING, ERROR, CRITICAL')", nargs='?', required=False)
	args = parser.parse_args()

	# Initializing logs
	log_path = init_logs("ZIA Supernets", args.log_level)

	# Pulling supernets
	aggregates = Supernets(log)

	if cloud_check(args.cloud) == False:
	 	log.error(f"[main] The provided cloud name '{cloud}' does not exist")
	 	return

	if args.include_continent != None and continent_check(args.include_continent) == False:
		log.error(f"[main] The provided continent name '{args.include_continent}' does not exist")
		return

	aggregates = add_cloud_ranges(aggregates, args.cloud, args.exclude_surcharge, args.include_continent, log)
	if args.exclude_hub == False:
		aggregates = add_hub_ranges(aggregates, args.cloud, log)
	if args.exclude_future == False:
		aggregates = add_future_cloud_ranges(aggregates, args.cloud, log)
	if args.exclude_ipv6 == False:
		print(aggregates)
	else:
		print(aggregates.ipv4_only())

if __name__ == "__main__":
	main()
