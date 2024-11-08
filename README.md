# ZIA-Supernets
Script to calculate ZIA supernets from a set of Zscaler IP ranges

Python script should calculate ZIA supernets for different clouds, while specifying various options and printing to the console. It contains code under MIT License. It requires the Python requests library. Some of the details, including surcharge data centers (which are included in your current licensing) and future IP ranges, are defined manually in the script so the script will need to be updated on a regular basis to be completely accurate.

python zia_supernets.py --cloud CLOUD [--exclude_future] [--exclude_hub] [--exclude_ipv6] [--exclude_surcharge] [--log_level [LOG_LEVEL]]

python zia_supernets.py --help
Script to export aggregated IP supernets for ZIA to use in allow list configurations

options:
  -h, --help            show this help message and exit
  --cloud CLOUD         ZIA cloud (i.e., zscloud, zscalerone, zscalertwo, zscalerthree)
  --exclude_future      Flag to exclude future ranges from output
  --exclude_hub         Flag to exclude hub ranges from output
  --exclude_ipv6        Flag to exclude IPv6 ranges
  --exclude_surcharge   Flag to exclude regional surcharge data centers
  --log_level [LOG_LEVEL]
                        Setting for details (DEBUG, INFO, WARNING, ERROR, CRITICAL')

Example output:
python zia_supernets.py --cloud zscalerthree --exclude_ipv6 --exclude_surcharge
8.25.203.0/24
64.74.126.64/26
70.39.159.0/24
72.52.96.0/26
89.167.131.0/24
94.188.131.0/25
104.129.192.0/20
112.196.99.180/32
128.177.125.0/24
136.226.0.0/16
137.83.128.0/18
147.161.128.0/17
165.225.0.0/17
165.225.192.0/18
167.103.0.0/16
170.85.0.0/16
185.46.212.0/22
199.168.148.0/24
213.152.228.0/24
216.52.207.64/26
216.218.133.192/26
