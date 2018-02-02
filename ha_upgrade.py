#!/usr/bin/python

import ugf
import getpass
from time import sleep
import sys
import logging

logger = logging.getLogger("main")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler("ha_upgrade.log")
formatter = logging.Formatter('%(asctime)s %(name)s\t\t%(levelname)s:\t\t\t\t%(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

# logging.basicConfig(filename="ha_upgrade.log", format=' %(asctime)s %(name)s %(levelname)s:\t\t%(message)s', level=logging.DEBUG)


fw_1 = ""
fw_2 = ""
fw_1_state = ""
fw_2_state = ""
next_version = ""
state_table = {'passive' : fw_1, 'active' : fw_2}


upgrade_path = {'5.0.6':'6.0.0','6.0.0':'6.1.0','6.1.0':'7.0.1','7.0.1':'7.1.0','7.1.0':'8.0.0'}

def getIP():
    ip_addr = raw_input('Enter the IP of the passive firewall: ')
    return ip_addr
def kill():
    logging.critical('Exiting due to errors.')
    exit()

fw_1 = getIP()
print """What version do you want to move to? This script can handle multi-version upgrade. For example
this script can take a device running PAN-OS version 6.0.5 and upgrade all the way through 7.1.4."""

target_version = raw_input('Target Version (e.g. 7.1.5): ')

user = raw_input('Enter your username: ')
passwd = getpass.getpass('Enter your password: ')

api_key = ugf.get_key(fw_1, user, passwd)




if ugf.ha_enable_check(fw_1, api_key) == "no":
    logging.error('High Availability is not enabled on this firewall. Exiting now.')
    exit()
if ugf.ha_state_check(fw_1, api_key) == "active":
    logging.warning('This is not the passive firewall. Finding the peer.')
    fw_2 = fw_1
    fw_1 = ugf.ha_get_peer_IP(fw_2, api_key)
if ugf.ha_state_check(fw_1, api_key) == "passive":
    fw_2 = ugf.ha_get_peer_IP(fw_1, api_key)
    

# Initial update of the state table


logging.info('Initializing state table')
fw_1_state = ugf.ha_state_check(fw_1, api_key)
state_table[fw_1_state] = fw_1
fw_2_state = ugf.ha_state_check(fw_2, api_key)
state_table[fw_2_state] = fw_2

confirm = raw_input('Active firewal is %s and passive firewall is %s. Is this correct? (Y/n)  ' % (fw_2, fw_1))

if confirm == ('n' or 'no' or 'N' or 'No' or 'NO'):
    print "Something is rotten in the state of Denmark. Exiting."
    exit()
# else:
#     fw_1_state = "passive"
#     fw_2_state = "active"



cur_version = ugf.get_PANOS_ver(fw_1, api_key)

# Walk up the upgrade path starting at the current version and ending at the target version

while cur_version != target_version:
    if cur_version[0:3] == target_version[0:3]:
        next_version = target_version
    else:
        cur_version = cur_version[0:3] + '.0'
        next_version = upgrade_path[cur_version]
    cur_fw = state_table['passive']
 
    suspend = ugf.ha_state_suspend(cur_fw, api_key)
    if suspend == 1:
        kill()
    dl_status = ugf.dl_PANOS(cur_fw, next_version, api_key) 
    if dl_status == 1:
        kill()
    logging.info('Installing %s. This process can take several minutes.' % next_version)
    install_status = ugf.install_PANOS(cur_fw, next_version, api_key)
    if install_status == 1:
        print install_status
        kill()
    ugf.reboot_FW(cur_fw, api_key)
    cur_fw = state_table['active']
    dl_status = ugf.dl_PANOS(cur_fw, next_version, api_key)
    if dl_status == 1:
        kill()
    logging.info('Installing %s. This process can take several minutes.' % next_version)
    install_status = ugf.install_PANOS(cur_fw, next_version, api_key)
    if install_status == 1:
        print install_status
        kill()
    ugf.reboot_FW(cur_fw, api_key)
    # Update state table
    logging.info('Updating state table.')
    fw_1_state = ugf.ha_state_check(fw_1, api_key)
    state_table[fw_1_state] = fw_1
    fw_2_state = ugf.ha_state_check(fw_2, api_key)
    state_table[fw_2_state] = fw_2


print "Upgrades complete."
