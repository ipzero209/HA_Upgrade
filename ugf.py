#!/usr/bin/python


import os
import requests
import xml.etree.ElementTree as et
from time import sleep
import logging

ugf_logger = logging.getLogger("ugf")




#logging.basicConfig(filename="ha_upgrade.log", format=' %(asctime)s %(name)s %(levelname)s:\t\t%(message)s', level=logging.DEBUG)




def get_key(ip, user, password):
    """Retrieves the API key for the specified user"""
    logger = logging.getLogger("ugf.get_key")
    logger.info('Requesting API key for user %s from %s' %(user, ip))
    req_string = "https://" + ip + "/api/?type=keygen&user=" + user + "&password=" + password
    resp = requests.get(req_string, verify=False)
    respXML = et.fromstring(resp.content)
    if resp.status_code != 200:
        err_node = respXML.find('./result/msg')
        logger.error('Code %i, %s' %(resp.status_code, err_node.text))
    k_node = respXML.find('./result/key')
    return k_node.text

def ha_enable_check(fw_IP, key):
    """Checks to see if HA is enabled on the specified firewall"""
    logger = logging.getLogger("ugf.ha_enable_check")
    logger.info('Checking to see if HA is enabled on %s' % fw_IP)
    req_string = "https://" + fw_IP + "/api/?type=op&cmd=<show><high-availability><state></state></high-availability></show>&key=" + key
    resp = requests.get(req_string, verify=False)
    respXML = et.fromstring(resp.content)
    if resp.status_code != 200:
        err_node = respXML.find('./result/msg')
        logger.error('Code %i, %s' %(resp.status_code, err_node.text))
    enable_node = respXML.find('./result/enabled')
    return enable_node.text

def ha_state_check(fw_IP, key):
    """Checks the HA state of the specified firewall"""
    logger = logging.getLogger("ugf.ha_state_check")
    logger.info('Checking HA state of %s' % fw_IP)
    req_string = "https://" + fw_IP + "/api/?type=op&cmd=<show><high-availability><state></state></high-availability></show>&key=" + key
    resp = requests.get(req_string, verify=False)
    respXML = et.fromstring(resp.content)
    if resp.status_code != 200:
        err_node = respXML.find('./result/msg')
        logger.error('Code %i, %s' %(resp.status_code, err_node.text))
    state_node = respXML.find('./result/group/local-info/state')
    return state_node.text

def ha_get_peer_IP(fw_IP, key):
    """Retrieves the HA peer IP address"""
    logger = logging.getLogger("ugf.ha_get_peer")
    logger.info('Getting peer IP for %s' % fw_IP)
    req_string = "https://" + fw_IP + "/api/?type=op&cmd=<show><high-availability><state></state></high-availability></show>&key=" + key
    resp = requests.get(req_string, verify=False)
    respXML = et.fromstring(resp.content)
    if resp.status_code != 200:
        err_node = respXML.find('./result/msg')
        logger.error('Code %i, %s' %(resp.status_code, err_node.text))
    peer_node = respXML.find('./result/group/peer-info/mgmt-ip')
    peer = peer_node.text
    peer = peer[:-3]
    return peer

def get_PANOS_ver(fw_IP, key):
    """Checks the current version of PAN-OS running on the specified firewall"""
    logger = logging.getLogger("ugf.get_PANOS_ver")
    logger.info('Checking for current PAN-OS version on %s' % fw_IP)
    req_string = "https://" + fw_IP + "/api/?type=op&cmd=<show><system><info></info></system></show>&key=" + key
    resp = requests.get(req_string, verify=False)
    respXML = et.fromstring(resp.content)
    if resp.status_code != 200:
        err_node = respXML.find('./result/msg')
        logger.error('Code %i, %s' %(resp.status_code, err_node.text))
    ver_node = respXML.find('./result/system/sw-version')
    return ver_node.text

def dl_PANOS(fw_IP, version, key):
    """Downloads the specified version of PAN-OS"""
    logger = logging.getLogger("ugf.dl_PANOS")
    logger.info('Attempting to download PAN-OS v%s on %s' %(version, fw_IP))
    check_req_string = "https://" + fw_IP + "/api/?type=op&cmd=<request><system><software><check></check></software></system></request>&key=" + key
    check_resp = requests.get(check_req_string, verify=False)
    check_respXML = et.fromstring(check_resp)
    if check_resp.status_code != 200:
        err_node = respXML.find('./result/msg')
        logger.error('Code %i, %s' %(resp.status_code, err_node.text))
    dl_req_string = "https://" + fw_IP + "/api/?type=op&cmd=<request><system><software><download><version>" + version + "</version></download></software></system></request>&key=" + key
    dl_resp = requests.get(dl_req_string, verify=False)
    dl_respXML = et.fromstring(dl_resp.content)
    if resp.status_code != 200:
        err_node = respXML.find('./result/msg')
        logger.error('Code %i, %s' %(resp.status_code, err_node.text))
    job_node = dl_respXML.find('./result/job')
    jobID = job_node.text
    result = jobChecker(fw_IP, jobID, key)
    if result == 1:
        logger.error('Download of %s on %s failed.' %(version, fw_IP))
        return 1
    else:
        logger.info('Download of %s on %s successful' %(version, fw_IP))
        return 0


def install_PANOS(fw_IP, version, key):
    """ Installs the specified PAN-OS version on the firewall"""
    logger = logging.getLogger("ugf.install_PANOS")
    logger.info('Attempting to install PAN-OS v%s on %s' %(version, fw_IP))
    req_string = "https://" + fw_IP + "/api/?type=op&cmd=<request><system><software><install><version>" + version + "</version></install></software></system></request>&key=" + key
    resp = requests.get(req_string, verify=False)
    respXML = et.fromstring(resp.content)
    if resp.status_code != 200:
        err_node = respXML.find('./result/msg')
        logger.error('Code %i, %s' %(resp.status_code, err_node.text))
    job_node = respXML.find('./result/job')
    jobID = job_node.text
    result = jobChecker(fw_IP, jobID, key)
    if result == 1:
        logger.error('There was an issue with installation job number %s on %s' %(jobID, fw_IP))
        return 1
    else:
        logger.info('Installation of %s on %s successful' %(version, fw_IP))
        return 0


def ha_state_suspend(fw_IP, key):
    """Sets the HA state of the specified firewall to suspended"""
    logger = logging.getLogger("ugf.ha_state_suspend")
    logger.info('Attempting to suspend %s' % fw_IP)
    req_string = "https://" + fw_IP + "/api/?type=op&cmd=<request><high-availability><state><suspend></suspend></state></high-availability></request>&key=" + key
    resp = requests.get(req_string, verify=False)
    respXML = et.fromstring(resp.content)
    if resp.status_code != 200:
        err_node = respXML.find('./result/msg')
        logger.error('Code %i, %s' %(resp.status_code, err_node.text))
    result_node = respXML.find('./result')
    if "Successfully changed" in result_node.text:
        logger.info('Successfully suspended %s' %fw_IP)
        return 0
    else:
        logger.error('Issue suspending %s' %fw_IP)
        return 1





def jobChecker(fw_IP, jobID, key):
    """Checks the status of the specified job"""
    logger = logging.getLogger("ugf.jobChecker")
    logger.info('Checking status of job %s on %s' %(jobID, fw_IP))
    req_string = "https://" + fw_IP + "/api/?type=op&cmd=<show><jobs><id>" + jobID +"</id></jobs></show>&key=" + key
    resp = requests.get(req_string, verify=False)
    respXML = et.fromstring(resp.content)
    if resp.status_code != 200:
        err_node = respXML.find('./result/msg')
        logger.error('Code %i, %s' %(resp.status_code, err_node.text))
    status_node = respXML.find('./result/job/status')
    status = status_node.text
    while status == "ACT":
        progress_node = respXML.find('./result/job/progress')
        progress = progress_node.text
        logger.info('Job on %s is %s percent complete' % (fw_IP, progress))
        resp = requests.get(req_string, verify=False)
        respXML = et.fromstring(resp.content)
        status_node = respXML.find('./result/job/status')
        status = status_node.text
        if progress == '99':
            print "Waiting for daemons to complete"
            sleep(180)
            break
        sleep(10)
    resp = requests.get(req_string, verify=False)
    respXML = et.fromstring(resp.content)
    result_node = respXML.find('./result/job/result')
    result = result_node.text
    if result == "OK":
        logger.info('Job %s is complete on %s' %(jobID, fw_IP))
        return 0
    else:
        logger.error('There was an issue with job %s on %s. Status is %s' % (jobID, fw_IP, result))
        return 1

def reboot_FW(fw_IP, key):
    """Reboots the indicated firewall"""
    logger = logging.getLogger("ugf.reboot_FW")
    logger.info('Rebooting %s. This will take several minutes.' %fw_IP)
    req_string = "https://" + fw_IP + "/api/?type=op&cmd=<request><restart><system></system></restart></request>&key=" + key
    resp = requests.get(req_string, verify=False)
    if resp.status_code != 200:
        err_node = respXML.find('./result/msg')
        logger.error('Code %i, %s' %(resp.status_code, err_node.text))
    up_Checker(fw_IP)
    return


def up_Checker(fw_IP):
    """Checks the reachability of the IP specified. Presumes that system isn't
    completely down and is still responding to ping when the function is called."""
    logger = logging.getLogger("ugf.up_Checker")
    status = 0
    while status == 0:
        print "Firewall is shutting down."
        if os.name == 'nt':
            status = os.system('ping -n 1 %s' % fw_IP)
        else:
            status = os.system('ping -c 1 %s' % fw_IP)
        sleep(10)
    while status != 0:
        print "Firewall is down."
        if os.name == 'nt':
            status = os.system('ping -n 1 %s' % fw_IP)
        else:
            status = os.system('ping -c 1 %s' % fw_IP)
    if status == 0:
        print "Firewall is back up. Waiting 10 minutes for OS load and auto commit."
        sleep(600)
    return
