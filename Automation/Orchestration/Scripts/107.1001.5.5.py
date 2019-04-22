import time
import sys
import utils
import products
import TBVars
import re
import kubelib as k8s
from testutil import TestUtil
# import helpers
import yaml

from crdLib import base_path
from crdLib import REWRITE_POLICY_CRD
from crdLib import APPLIED_ALREADY
from crdLib import APPLY_NOW
from crdLib import testCRD
from crdLib import V_LOG
from crdLib import V_REGEXLOG
from crdLib import V_CONFIG


testbed = TBVars.TBFILE
tb = utils.yaml_reader(testbed)
master_ip =  tb['MASTER'][0]['IP']
worker_ip = tb['WORKER'][0]['IP']
net = tb['OPTIONS'][0]['NETWORK']
netmask = tb['NS'][0]['NETMASK']
gateway = tb['NS'][0]['GATEWAY']
tid =  TBVars.TID
password = tb['MASTER'][0]['PASS']
username = tb['MASTER'][0]['USER']
prompt = tb['MASTER'][0]['PROMPT']
ingress = tb['NS'][0]['IP']
coverage = tb['OPTIONS'][0]['Coverage']

# Connecting to the ATS System
param = {
'tid' : TBVars.TID,
'sname':__file__
}
ats = utils.test(param)

param = {
'ip': master_ip,
'user':username,
'passwd':password,
'prompt':prompt,
'ats':ats,
'basic_config':True
}
linux_session = products.linux(param)

input_output_files_operation = [
    ['INGRESS_AND_SERVICES', [['ADD', 'Ingress/citrix_ingress.yaml'],
                             ['ADD', 'CIC/citrix_service.yaml']]],
    ['CRD', [
        ['ADD', "CRD/blacklist_array_of_urls1.yaml", 'CRD/blacklist_array_of_urls1.json', APPLY_NOW, 'SUCCESS', None,
         [V_LOG, V_REGEXLOG, V_CONFIG]],
        ['ADD', "CRD/blacklist_array_of_urls2.yaml", 'CRD/blacklist_array_of_urls2.json', APPLY_NOW, 'SUCCESS', None,
         [V_LOG, V_REGEXLOG, V_CONFIG]],
        ['ADD', "CRD/blacklist_array_of_urls3.yaml", 'CRD/blacklist_array_of_urls3.json', APPLY_NOW, 'SUCCESS', None,
         [V_LOG, V_REGEXLOG, V_CONFIG]]]],

    ['CIC', ['SHUTDOWN', 'WAIT_TILL_TERMINATING']],

    ['WAIT_FOR_SECONDS', ['5','Waiting for CIC to completely shutdown']],

    ['CRD', [
        ['DELETE', "CRD/blacklist_array_of_urls2.yaml", 'CRD/blacklist_array_of_urls2.json', APPLY_NOW, 'SUCCESS', None,
         []],
        ['ADD', "CRD/blacklist_array_of_urls4.yaml", 'CRD/blacklist_array_of_urls4.json', APPLY_NOW, 'SUCCESS', None,
         []],
        ['ADD', "CRD/blacklist_array_of_urls5.yaml", 'CRD/blacklist_array_of_urls5.json', APPLY_NOW, 'SUCCESS', None,
         []]]],

    ['CIC', ['BOOTUP', 'NO_WAIT']],

    ['WAIT_FOR_SECONDS', ['60', 'Waiting for CIC to bootup']],

    ['CRD', [
        ['ADD', "CRD/blacklist_array_of_urls1.yaml", 'CRD/blacklist_array_of_urls1.json', APPLIED_ALREADY, 'SUCCESS',
         None, [V_LOG, V_REGEXLOG, V_CONFIG]],
        ['DELETE', "CRD/blacklist_array_of_urls2.yaml", 'CRD/blacklist_array_of_urls2.json', APPLIED_ALREADY, 'SUCCESS',
         None, [V_REGEXLOG, V_CONFIG]],
        ['ADD', "CRD/blacklist_array_of_urls3.yaml", 'CRD/blacklist_array_of_urls3.json', APPLIED_ALREADY, 'SUCCESS',
         None, [V_LOG, V_REGEXLOG, V_CONFIG]],
        ['ADD', "CRD/blacklist_array_of_urls4.yaml", 'CRD/blacklist_array_of_urls4.json', APPLIED_ALREADY, 'SUCCESS',
         None, [V_LOG, V_REGEXLOG, V_CONFIG]],
        ['ADD', "CRD/blacklist_array_of_urls5.yaml", 'CRD/blacklist_array_of_urls5.json', APPLIED_ALREADY, 'SUCCESS',
         None, [V_LOG, V_REGEXLOG, V_CONFIG]]]],
    ['CLEAN_UP_YAML', ['CRD/blacklist_array_of_urls1.yaml',
                       'CRD/blacklist_array_of_urls2.yaml',
                       'CRD/blacklist_array_of_urls3.yaml',
                       'CRD/blacklist_array_of_urls4.yaml',
                       'CRD/blacklist_array_of_urls5.yaml',
                       'Ingress/citrix_ingress.yaml',
                       'CIC/citrix_service.yaml']]
]
crd_kind = 'rewritepolicies'
testcase = {'id': '107.1001.5.4',
            'name': 'Some CRD files deleted and some CRD files added during CIC reboot'}


test_current_tesecase = testCRD(ats, linux_session, input_output_files_operation, crd_kind, testcase)