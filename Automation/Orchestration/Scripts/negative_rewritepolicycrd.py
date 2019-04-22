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
from crdLib import SUCCESS
from crdLib import FAILURE
from crdLib import V_INPUTVALIDATION

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
def crd_negative_test_init():
    ingress_services_negative_testcase_init = [
        ['INGRESS_AND_SERVICES', [['ADD', 'Ingress/citrix_ingress.yaml'],
                                  ['ADD', 'CIC/citrix_service.yaml']]]
    ]

    testcase = {'id': 'Negative testcase init',
                'name': 'Negative testcase Ingress and Services Init'}

    init_negative_test = testCRD(ats, linux_session, ingress_services_negative_testcase_init, REWRITE_POLICY_CRD,
                                 testcase)
    if not init_negative_test.get_result():
        TestUtil.custom_ats_log(ats, 'red', '6', 'white', 'FAILED: Ingress and service negative testcase init')
        ats.info('Failure values: `{}'.format(str(ingress_services_negative_testcase_init)))
        crd_negative_test_cleanup()
        sys.exit()


def crd_negative_test_cleanup():
    ingress_services_negative_testcase_cleanup = [
        ['CLEAN_UP_YAML', ['Ingress/citrix_ingress.yaml',
                           'CIC/citrix_service.yaml']]]

    testcase = {'id': 'Negative testcase cleanup',
                'name': 'Negative testcase Ingress and Services cleanup'}

    cleanup_negative_test = testCRD(ats, linux_session, ingress_services_negative_testcase_cleanup, REWRITE_POLICY_CRD,
                                    testcase)
    if not cleanup_negative_test.get_result():
        TestUtil.custom_ats_log(ats, 'red', '6', 'white', 'FAILED: Ingress and service negative testcase init')
        ats.info('Failure values: `{}'.format(str(ingress_services_negative_testcase_cleanup)))
try:

    crd_negative_test_init()
    #pdb.set_trace()
    testcase_10_107_1_27 = [
        ['CRD', [
            ['ADD', "CRD/10.107.1.27_crd_1.yaml", None, APPLY_NOW, FAILURE, None,
             [V_INPUTVALIDATION]],
            ['ADD', "CRD/10.107.1.27_crd_2.yaml", 'CRD/10.107.1.27_crd_2.json', APPLY_NOW, FAILURE, 'Nitro exception:Expression syntax error \[http\.req\.\^url1\.equal, Offset [0-9]*\]',
             [V_LOG, V_REGEXLOG, V_CONFIG]]]],
        ['CLEAN_UP_YAML', ['CRD/10.107.1.27_crd_1.yaml','CRD/10.107.1.27_crd_2.yaml']]
    ]
    testcase = {'id': '10.107.1.27',
                'name': 'Validation for two different invalid CRD instance '}

    crd_test = testCRD(ats, linux_session, testcase_10_107_1_27, REWRITE_POLICY_CRD, testcase)

    crd_negative_test_cleanup()

except Exception as e:
    ats.error("Exception: Negative Rewrite Policy CRD {}".format(e.message))
    crd_negative_test_cleanup()




