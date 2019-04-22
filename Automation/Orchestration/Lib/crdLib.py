
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
import os
import json
import requests
import re

from deploymentLib import cic_pod_details
testbed = TBVars.TBFILE
tb = utils.yaml_reader(testbed)

base_path= "~/.system_test_yamls/"
REWRITE_POLICY_CRD = 'rewritepolicies'
APPLIED_ALREADY = 'APPLIED_ALREADY'
APPLY_NOW = 'APPLY_NOW'
LOCAL_TEMPLATE_FILEPATH = os.environ['HOME'] + '/Automation/Orchestration/Config/template_yamls/'

SHUTDOWN = 'SHUTDOWN'
BOOTUP = 'BOOTUP'
REBOOT = 'REBOOT'
WAIT_TILL_TERMINATING = 'WAIT_TILL_TERMINATING'
WAIT_TILL_CREATING = "WAIT_TILL_CREATING"
NO_WAIT = 'NO_WAIT'
CPX = 'CPX'
VPX= 'VPX'
VERIFY = 'VERIFY'
NO_VERIFY = 'NO_VERIFY'
CLEAN_UP_YAML = 'CLEAN_UP_YAML'
NO_RETRY = 'no_retry'
NEED_RETRY = 'NEED_RETRY'
V_CONFIG = 'V_CONFIG'
V_LOG = 'V_LOG'
V_REGEXLOG = 'V_REGEXLOG'
V_INPUTVALIDATION = 'V_INPUTVALIDATION'
SUCCESS = 'SUCCESS'
FAILURE = 'FAILURE'
################################### Subroutines for builtin ###################################

class inputValidationException(Exception):
    pass

class testCRD(object):
    def __init__(self, ats, session, input_output_files_operation, crd_kind, testcase, extra_testcase=[]):
        try:
            testcase_begin_log = 'START EXECUTION: TESTCASE ID: ' + testcase['id'] + ': ' + testcase['name']
            self.send_logs(ats, session, 'purple', '2', 'white', testcase_begin_log)
            self.result = self.segregate_cic_test(ats, session, input_output_files_operation, crd_kind, testcase)
            if self.result:
                testcase_end_log = 'END EXECUTION: PASSED: CRD {} TESTCASE ID: {} {}'.format(
                    crd_kind, testcase['id'], testcase['name']
                )
                self.send_logs(ats, session, 'green', '2', 'white', testcase_end_log)
                ats.res(testcase['id'] +":"+ testcase['name'] + ":PASSED")
                for testcase_instance in extra_testcase:
                    ats.res(testcase_instance['id'] +":"+ testcase_instance['name'] + ":PASSED")

            else:
                testcase_end_log = 'END EXECUTION: FAIL: CRD {} TESTCASE ID: {} {}'.format(
                    crd_kind, testcase['id'], testcase['name']
                )
                self.send_logs(ats, session, 'red', '2', 'white', testcase_end_log)
                ats.res(testcase['id'] + ":" + testcase['name'] + ":FAILED")
                for testcase_instance in extra_testcase:
                    ats.res(testcase_instance['id'] +":"+ testcase_instance['name'] + ":FAILED")
            self.clean_up_testcase_entries(ats, session, input_output_files_operation, crd_kind, testcase)

        except Exception as e:
            self.clean_up_testcase_entries(ats, session, input_output_files_operation,crd_kind, testcase)

    def get_result(self):
        return self.result



    def clean_up_testcase_entries(self, ats, session, input_output_files_operation, crd_kind, testcase):
        clean_up_logs = 'START EXECUTION: CLEAN_UP BLOCK {}'. format(testcase['id'])
        self.send_logs(ats, session, 'peachpuff', '1', 'black', clean_up_logs)
        for operation, values in input_output_files_operation:
            if operation != CLEAN_UP_YAML:
                continue
            for clean_yaml_file in values:
                if 'Ingress' in clean_yaml_file:
                    for ingress_class in cic_pod_details.keys():
                        new_clean_yaml_file = self.get_ingress_yaml_name(clean_yaml_file, ingress_class)
                        try:
                            self.delete_yaml(session, base_path + new_clean_yaml_file)
                        except Exception as e:
                            ats.info('CLEAN UP: ERROR {}'.format(new_clean_yaml_file))
                    continue
                try:
                    self.delete_yaml(session, base_path + clean_yaml_file)
                except Exception as e:
                    ats.error('CLEAN UP: ERROR {}'.format(str(clean_yaml_file)))
        clean_up_logs = 'END EXECUTION: CLEAN_UP BLOCK {}'.format(testcase['id'])
        self.send_logs(ats, session, 'peachpuff', '1', 'black', clean_up_logs)
        return True

    def get_ingress_yaml_name(self, filename, ingress_class):
        return filename[:-5] + '_' + ingress_class + '.yaml'

    def add_ingress_class_within_ingress_file(self, ats, session, filename, ingress_class):
        add_ingress_class_str = 'kubernetes.io/ingress.class: \\"' + ingress_class + '\\"'
        filename_ingress_class = self.get_ingress_yaml_name(filename, ingress_class)
        sed_cmd_has_annotations = 'sed "/annotations/a\    ' + add_ingress_class_str + '" ' +\
                                  base_path + filename + ' > ' + base_path + filename_ingress_class
        sed_cmd_has_no_annotations = 'sed "/metadata/a\  annotations:\n\    ' + add_ingress_class_str + '" ' +\
                                     base_path + filename + ' > ' + base_path + filename_ingress_class
        has_annotations = session.exec_cmd('egrep -ic annotations ' + base_path + filename)
        has_annotations = has_annotations.split('\r\n')[1]
        if has_annotations == '1':
            session.exec_cmd(sed_cmd_has_annotations)
        else:
            session.exec_cmd(sed_cmd_has_no_annotations)

        ingress_class_filename = base_path + filename_ingress_class
        get_name_of_ingress_cmd =  'sed -n "/name:/p" '
        get_name_of_ingress = session.exec_cmd(get_name_of_ingress_cmd + ingress_class_filename)
        get_name_of_ingress = get_name_of_ingress.split('\r\n')[1]
        get_name_of_ingress = get_name_of_ingress.rstrip()
        get_name_of_ingress = get_name_of_ingress + ingress_class.replace('_', '-')

        leading_tabs = len(get_name_of_ingress) - len(get_name_of_ingress.lstrip('\t'))
        leading_spaces = len(get_name_of_ingress) - len(get_name_of_ingress.lstrip(' '))
        if leading_tabs != 0:
            replacestringingress = '\\' +'\t'*leading_tabs + get_name_of_ingress.lstrip()
        if leading_spaces != 0:
            replacestringingress = '\\' +' '*leading_spaces + get_name_of_ingress.lstrip()

        name_replace_cmd = 'sed -i "/name:/c'+replacestringingress + '" '

        session.exec_cmd(name_replace_cmd + ingress_class_filename)


        return filename_ingress_class


    def handle_ingress_and_services(self, ats, session, values, ingress_class):

        for operation in values:
            operator = operation[0]
            filename = operation[1]
            if 'Ingress' in filename:
                filename_ingress_class = self.add_ingress_class_within_ingress_file(ats,
                                                                                    session, filename, ingress_class)
            else:
                filename_ingress_class = filename

            if operator in ['ADD', 'MODIFY']:
                out = self.apply_yaml(session, base_path + filename_ingress_class)
                ats.info(out)
            elif operator is 'DELETE':
                out = self.delete_yaml(session, base_path + filename_ingress_class)
                ats.info(out)
        result = True
        if result:
            ats.info('SUCCESS: CONFIGURE: ingress services  \n values {}'.format(str(values)))
        else:
            ats.error('FAILURE: CONFIGURE: ingress services \n values {}'.format(str(values)))
            raise Exception('While configuring Ingress and services: ')

    def sleep_for_seconds(self, ats, wait_time, user_str = ' '):
        wait_time = int(wait_time)
        if (wait_time <= 12):
            ats.info('Sleeping for {} seconds: {}'.format(wait_time, user_str))
            time.sleep(wait_time)
        else:
            while True:
                ats.info('Sleeping for {} seconds : {}'.format(wait_time, user_str))
                time.sleep(12)
                wait_time = wait_time - 12
                if (wait_time <= 12):
                    ats.info('Sleeping for {} seconds : {}'.format(wait_time, user_str))
                    time.sleep(wait_time)
                    break

    def handle_cic(self, ats, session, cic_name, values):
        result = True
        operator = values[0]
        wait_till = values[1]
        cic_yamlfile = cic_pod_details[cic_name]['cic_yaml']
        if wait_till == NO_WAIT and operator == SHUTDOWN:
            out = self.delete_yaml(session, base_path + cic_yamlfile)
        elif wait_till == WAIT_TILL_TERMINATING and operator == SHUTDOWN:
            self.clean_up(ats, session, [cic_yamlfile])
        elif wait_till == NO_WAIT and operator == BOOTUP:
            out = self.apply_yaml(session, base_path + cic_yamlfile)
        elif wait_till == WAIT_TILL_CREATING and operator == BOOTUP:
            self.bring_up(ats, session, [cic_yamlfile])
        elif wait_till == NO_WAIT and operator == REBOOT:
            out = self.delete_yaml(session, base_path + cic_yamlfile)
            out = self.apply_yaml(session, base_path + cic_yamlfile)
        elif wait_till == WAIT_TILL_CREATING and operator == REBOOT:
            out = self.delete_yaml(session, base_path + cic_yamlfile)
            bring_up(ats, session, [cic_yamlfile])


        if result:
            ats.info('SUCCESS: CONFIGURE: CIC: {} \n {} \n values {}'.format(
                cic_name, cic_yamlfile, values))
        else:
            ats.error('FAILURE: CONFIGURE: CIC: {}  \n {} \n values {}'.format(
                cic_name, cic_yamlfile, values))
            raise Exception('While configuring CIC {}'.format(cic_name))

    def reboot_netscaler(self, ats, netscaler_name, netscaler_ip, operation, wait_till):
        param = {
            'ip': netscaler_ip,
            'user': 'nsroot',
            'passwd': 'nsroot',
            'prompt': '>',
            'ats': ats,
            'basic_config': True
        }
        netscaler_session = products.linux(param)
        if not netscaler_session.expect_session:
            raise Exception('Netscaler VPX {} is unreachable'.format(netscaler_ip))
        netscaler_session.exec_cmd('reboot -f')
        if wait_till == NO_WAIT:
            return True
        elif wait_till == WAIT_TILL_CREATING:
            iterations = 1
            while True:
                if (iterations == 6):
                    break
                netscaler_session = products.linux(param)
                if not netscaler_session.expect_session:
                    self.sleep_for_seconds(ats, 10, 'Waiting for Netscaler {} to boot up'.format(netscaler_ip))
                    iterations = iterations + 1
                    continue
                else:
                    return True
            raise Exception('Netscaler {} not booting up'.format(netscaler_ip))
        else:
            raise Exception('Unknown  wait till {} for NETSCALER option'.format(wait_till))



    def handle_netscaler(self, ats, session, netscaler_details, values):
        netscaler_name = netscaler_details['name']
        netscaler_ip = netscaler_details['ip']
        cpx_yamlfile = netscaler_details['cpx_yaml']
        operation = values[0]
        wait_till = values[1]
        if cpx_yamlfile == None:
            netscaler_type = 'VPX'
        else:
            netscaler_type = 'CPX'

        if operation == SHUTDOWN or operation == BOOTUP or operation != REBOOT:
            raise Exception('Only REBOOT allowed with NETSCALER OPTION: given option {}'.format(str(operation)))

        if netscaler_type == 'CPX':
            if wait_till == NO_WAIT:
                out = self.delete_yaml(session, base_path + cpx_yamlfile)
                out = self.apply_yaml(session, base_path + cpx_yamlfile)
            elif wait_till == WAIT_TILL_CREATING:
                out = self.delete_yaml(session, base_path + cpx_yamlfile)
                self.bring_up(ats, session, [cpx_yamlfile])
            else:
                raise Exception('Unsupported option: {} for NETSCALER option'.format(wait_till))
        elif netscaler_type == VPX:
            result = self.reboot_netscaler(ats, netscaler_name, netscaler_ip, operation, wait_till)

        result = True

        if result:
            ats.info('SUCCESS: CONFIGURE: NETSCALER {}:{} crd_kind {} testcase {}:{} \n values {}'.format(
                netscaler_ip, netscaler_name, crd_kind, testcase['id'], testcase['name'], values
            ))
        else:
            ats.error('FAILURE: CONFIGURE: NETSCALER {}:{} crd_kind {} testcase {}:{} \n values {}'.format(
                netscaler_ip, netscaler_name, crd_kind, testcase['id'], testcase['name'], values
            ))
            raise Exception('While configuring Netscaler {} {}'. format(netscaler_ip, netscaler_name))


    def send_logs(self, ats, session, background_color, font_size, font_color, logs):
        ats.info('</font><br/><font size="'+font_size+'" color="' + font_color +
                 '"><span style="background-color: ' + background_color +'">'+logs+'</span><font size="2" color ="black"">')
    def segregate_cic_test(self, ats, session, input_output_files_operation, crd_kind, testcase):
        try:
            for cic_name, cpx_ip in cic_pod_details.items():
                netscaler_name = cpx_ip['name']
                netscaler_ip = cpx_ip['ip']
                cpx_yamlfile = cpx_ip['cpx_yaml']
                Deployment_logs = 'START EXECUTION: Deployment {} : {}'.format(cic_name, testcase['id'])
                self.send_logs(ats,session, 'orange', '1', 'white', Deployment_logs)
                for operation, values in input_output_files_operation:

                    if operation == 'INGRESS_AND_SERVICES':
                        ingsvc_logs = 'START EXECUTION: INGRESS_AND SERVICES: BLOCK: {} {}'.format(
                            cic_name, testcase['id'])
                        self.send_logs(ats, session, 'peachpuff', '1', 'black', ingsvc_logs)
                        result = self.handle_ingress_and_services(ats, session, values, cic_name)
                        ingsvc_logs = 'END EXECUTION: INGRESS_AND SERVICES: BLOCK: {} {}'.format(
                            cic_name, testcase['id'])
                        self.send_logs(ats, session, 'peachpuff', '1', 'black', ingsvc_logs)

                    elif operation == 'CRD':
                        crd_logs = "START EXECUTION: CRD BLOCK: {}: {}".format(cic_name, testcase['id'])
                        self.send_logs(ats, session, 'peachpuff', '1', 'black', crd_logs)
                        result = self.test_crd_yamls(ats, session, values, crd_kind, netscaler_ip, cic_name)
                        if result:
                            ats.info('SUCCESS: CONFIGURE: CRD crd_kind {} testcase {}:{} \n values {}'.format(
                            crd_kind, testcase['id'], testcase['name'], values
                        ))
                            crd_logs = "END EXECUTION: pass: CRD BLOCK: {} {}".format(cic_name, testcase['id'])
                            self.send_logs(ats, session, 'peachpuff', '1', 'black', crd_logs)
                        else:
                            ats.error('FAILURE: CONFIGURE: CRD crd_kind {} testcase {}:{} \n values {}'.format(
                                crd_kind, testcase['id'], testcase['name'], values
                            ))
                            crd_logs = "END EXECUTION: fail: CRD BLOCK: {} {}".format(cic_name, testcase['id'])
                            self.send_logs(ats, session, 'peachpuff', '1', 'black', crd_logs)
                            raise Exception('While configuring CRD {} {} {}'.format(crd_kind, testcase['id'],
                                                                                    testcase['name']))

                    elif operation == 'CIC':
                        cic_logs = 'START EXECUTION: CIC BLOCK: {} {}'.format(cic_name, testcase['id'])
                        self.send_logs(ats, session, 'peachpuff', '1', 'black', cic_logs)
                        result = self.handle_cic(ats, session, cic_name, values)
                        cic_logs = 'END EXECUTION: CIC BLOCK: {} {}'.format(cic_name, testcase['id'])
                        self.send_logs(ats, session, 'peachpuff', '1', 'black', cic_logs)


                    elif operation == 'NETSCALER':
                        cpx_logs = 'START EXECUTION: NETSCALER BLOCK: {} {}'.format(cic_name, testcase['id'])
                        self.send_logs(ats, session, 'peachpuff', '1', 'black', cpx_logs)
                        netscaler_details = cpx_ip
                        self.handle_netscaler(ats, session, netscaler_details, values)
                        cpx_logs = 'END EXECUTION: NETSCALER BLOCK: {} {}'.format(cic_name, testcase['id'])
                        self.send_logs(ats, session, 'peachpuff', '1', 'black', cpx_logs)

                    elif operation == 'WAIT_FOR_SECONDS':
                        wait_logs = 'START EXECUTION: WAIT: {} BLOCK: {} {}'.format(
                            values[0], cic_name, testcase['id'])
                        self.send_logs(ats, session, 'peachpuff', '1', 'black', wait_logs)
                        self.sleep_for_seconds(ats, values[0], values[1])
                        wait_logs = 'END EXECUTION: WAIT: {} BLOCK: {} {}'.format(
                            values[0], cic_name, testcase['id'])
                        self.send_logs(ats, session, 'peachpuff', '1', 'black', wait_logs)

                self.clean_up_testcase_entries(ats, session, input_output_files_operation, crd_kind, testcase)
                Deployment_logs = 'END EXECUTION: Deployment {} : {}'.format(cic_name, testcase['id'])
                self.send_logs(ats, session, 'orange', '1', 'white', Deployment_logs)
            ats.info('END EXECUTION: PASSED: TESTCASE ID: ' + testcase['id'] + ': ' + testcase['name'])
            return True
        except Exception as e:
            ats.error('END EXECUTION: FAIL: CRD {} TESTCASE ID: {} {} \n Exception {}'.format(
                crd_kind, testcase['id'], testcase['name'], e.message
            ))
            return False

    def test_crd_yamls(self, ats, session, input_output_files_operation, crd_kind, netscaler_ip, cic_name):
        try:
            has_verify = False
            for operation in input_output_files_operation:
                if operation[6] != []:
                    has_verify = True
                    break

            if has_verify == True:
                current_log_timestamp, firstline_timestamp = \
                    self.get_log_timestamp(ats, session, cic_name)
            else:
                current_log_timestamp = None
                firstline_timestamp = None

            for operation in input_output_files_operation:
                operator = operation[0]
                filename = operation[1]
                applied_already = operation[3]
                expected_crd_apply_result = operation[4]
                expected_crd_log = operation[5]
                verify = operation[6]
                if applied_already == APPLIED_ALREADY:
                    continue
                try:
                    if operator in ['ADD', 'MODIFY']:
                        out = self.apply_yaml(session, base_path + filename)
                        ats.info(out)
                    elif operator is 'DELETE':
                        out = self.delete_yaml(session, base_path + filename)
                        ats.info(out)
                    if V_INPUTVALIDATION in verify and expected_crd_apply_result == FAILURE:
                        raise Exception('Input validation not executed: fail: file {}'.format(base_path + filename))
                except inputValidationException as e:
                    if V_INPUTVALIDATION in verify and expected_crd_apply_result == FAILURE:
                        ats.info('Input validation executed: pass: file: {}'.format(base_path + filename))
                    else:
                        raise Exception('Input validation executed: fail: file {}'.format(base_path + filename))
            result = self.crd_result_verify(ats, session, input_output_files_operation, cic_name, current_log_timestamp,
                                            firstline_timestamp)
            if result == False:
                ats.error('FAILURE: CRD initial Verification CIC {} kind {}'.format(cic_name, crd_kind))
                return False

            for output_file_verification in input_output_files_operation:
                output_file_operator = output_file_verification[0]
                input_yamlfile = output_file_verification[1]
                output_filename = output_file_verification[2]
                expected_crd_result = output_file_verification[4]
                verify = output_file_verification[6]
                if V_CONFIG not in verify:
                    continue
                with open(LOCAL_TEMPLATE_FILEPATH + input_yamlfile) as f:
                    data = yaml.load(f)
                    crd_instance_name = data['metadata']['name']

                    crd_instance_version = k8s.get_crd_version(session, crd_kind, crd_instance_name)
                    if crd_instance_version is None:
                        ats.error(
                            "Failed to fetch crd instance version for {}.{}".format(crd_kind, crd_instance_name))
                        return False

                """check keys mentioned in edits in crd_output.json and replace with value in edits"""
                edits = {'CRDINSTANCEVERSION': crd_instance_version,
                         'REPLACE_INGRESSCLASS': cic_name}

                crd_output_file = LOCAL_TEMPLATE_FILEPATH + output_filename
                with open(crd_output_file) as f:
                    expected_output = json.load(f)
                expected_output = TestUtil.replace_pattern(ats, expected_output, edits)
                if expected_output is None:
                    ats.error('Failed to setup expected output {}.{}'.format(crd_kind, crd_output_file))
                    return False

                for k, v in expected_output.iteritems():
                    ns_output = k8s.get_conf(netscaler_ip, k)
                    if (output_file_operator == 'DELETE' and not ns_output):
                        continue
                    if (output_file_operator in ['ADD', 'MODIFY'] and not ns_output and expected_crd_result == SUCCESS):

                        ats.error("{} is not configured on NS for {}.{}".format(k, crd_kind, crd_instance_name))
                        return False

                    compare_output_result = TestUtil.compare_output(ats, v, ns_output, k)
                    if (output_file_operator in ['ADD', 'MODIFY'] and not compare_output_result and
                            expected_crd_result == SUCCESS):
                        ats.error(
                            'Failed to add configuration {} with {}.{}'.format(str(v), crd_kind, crd_instance_name))

                        return False
                    elif output_file_operator is 'DELETE' and compare_output_result:
                        ats.error(
                            'Failed to delete config {} with {}.{}'.format(str(v), crd_kind, crd_instance_name))
                        return False

            return True

        except Exception as e:
            ats.error('Failed for crd implementation with error: {}'.format(e.message))
            ats.info('Failed input_output_files_operation: {}'.format(input_output_files_operation))
            return False


    def crd_singleyaml_verify(self, ats, session, crd_yamlfile, operation, expected_result, cic_name, log_file_path,
                              verify, custom_regex_pattern=None):
        failure_event_dict = {'SUCCESS': 'FAILURE', 'FAILURE': 'SUCCESS'}
        failure_result = failure_event_dict[expected_result]

        with open(LOCAL_TEMPLATE_FILEPATH + crd_yamlfile) as f:
            data = yaml.load(f)
            crd_instance_name = data['metadata']['name']
        search_regex_string = operation + '.*?event.*?' + str(expected_result) + '.*?' + crd_instance_name
        failure_regex_string = operation + '.*?event.*?' + str(failure_result) + '.*?' + crd_instance_name
        operation_result = session.exec_cmd('egrep -ic ' + search_regex_string + ' ' + log_file_path)
        operation_result = operation_result.split('\r\n')[1]
        failure_operation_result = session.exec_cmd('egrep -ic ' + failure_regex_string + ' ' + log_file_path)
        failure_operation_result = failure_operation_result.split('\r\n')[1]

        if V_LOG not in verify:
            failure_operation_result = '0'
            operation_result = '1'

        if V_REGEXLOG in verify:
            if not custom_regex_pattern:
                custom_log_result = 1
            else:

                custom_log_regex_pattern = 'egrep -ic ' + ' "'+custom_regex_pattern+'" ' + log_file_path
                custom_log_result = session.exec_cmd(custom_log_regex_pattern)
                custom_log_result = custom_log_result.split('\r\n')[1]
        else:
            custom_log_result = '1'


        if failure_operation_result != '0':
            ats.error(
                'FAILURE: CRD apply file {}: {}.{} expected result {}'.format(crd_yamlfile, operation, crd_instance_name,
                                                                              expected_result))
            return [False, NO_RETRY]
        if operation_result != '0' and custom_log_result != '0':
            ats.info('PASS: CRD apply file {}: {}.{} expected result {}'.format(crd_yamlfile, operation, crd_instance_name,
                                                                                expected_result))
            return [True, NO_RETRY]
        if operation_result != '0' and custom_log_result == '0':
            ats.error('FAILURE: custom regex_match: {} :PASS: CRD file apply  {}: {}.{} expected result {}'.format(
                custom_regex_pattern, crd_yamlfile, operation, crd_instance_name, expected_result))
            return [False, NO_RETRY]
        if operation_result == '0' and failure_operation_result == '0':
            ats.info(
                'Waiting for 2 seconds for CRD file {} : {}.{} to apply expected result: {}'.format(
                    crd_yamlfile, operation, crd_instance_name, expected_result))
            return [False, NEED_RETRY]

    def crd_result_verify(self, ats, session, input_output_files_operation, cic_name, current_log_timestamp,
                          firstline_timestamp):

        max_retries = 6
        for operation in input_output_files_operation:
            operator = operation[0]
            crd_yamlfile = operation[1]
            applied_already = operation[3]
            expected_crd_apply_result = operation[4]
            crd_custom_regex_log_pattern = operation[5]
            verify = operation[6]
            if V_LOG not in verify and V_REGEXLOG not in verify:
                continue

            for idx_retry in range(max_retries):
                if applied_already == APPLIED_ALREADY:
                    timestamp = firstline_timestamp
                else:
                    timestamp = current_log_timestamp

                trimmed_log_file = self.get_trimmed_logfile(ats, session, cic_name, timestamp)
                result = self.crd_singleyaml_verify(ats, session, crd_yamlfile, operator, expected_crd_apply_result,
                                                    cic_name, trimmed_log_file, verify, crd_custom_regex_log_pattern)
                if result[0] == False and result[1] == NO_RETRY:
                    ats.error('FAILURE: CRD: VERIFY {} {} expected result {} custom_regex_pattern {}'. format(operator, crd_yamlfile, expected_crd_apply_result, crd_custom_regex_log_pattern))
                    return False
                elif result[0] == False and result[1] == NEED_RETRY:
                    if idx_retry == max_retries - 1:
                        ats.error('FAILURE: CRD: VERIFY: max retries done: {} {}.{} expected result {} custom_regex_pattern {}'.format(idx_retry, max_retries, operator, crd_yamlfile, expected_crd_apply_result, crd_custom_regex_log_pattern))
                        return False
                    ats.info('RETRY: CRD: VERIFY: retry count: {} : max retries: {} : {}.{} expected result {} custom_regex_pattern {}'.format(idx_retry, max_retries, operator, crd_yamlfile, expected_crd_apply_result, crd_custom_regex_log_pattern))
                else:
                    ats.info('PASSED: CRD: VERIFY {} {} expected result {} custom_regex_pattern {}'. format(operator, crd_yamlfile, expected_crd_apply_result, crd_custom_regex_log_pattern))
                    break

        return True

    def clean_up(self, ats, session, delete_yamls):
        ats.info("\n**********Cleaning up all the pods and resources.************")
        for cmd in delete_yamls:
            out = k8s.apply_cmd(session, "kubectl delete -f " + base_path + cmd)
            if 'error' in out.lower():
                raise Exception('YAML DELETE: FAIL: {} \n Reason: {}'.format(base_path + cmd),
                                k8s.delete_first_last_line(out))

        self.wait_till_terminating(ats, session)

    def bring_up(self, ats, session, create_yamls):
        ats.info("\n**********Cleaning up all the pods and resources.************")
        for cmd in create_yamls:
            out = k8s.apply_cmd(session, "kubectl create -f " + base_path + cmd)
            if 'error' in out.lower():
                raise Exception('YAML APPLY: FAIL {} \n Reason: {}'.format(base_path + cmd),
                                k8s.delete_first_last_line(out))
            # out = k8s.create_yaml(session, base_path+cmd)
        time.sleep(2)
        self.wait_till_creating(ats, session)

    def apply_yaml(self, session, path):

        cmd = 'kubectl apply -f %s' % path
        out = session.exec_cmd(cmd)
        out = session.exec_cmd(cmd)
        if 'error' in out.lower() and 'unchanged' not in out.lower():
            raise Exception('YAML APPLY: FAIL {} \n Reason: {}'.format(base_path + cmd),
                            k8s.delete_first_last_line(out))
        if 'created' not in out.lower() and 'unchanged' not in out.lower() and 'configured' not in out.lower():
            raise inputValidationException('INPUT VALIDATION: APPLY YAML: fail: \n file: {}'.format(base_path + cmd))
        out = k8s.delete_first_last_line(out)
        return out

    def delete_yaml(self, session, path):
        cmd = 'kubectl delete -f %s' % path
        out = session.exec_cmd(cmd)
        if 'error' in out.lower() and 'notfound' not in out.lower():
            raise Exception('YAML APPLY: FAIL {} \n Reason: {}'.format(base_path + cmd),
                            k8s.delete_first_last_line(out))
        if 'deleted' not in out.lower() and 'notfound' not in out.lower():
            raise inputValidationException('INPUT VALIDATION: DELETE YAML: fail: \n file: {}'.format(base_path + cmd))
        out = k8s.delete_first_last_line(out)
        return out

    def get_log_timestamp(self, ats, session, cic_name):

        logfile = self.get_logs(ats, session, cic_name, 'crd_test', "app",
                                cic_pod_details[cic_name]['cic_container_name'])

        current_timestamp = session.exec_cmd('sed -n \'$p\' ' + logfile + ' | awk \'{print $1,$2}\'')
        firstline_timestamp = session.exec_cmd('sed -n \'30p\' ' + logfile + ' | awk \'{print $1,$2}\'')
        current_timestamp = current_timestamp.split('\r\n')[1]
        firstline_timestamp = firstline_timestamp.split('\r\n')[1]
        timestamp_pattern = '[0-9]*-[0-9]*-[0-9]*'
        if not re.search(timestamp_pattern, current_timestamp)\
                or not re.search(timestamp_pattern, firstline_timestamp):

            raise Exception('ERROR: Log file Timestamp retrival: timestamp retrieved {} {}'.format(current_timestamp,
                                                                                                   firstline_timestamp))

        return current_timestamp, firstline_timestamp

    def get_trimmed_logfile(self, ats, session, cic_name, from_timestamp):

        log_file = self.get_logs(ats, session, cic_name, 'crd_test', "app",
                                 cic_pod_details[cic_name]['cic_container_name'])
        trimmedlogfile = log_file + '_trimmed'
        session.exec_cmd('sed -n -e \'/' + from_timestamp + '/,$p\' ' + log_file + ' > ' + trimmedlogfile)
        return trimmedlogfile

    def get_logs(self, ats, linux_session, value, tc_id, label="app", container = None):
        cic_pod_name = k8s.get_cpx_ns(linux_session, label, value)
        if len(cic_pod_name) > 0:
            cic_pod_name = cic_pod_name[0]
            ats.info("Getting info")
            path_for_logs = "~/cic_logs_system_test/" + cic_pod_name + "_" + tc_id
            if not container:
                linux_session.exec_cmd("kubectl logs " + cic_pod_name + " > " + path_for_logs)
            else:
                linux_session.exec_cmd("kubectl logs " + cic_pod_name + " -c " + container+ " > " + path_for_logs)
            return path_for_logs

    def wait_till_terminating(self, ats, linux_session):
        ats.info("Waiting for the pods to terminate.")
        cmd = 'kubectl get pods --all-namespaces | grep Terminating --color=Never'
        pods_terminating = 1
        while pods_terminating > 0:
            out = linux_session.exec_cmd(cmd)
            pods_terminating = len(out.split("\r\n")[1:-1])
            ats.info("Terminating pods: " + str(pods_terminating))
            time.sleep(2)

    def wait_till_creating(self, ats, linux_session):
        ats.info("Waiting for the pods to start. Initial wait 10 seconds")
        time.sleep(10)
        cmd = 'kubectl get pods --all-namespaces | grep ContainerCreating --color=Never'
        out = linux_session.exec_cmd(cmd)

        pods_creating = len(out.split("\r\n")[1:-1])

        ats.info("Creating pods: " + str(pods_creating))
        in_while_loop = False
        while pods_creating > 0:
            in_while_loop = True
            out = linux_session.exec_cmd(cmd)
            pods_creating = len(out.split("\r\n")[1:-1])
            ats.info("Creating pods: " + str(pods_creating))
            time.sleep(2)
        if in_while_loop:
            time.sleep(10)
