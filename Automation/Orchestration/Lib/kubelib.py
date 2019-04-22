import pdb
import time
import sys
import os
import re
import requests
import urllib
import json
import ipaddress
import TBVars
import utils
import pdb

from massrc.com.citrix.mas.nitro.resource.Base import base_resource
from massrc.com.citrix.mas.nitro.exception.nitro_exception import nitro_exception
from massrc.com.citrix.mas.nitro.service.nitro_service import nitro_service
from massrc.com.citrix.mas.nitro.resource.config.ns import ns
from massrc.com.citrix.mas.nitro.resource.config.mps.managed_device import managed_device
from massrc.com.citrix.mas.nitro.resource.config.mps.triton_config import triton_config
from massrc.com.citrix.mas.nitro.resource.config.mps.kubernetes_param import kubernetes_param
from massrc.com.citrix.mas.nitro.resource.config.ns.ns import ns
from massrc.com.citrix.mas.nitro.resource.config.ns.ns_lbvserver import ns_lbvserver
from massrc.com.citrix.mas.nitro.resource.config.ns.ns_servicegroupmember_binding import ns_servicegroupmember_binding

def apply_cmd(session, cmd):
    out = session.exec_cmd(cmd)
    if "curl" not in cmd:
        out = delete_first_last_line(out)
        if ("ingress" in out and "AlreadyExists" in out):
            time.sleep(30)
            out = session.exec_cmd(cmd)
            out = delete_first_last_line(out)

    return out

def apply_yaml(session, path):
    cmd = 'kubectl apply -f %s'%path
    out = session.exec_cmd(cmd)
    out = delete_first_last_line(out)
    return out

def delete_yaml(session, path):
    cmd = 'kubectl delete -f %s'%path
    out = session.exec_cmd(cmd)
    out = delete_first_last_line(out)
    return out

def check_status(session, obj, name):
    if (obj == 'pod'):  
        cmd = 'kubectl get %s -l app=%s --field-selector=status.phase==Running'%(obj, name)
        out = session.exec_cmd(cmd)
        pods_running = len(out.split("\r\n")[1:-1]) - 1 # title row is ignored.
        
        cmd = 'kubectl get %s -l app=%s'%(obj, name)
        out = session.exec_cmd(cmd)
        pods_tot = len(out.split("\r\n")[1:-1]) - 1 # title row is ignored.
        
        return int(pods_running == pods_tot)

    if (obj == 'replicationcontroller'):
        cmd = 'kubectl -ojson get %s -l app=%s'%(obj, name)
        out = session.exec_cmd(cmd)

        json_str = delete_first_last_line(out)
        try:
            json_response = json.loads(json_str)
        except:
            ats.info("There was an exception in loading the json string will try once more...")
            json_str = delete_first_last_line(out)
            try:
                out = session.exec_cmd(cmd)
                json_response = json.loads(json_str)
            except:
                ats.info("No luck in trying it again... Sorry")
                return False

        if 'readyReplicas' in json_response['items'][0]['status']:
            replicas_ready = json_response['items'][0]['status']['readyReplicas']
            replicas_desired = json_response['items'][0]['status']['replicas']
            return int(replicas_ready == replicas_desired)
        else:
            return False

    if (obj == 'deployment'):
        cmd = 'kubectl -ojson get %s -l app=%s'%(obj, name)
        out = session.exec_cmd(cmd)

        json_str = delete_first_last_line(out)
        try:
            json_response = json.loads(json_str)
        except:
            ats.info("There was an exception in loading the json string will try once more...")
            json_str = delete_first_last_line(out)
            try:
                out = session.exec_cmd(cmd)
                json_response = json.loads(json_str)
            except:
                ats.info("No luck in trying it again... Sorry")
                return False

        if 'readyReplicas' in json_response['items'][0]['status']:
            replicas_ready = json_response['items'][0]['status']['readyReplicas']
            replicas_desired = json_response['items'][0]['status']['replicas']
            return int(replicas_ready == replicas_desired)
        else:
            return False

    # if (obj == 'ing'):
    #     # do something

def get_endpoints(session, name, namespace = "default"):
    cmd = 'kubectl -ojson get endpoints %s'%name
    cmd = cmd+" -n "+namespace
    out = session.exec_cmd(cmd)
    if("Error from server" in out):
        return []
    json_str = delete_first_last_line(out)
    try:
        json_response = json.loads(json_str)
    except:
        ats.info("There was an exception in loading the json string will try once more...")
        json_str = delete_first_last_line(out)
        try:
            out = session.exec_cmd(cmd)
            json_response = json.loads(json_str)
        except:
            ats.info("No luck in trying it again... Sorry")
            return False

    if 'addresses' in json_response['subsets'][0]:
        addresses_list = json_response['subsets'][0]['addresses']
    else:
        addresses_list = []
    endpoints = []
    for address in addresses_list:
        endpoints.append(address['ip'])
    return endpoints

def check_cpx_services(session, service_name, namespace, protocol, ingress_name, port, direction, label_name="app", value="cpx-ingress", container="cpx "):
    data = {'serviceName':service_name, 'namespace':namespace, 'ingPort':protocol, 'port':port, 'ingressName':ingress_name}
    testbed = TBVars.TBFILE
    tb = utils.yaml_reader(testbed)
    pattern = tb['TEMPLATE'][0]['LBVS']
    l_tags = re.findall('<(.*?)>', pattern)
    lbvs_name = pattern
    for tag in l_tags:
        lbvs_name = lbvs_name.replace("<"+tag+">", data[tag])
    # apply_cmd(session, lbvs_name)
    if direction=='ew':
        cpx_list = get_cpx_ew(session)
    else:
        cpx_list = get_cpx_ns(session, label_name, value)

    cpx_cmd = 'sh lbvs %s'%lbvs_name

    active_services = 0
    endpoints_list = []
    for cpx in cpx_list:
        if value == "builtin-hostport" or container != "cpx ":
            cpx = cpx + " -c "+ container
        k8s_cmd = " kubectl exec %s /var/netscaler/bins/cli_script.sh '%s' "%(cpx, cpx_cmd)
        sh_cmd = "sh lbvs"
        k8s_sh_cmd = " kubectl exec %s /var/netscaler/bins/cli_script.sh '%s' "%(cpx, sh_cmd)
        out_1 = apply_cmd(session, k8s_sh_cmd)
        out = apply_cmd(session, k8s_cmd)

        extract_after = 'Group Name:'
        extract_before = 'CSPolicy:'
        if(len(out.split(extract_after)) > 1):
            out = out.split(extract_after)[1]
            out = out.split(extract_before)[0]
            out = delete_first_last_line(out)
            if out == "":
                services_list = []
            else:
                services_list = out.split("\r\n")
                services = []
                for service in services_list:
                    if "State" in service:
                        services.append(service)
                services_list = services
        else:
            active_services = 0
            services_list = []
        endpoints_list = get_endpoints(session, service_name, namespace)
        apply_cmd(session,"echo \""+ str(len(services_list))+" Service list : "+ out+" List of cpx "+str(len(cpx_list)*len(endpoints_list)) + "\"")
        if len(services_list) == len(cpx_list)*len(endpoints_list):
            for endpoint in endpoints_list:
                for service in services_list:
                    if ((str(endpoint) in service) and ('State: UP' in service)):
                        active_services = active_services + 1
                        break
        else:
            cmd = "echo service_list = "+str(len(services_list)) + " Endpoints List" + str(len(cpx_list)*len(endpoints_list))
            apply_cmd(session, cmd)
            for service in services_list:
                if ('State: UP' in service):
                    active_services = active_services + 1
                    break
    cmd = "echo Active services = "+str(active_services) + " Endpoints List = " + str(len(cpx_list)*len(endpoints_list))
    apply_cmd(session, cmd)
    return int(active_services == len(cpx_list)*len(endpoints_list))

def check_vpx_services(session, master_session, service_name, namespace, protocol, ingress_name, port, direction, age):
    data = {'serviceName':service_name, 'namespace':namespace, 'ingPort':protocol, 'port':port, 'ingressName':ingress_name}
    testbed = TBVars.TBFILE
    tb = utils.yaml_reader(testbed)
    pattern = tb['TEMPLATE'][0]['LBVS']
    l_tags = re.findall('<(.*?)>', pattern)
    lbvs_name = pattern
    for tag in l_tags:
        lbvs_name = lbvs_name.replace("<"+tag+">", data[tag])

    if(age == 'old'):
        lbvs_name = 'k8s_'+service_name+'.'+namespace+'.'+protocol
    sh_cmd = 'sh lbvs'
    cpx_cmd = 'sh lbvs %s'%lbvs_name
    session.exec_cmd(sh_cmd)
    out = session.exec_cmd(cpx_cmd)
    active_services = 0

    extract_after = 'Group Name:'
    extract_before = 'CSPolicy:'
    if(len(out.split(extract_after)) > 1):
            out = out.split(extract_after)[1]
            out = out.split(extract_before)[0]
            out = delete_first_last_line(out)
            if out == "":
                services_list = []
            else:
                services_list = out.split("\r\n")
                services = []
                for service in services_list:
                    if "State" in service:
                        services.append(service)
                services_list = services
    else:
            active_services = 0
            services_list = []
    endpoints_list = get_endpoints(master_session, service_name, namespace)
    apply_cmd(master_session, "echo \"" + str(len(services_list)) + " Service list: "+out + " Endpoints = " + str(len(endpoints_list)) + "\"")
    if len(services_list) == len(endpoints_list):
        for endpoint in endpoints_list:
            for service in services_list:
                    if ((str(endpoint) in service) and ('State: UP' in service)):
                        active_services = active_services + 1
                        break
    return int(active_services == len(endpoints_list))

def get_cpx_ew(session):
    out = apply_cmd_listoutput(session, 'kubectl get pods -l app=cpx-daemon')
    cpx_list = [x.split(" ")[0] for x in out[1:]] # exclude the first line containing the title for each column, then get cpx names till space
    return cpx_list

def get_cpx_ns(session, label_name="app", value="cpx-ingress"):
    out = apply_cmd_listoutput(session, 'kubectl get pods -l '+label_name+'='+value)
    cpx_list = [x.split(" ")[0] for x in out[1:]] # exclude the first line containing the title for each column, then get cpx names till space
    return cpx_list

def mas_login(mas_ip):
    username = 'nsroot'
    password = 'nsroot'
    try :
        cli = nitro_service(mas_ip,"http","v1")
        cli.set_credential(username,password)
        cli.timeout = 1800
        login_info = cli.login()
        login_token = login_info['login'][0]['token']
        print 'login_token: {}'.format(login_token)
        login_sessionid = login_info['login'][0]['sessionid']
        print 'login_sessionid: {}'.format(login_sessionid)
        return cli
    except nitro_exception as  e:
        print("Exception::errorcode="+str(e.errorcode)+",message="+ e.message)
        return e.message


def mas_cpx_check(mas_session):
    cli = mas_session
    dev = ns()
    cpx_list = dev.get_filtered(cli, 'ns_ip_address:192.168.1.2')
    count = 0
    for cpx in cpx_list:
        if (cpx.instance_state == "Up"): # OR if (cpx.node_state == "UP"):
            count = count + 1
    return int(count == len(cpx_list))


def mas_lbvserver_check(mas_session, service_name, namespace, protocol):
    cli = mas_session   
    lbv = ns_lbvserver()
    lbvs_name = service_name+'.'+namespace+'.'+protocol
    filter = 'name:%s'%lbvs_name
    lbvs_list = lbv.get_filtered(cli, filter)
    count = 0
    for lbvs in lbvs_list:
        if (lbvs.vsvr_state == "UP"): # OR: if(lbvs.state == "Up"):
            count = count + 1
    return int(count == len(lbvs_list))


def mas_service_binding_check(mas_session, service_name, namespace, protocol):
    cli = mas_session
    svcgrpmembin = ns_servicegroupmember_binding()
    servicegroupmember_name =  service_name+'.'+namespace+'.'+protocol
    filter = 'servicegroupname:%s'%servicegroupmember_name # servicegroupmember name is the same as servicegroup name, and even the json key is just servicegroupname and not servicegroupmembername
    servicegroupmember_list = svcgrpmembin.get_filtered(cli, filter)
    count = 0
    for servicegroupmember in servicegroupmember_list:
        if(servicegroupmember.svrstate == "UP"):
            count = count + 1
    return int(count == len(servicegroupmember_list))


def check_ingress_device_services(ingress_session, kub_master_session, service_name, namespace, protocol):
    # lbvs_name = service_name+'.'+namespace+'.'+protocol
    lbvs_name = 'web-ingress.default.80-web-frontend.default.http-lb'
    cmd = 'sh lbvs %s'%lbvs_name
    out = apply_cmd(ingress_session, cmd)

    extract_after = 'Group Name: web-ingress.default.80-web-frontend.default.http-svcgrp'
    out = out.split(extract_after)[1]
    out = delete_first_last_line(out)
    services_list = out.split("\r\n")[1:] # remove the additional empty that's still left behind in previous output

    endpoints_list = get_endpoints(kub_master_session, service_name, namespace)
    active_services = 0
    for endpoint in endpoints_list:
        for service in services_list:
            if ((str(endpoint) in service) and ('State: UP' in service)):
                active_services = active_services + 1
    return int(active_services == len(endpoints_list))




# Remove first and last line of output and return as string. 
# Used when "out.strip("\r\n")[1:-1]" can't be used to extract a multi-line string like a json.
def delete_first_last_line(s):
    s = s.split('\n', 1)[-1]
    if s.find('\n') == -1:
        return ''
    return s.rsplit('\n', 1)[0]

def apply_cmd_listoutput(session, cmd):
    out = session.exec_cmd(cmd)
    out = out.split("\r\n")[1:-1]
    return out

def apply_yaml_listoutput(session, path):
    cmd = 'kubectl apply -f %s'%path
    out = session.exec_cmd(cmd)
    out = out.split("\r\n")[1:-1]
    return out

def delete_yaml_listoutput(session, path):
    cmd = 'kubectl delete -f %s'%path
    out = session.exec_cmd(cmd)
    out = out.split("\r\n")[1:-1]
    return out

def scale(ats, session, no_replicas, resource_type, catalogue):
    ats.info("\n Scaling the "+catalogue+" to "+str(no_replicas)+" replicas\n")
    cmd = "kubectl scale --replicas="+str(no_replicas)+" "+resource_type+"/"+catalogue
    out = apply_cmd(session, cmd)
    if "Error from server" in out:
        return 0
    return 1

def cluster_node_ips(session):
    out = session.exec_cmd("kubectl describe nodes | grep InternalIP")
    ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', out )
    return ips

def node_flannel_network(session):
    out = session.exec_cmd("ifconfig cni")
    out = re.findall(r'[0-9]+(?:\.[0-9]+){3}', out)
    if len(out) != 3:
        out = session.exec_cmd("ifconfig flannel.1")
        out = re.findall(r'[0-9]+(?:\.[0-9]+){3}', out)
    return out

def check_ha_status(session):
    out = session.exec_cmd("sh ha node")
    if re.search('Sync State: SUCCESS',out):
       return 1
    else:
       return 0

def get_ips_of_pods(session, pod_name):
    out = session.exec_cmd("kubectl get pods -o wide | grep "+pod_name+" | awk '{print $6;}'")
    out = delete_first_last_line(out)
    ips = out.split('\n')
    return ips

# TODO: This should be done using labels
def update_hosts(session, pod_name, url, ats):
    ips = get_ips_of_pods(session, pod_name)
    ats.info("\n\n\n\n###############\nThe IP of the cpx-ingress pod is : "+ips[0]+"\n####################\n")
    for ip in ips:
        current_ip = ip.strip()
        echo_cmd = current_ip+" "+url
        out = session.exec_cmd("echo '"+echo_cmd+"' >> /etc/hosts")
        session.exec_cmd(r'sed -r -i.bak "s/^ *[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+( +'+url+')/'+current_ip+r'\1/" /etc/hosts')

# k8s-<vip>:<port>:<protocol>
def check_cpx_csvs(session, service_name, namespace, ports, vip_service, age, label_name="app", value="cpx-ingress", container="cpx "): 
    data = {'vip':vip_service, 'namespace':namespace, 'ports':ports, 'port': '', 'protocol': ''}
    testbed = TBVars.TBFILE
    tb = utils.yaml_reader(testbed)
    pattern = tb['TEMPLATE'][0]['CSVS']

    l_tags = re.findall('<(.*?)>', pattern)
    services = []
    for port in data['ports']:
        csvs_name = pattern
        data['port'] = data['ports'][port]
        data['protocol'] = port
        for tag in l_tags:
            if tag in data:
                csvs_name = csvs_name.replace("<"+tag+">", data[tag])
            elif tag in ingress:
                csvs_name = csvs_name.replace("<"+tag+">", ingress[tag])
            else:
                csvs_name = ''
                break
        if csvs_name is not '':
            services.append(csvs_name)

    pass_count = 0
    cpx_list = get_cpx_ns(session, label_name, value)
    apply_cmd(session, "echo the cpxs that I have found are : "+str(cpx_list))
    apply_cmd(session, "echo the csvs that I have found are : "+str(services))
    for cpx in cpx_list:
        if value == "builtin-hostport" or container != "cpx ":
            cpx = cpx + " -c "+ container
        for service in services:
            csvs_cmd = "kubectl exec "+cpx+" /var/netscaler/bins/cli_script.sh 'shcsvs "+service+"'"
            sh_cmd = "kubectl exec "+cpx+" /var/netscaler/bins/cli_script.sh 'shcsvs'"
            sh_out = apply_cmd(session, sh_cmd)
            csvs_out = apply_cmd(session, csvs_cmd)
            if "State: UP" in csvs_out:
                pass_count+=1

    return int(pass_count == len(ports))


def check_status_ats(session, obj, name, ats):
    if (obj == 'pod'):  
        cmd = 'kubectl get %s -l app=%s --field-selector=status.phase==Running'%(obj, name)
        out = session.exec_cmd(cmd)
        pods_running = len(out.split("\r\n")[1:-1]) - 1 # title row is ignored.
        
        cmd = 'kubectl get %s -l app=%s'%(obj, name)
        out = session.exec_cmd(cmd)
        pods_tot = len(out.split("\r\n")[1:-1]) - 1 # title row is ignored.
        
        return int(pods_running == pods_tot)

    if (obj == 'replicationcontroller'):
        cmd = 'kubectl -ojson get %s -l app=%s'%(obj, name)
        out = session.exec_cmd(cmd)

        ats.info("OUTPUT : \n" + str(out))
        
        json_str = delete_first_last_line(out)
        try:
            json_response = json.loads(json_str)
        except:
            ats.info("There was an exception in loading the json string will try once more...")
            json_str = delete_first_last_line(out)
            try:
                out = session.exec_cmd(cmd)
                json_response = json.loads(json_str)
            except:
                ats.info("No luck in trying it again... Sorry")
                return False

        if 'readyReplicas' in json_response['items'][0]['status']:
            replicas_ready = json_response['items'][0]['status']['readyReplicas']
        else:
            replicas_ready = -1
        if 'replicas' in json_response['items'][0]['status']:
            replicas_desired = json_response['items'][0]['status']['replicas']
        else:
            replicas_desired = -2

        return int(replicas_ready == replicas_desired)

def check_cpx_cspolicy(session, service_name, namespace, protocol, ingress_name, port, direction, label_name="app", value="cpx-ingress", container="cpx "):
    cpx_list = get_cpx_ns(session, label_name, value)
    policy_name = 'k8s-'+ingress_name+'.'+namespace+'.'+port+'.'+'k8s-'+service_name+'.'+namespace+'.'+protocol+'.svc'
    cspolicy_cmd = ""
    for cpx in cpx_list:
        if value == "builtin-hostport" or container != "cpx ":
            cpx = cpx + " -c "+ container
        cspolicy_cmd = "kubectl exec "+cpx+" /var/netscaler/bins/cli_script.sh 'shcspolicy "+policy_name+"'"
        sh_cmd = "kubectl exec " + cpx + " /var/netscaler/bins/cli_script.sh 'shcspolicy'"
        sh_out = apply_cmd(session, sh_cmd)
        cspolicy_out = apply_cmd(session, cspolicy_cmd)
        if "Rule:" in cspolicy_out:
            return True
    return False

# TODO: Clean this up by creating a function for checking ns feature with feature and ingress as the parameter. Creating the names on fly.
def check_ns_feature(session, feature, item, to_search, label_name="app", value="cpx-ingress", container="cpx "):
    cpx_list = get_cpx_ns(session, label_name, value)
    for cpx in cpx_list:
        if value == "builtin-hostport" or container != "cpx ":
            cpx = cpx + " -c "+ container
        check_cmd = "kubectl exec "+cpx+" /var/netscaler/bins/cli_script.sh 'sh "+feature+" "+item+"' | grep "+"\""+to_search+"\""
        check_out = apply_cmd(session, check_cmd)
        if to_search in check_out:
            return True
    return False

# TODO: This is a work in progress. Other k8s resources also needs to be accounted for
def complete_clean_up(linux_session):
    cmd_list = [
        "kubectl delete namespace test",
        "kubectl delete deployment --all",
        "kubectl delete deployment --all -n test",
        "kubectl delete pods --all",
        "kubectl delete ing --all",
        "kubectl delete ing --all -n test",
        "kubectl delete svc --all",
        "kubectl delete svc --all -n test",
        "kubectl delete -f new_rbac.yaml",
        "kubectl config unset contexts.dev",
        "kubectl config use-context kubernetes",
        "kubectl delete daemonset --all"
        ]
    for cmd in cmd_list:
        out = apply_cmd(linux_session, cmd)

def get_csvservers(ingress):
    data = {'vip':ingress["vip"], 'namespace':ingress["namespace"], 'ports':ingress['servicePorts'], 
            'ingressName':ingress['ingressName'], 'port': '', 'protocol':''}
    testbed = TBVars.TBFILE
    tb = utils.yaml_reader(testbed)
    pattern = tb['TEMPLATE'][0]['CSVS']
    l_tags = re.findall('<(.*?)>', pattern)
    csvs_names = []
    for port in data['ports']:
        csvs_name = pattern
        data['port'] = data['ports'][port]
        data['protocol'] = port
        for tag in l_tags:
            if tag in data:
                csvs_name = csvs_name.replace("<"+tag+">", data[tag])
            elif tag in ingress:
                csvs_name = csvs_name.replace("<"+tag+">", ingress[tag])
            else:
                csvs_name = ''
                break
        if csvs_name is not '':
            csvs_names.append(csvs_name)

    return csvs_names

def get_sslvservers(ingress):
    data = {'vip':ingress["vip"], 'namespace':ingress["namespace"], 'ports':ingress['servicePorts'], 
            'ingressName':ingress['ingressName'], 'port': '', 'protocol':''}
    testbed = TBVars.TBFILE
    tb = utils.yaml_reader(testbed)
    pattern = tb['TEMPLATE'][0]['SSLVS']
    l_tags = re.findall('<(.*?)>', pattern)
    sslvs_names = []
    for port in data['ports']:
        if port is 'ssl':
            sslvs_name = pattern
            data['port'] = data['ports'][port]
            data['protocol'] = port
            for tag in l_tags:
                if tag in data:
                    sslvs_name = sslvs_name.replace("<"+tag+">", data[tag])
                elif tag in ingress:
                    sslvs_name = sslvs_name.replace("<"+tag+">", ingress[tag])
                else:
                    sslvs_name = ''
                    break
            if sslvs_name is not '':
                sslvs_names.append(sslvs_name)

    return sslvs_names

def get_cspolicies(ingress):
    data = {'serviceName':ingress["serviceName"], 'namespace':ingress["namespace"], 'protocol':'', 'port':'', 
            'ingressName':ingress["ingressName"], 'ports':ingress["servicePorts"], "ingPort":ingress["ingPort"]}
    testbed = TBVars.TBFILE
    tb = utils.yaml_reader(testbed)
    pattern = tb['TEMPLATE'][0]['CSPolicy']
    l_tags = re.findall('<(.*?)>', pattern)
    cspolicies = []
    for port in data['ports']:
        cspolicy = pattern
        data['port'] = data['ports'][port]
        data['protocol'] = port
        for tag in l_tags:
            if tag in data:
                cspolicy = cspolicy.replace("<"+tag+">", data[tag])
            elif tag in ingress:
                cspolicy = cspolicy.replace("<"+tag+">", ingress[tag])
            else:
                cspolicy = ''
                break
        if cspolicy is not '':
            cspolicies.append(cspolicy)

    return cspolicies

def get_servicegroups(ingress):
    data = {'serviceName':ingress["serviceName"], 'namespace':ingress["namespace"], 'protocol':'', 'port':'', 'ingressName':ingress["ingressName"], 
            'ports':ingress["servicePorts"], "ingPort":ingress["ingPort"]}
    testbed = TBVars.TBFILE
    tb = utils.yaml_reader(testbed)
    pattern = tb['TEMPLATE'][0]['ServiceGroup']
    l_tags = re.findall('<(.*?)>', pattern)
    servicegroups = []
    for port in data['ports']:
        servicegroup = pattern
        data['port'] = data['ports'][port]
        data['protocol'] = port
        for tag in l_tags:
            if tag in data:
                servicegroup = servicegroup.replace("<"+tag+">", data[tag])
            elif tag in ingress:
                servicegroup = servicegroup.replace("<"+tag+">", ingress[tag])
            else:
                servicegroup = ''
                break
        if servicegroup is not '':
            servicegroups.append(servicegroup)

    return servicegroups

def get_coverage(ats, linux_session):
    # TODO: To add the logic to get the name of CIC pod. This is depricated now.
    p_id_cmd = "kubectl exec -it nsingresscontroller ps ex | grep \"coverage run\" | awk '{print $1}'"
    p_id = apply_cmd(linux_session, p_id_cmd)
    ats.info("\n########################################### PID : " + p_id + "###########################################")
    ats.info("\n########################################### Going to kill the pid ###########################################")
    kill_cmd = "kubectl exec -it nsingresscontroller -- kill -SIGINT "+str(p_id)
    apply_cmd(linux_session, kill_cmd)

def get_certkeys(ats, linux_session, label_name="app", value="cpx-ingress", container="cpx "):
    cpx_list = get_cpx_ns(linux_session, label_name, value)
    cpx = cpx_list[0]
    if value == "builtin-hostport" or container != "cpx ":
        cpx = cpx + " -c "+ container
    certk_cmd = "kubectl exec "+cpx+" /var/netscaler/bins/cli_script.sh shcertk | grep \"Name: k8s-\" --color=Never | awk '{print $3}'"
    cert_keys = apply_cmd(linux_session, certk_cmd)
    cert_keys = cert_keys.split("\r\n")
    return cert_keys

def wait_till_terminating(ats, linux_session):
    ats.info("Waiting for the pods to terminate.")
    cmd = 'kubectl get pods --all-namespaces | grep Terminating --color=Never'
    pods_terminating = 1
    while pods_terminating > 0:
        out = linux_session.exec_cmd(cmd)
        pods_terminating = len(out.split("\r\n")[1:-1])
        ats.info("Terminating pods: "+str(pods_terminating))
        time.sleep(2)

def wait_till_creating(ats, linux_session):
    ats.info("Waiting for the pods to start.")
    cmd = 'kubectl get pods --all-namespaces | grep ContainerCreating --color=Never'
    out = linux_session.exec_cmd(cmd)
    
    pods_creating = len(out.split("\r\n")[1:-1])
    #pdb.set_trace()
    ats.info("Creating pods: "+str(pods_creating))
    in_while_loop = False
    while pods_creating > 0:
        in_while_loop = True
        out = linux_session.exec_cmd(cmd)
        pods_creating = len(out.split("\r\n")[1:-1])
        ats.info("Creating pods: "+str(pods_creating))
        time.sleep(2)
    if in_while_loop:
        time.sleep(10)

def clean_ingress(ats, linux_session):
    ats.info("Cleaning up all the ingresses")
    cmd = 'kubectl delete ing --all'
    out = linux_session.exec_cmd(cmd)
    ats.info("DONE!")

def get_logs(ats, linux_session, value, tc_id, label="app"):
    cic_pod_name = get_cpx_ns(linux_session, label, value)
    if len(cic_pod_name) > 0:
        cic_pod_name = cic_pod_name[0]
        ats.info("Getting info")
        path_for_logs = "~/cic_logs_system_test/"+cic_pod_name+"_"+tc_id
        linux_session.exec_cmd("kubectl logs "+cic_pod_name+" > "+path_for_logs)
        return path_for_logs

def get_crd_version(session, crd_deploy_name, crd_instance_name):
    out = apply_cmd(
        session, 'kubectl get ' + crd_deploy_name + ' -o=custom-columns=NAME:.metadata.name,RSRC:.metadata.resourceVersion | grep -w ' + crd_instance_name + ' | awk \'{print $2}\'')
    out = out.strip()
    return out
    
def get_conf(ip, feature):
    r = requests.get('http://' + ip + '/nitro/v1/config/' +
                     feature + '/', auth=('nsroot', 'nsroot'))
    list_dict = []
    if feature in json.loads(r.text):
        out = json.loads(r.text)[feature]
        for i in out:
            d = dict(i)
            list_dict.append(d)
        return list_dict

    feature = feature.split('/', 1)
    if feature[0] in json.loads(r.text):
        out = json.loads(r.text)[feature[0]]
        for i in out:
            d = dict(i)
            list_dict.append(d)
        return list_dict
    else:
        return []
    def apply_yaml(session, path):
        cmd = 'kubectl apply -f %s' % path
        out = session.exec_cmd(cmd)
        if 'error' in out.lower():
            raise Exception('YAML APPLY: FAIL {} \n Reason: {}'.format(base_path + cmd),
                            k8s.delete_first_last_line(out))
        if 'invalid' in out.lower():
            raise inputValidationException('INPUT VALIDATION: APPLY YAML: fail: \n file: {}'.format(base_path + cmd))
        out = k8s.delete_first_last_line(out)
        return out

    def delete_yaml(session, path):
        cmd = 'kubectl delete -f %s' % path
        out = session.exec_cmd(cmd)
        if 'error' in out.lower():
            raise Exception('YAML APPLY: FAIL {} \n Reason: {}'.format(base_path + cmd),
                            k8s.delete_first_last_line(out))
        if 'invalid' in out.lower():
            raise inputValidationException('INPUT VALIDATION: DELETE YAML: fail: \n file: {}'.format(base_path + cmd))
        out = k8s.delete_first_last_line(out)
        return out
