import TBVars
import utils
import products
import kubelib as k8s
import pdb


param = {
'tid' : TBVars.TID,
'sname' : __file__
}

testbed = TBVars.TBFILE

ats = utils.test(param)

tb = utils.yaml_reader(testbed)
master_ip = tb['MASTER'][0]['IP']
tid = TBVars.TID
password = tb['MASTER'][0]['PASS']
username = tb['MASTER'][0]['USER']
prompt = tb['MASTER'][0]['PROMPT']
VPX_IP = tb['NS'][0]['IP']




param = {
'ip': master_ip,
'user':username,
'passwd':password,
'prompt':prompt,
'ats':ats,
'basic_config':True
}
master_node_session = products.linux(param)


get_cpx_node_ip_string = 'kubectl describe nodes -l node-role=ingress | grep -i InternalIP | awk \'{print $2}\''
cpx_node_ip = k8s.apply_cmd(master_node_session, get_cpx_node_ip_string)
cpx_node_ip = cpx_node_ip.strip()

cic_pod_details1 = {'cic-vpx': {'name':'vpx',
							   'cic_yaml':'CIC/cic-vpx.yaml',
							   'cpx_yaml': None,
							   'ip':str(VPX_IP),
							   'cic_container_name': None},
                   'cic-hostport': {'name': 'cpx-hostport',
									'cic_yaml': 'CIC/cic-hostport.yaml',
									'cpx_yaml': 'CPX/cpx_hostport.yaml',
									'ip':cpx_node_ip+':31000',
									'cic_container_name': None},
                   'cic-nodeport': {'name': 'cpx-nodeport',
									'cic_yaml': 'CIC/cic-nodeport.yaml',
									'cpx_yaml': 'CPX/cpx_nodeport.yaml',
									'ip':cpx_node_ip+':32000',
									'cic_container_name': None},
				   'builtin-hostport': {'name': 'builtin-hostport',
										 'cic_yaml': 'CPX/cpx_builtin_hostport.yaml',
										 'cpx_yaml': 'CPX/cpx_builtin_hostport.yaml',
										 'ip': cpx_node_ip + ':33000',
										 'cic_container_name': 'cic'
										 }}
cic_pod_details = {'cic-vpx': {'name':'vpx',
							   'cic_yaml':'CIC/cic-vpx.yaml',
							   'cpx_yaml': None,
							   'ip':str(VPX_IP),
							   'cic_container_name': None}}
