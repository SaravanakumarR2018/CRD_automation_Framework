import os
import json
import re
import logging
import stat
import pdb
# sys.path.insert(0, '../')
# import kubelib as k8s

class TestUtil():

    @staticmethod
    def replace_pattern_in_json(ats, input_dict, edits, pattern_keys):
        """
        recursive function to find and replace value provided in edits
        :param ns_output: pass nested dict/list
        :param edits:    dict will contain pattern:replace_with
        :param pattern_keys: above pattern to be looked into value of
                keys mentioned in this set
        :return:
        """
        def _replace_pattern_in_json_util(input, edits):
            for k, v in input.items():
                if isinstance(v, dict):
                    _replace_pattern_in_json_util(v, edits)
                elif isinstance(v, list):
                    for listitem in v:
                        _replace_pattern_in_json_util(listitem, edits)
                elif k in pattern_keys:
                    for entry in edits:
                        v = re.sub(entry, edits[entry], v)
                    input[k] = v
        try:
            _replace_pattern_in_json_util(input_dict, edits)
        except Exception as e:
            ats.info("Exception is {}".format(e))

    @staticmethod
    def replace_pattern(ats, input_json, edits):
        """
        handle rewrite policy from crd
        :param ns_output: pass json input file which may contained nested list, dict
        :param edits:    dict will contain pattern:replace_with
        :return:
        """
        try:
            data = json.dumps(input_json)
            for entry in edits:
                search = entry
                replace = edits[entry]
                print re.sub("abc","xyz","abcsdhjdvnckdjfvabckdfnckjsdnfdjk\\rcadjnbcfkjabc")
                data = re.sub(search, replace, data)
            output = json.loads(data)
            return output

        except Exception as e:
            ats.info("Exception is {}".format(e))
            return None

    @staticmethod
    def replaceall_smallfile(ats, input_file, edits):
        """
        Generic function to replace pattern in a file and store it with same name.
        :param input_file: pass json input file
        :param edits:    dict will contain pattern:replace_with
        :return:
        """
        try:

            ats.info("Replacing configuration in file: %s", input_file)
            st = os.stat(input_file)
            os.chmod(input_file, st.st_mode | stat.S_IWUSR)
            lines = list()
            with open(input_file) as f:
                lines = f.readlines()
                f.close()
            for index, line in enumerate(lines):
                for entry in edits:
                    search = entry
                    replace = edits[entry]
                    line = re.sub(search, replace, line)
                    lines[index] = line

            f = open(input_file, 'w')
            for line in lines:
                f.write(line)
            f.close()
        except Exception as e:
            ats.info("Exception is {}".format(e))

    @staticmethod
    def compare_output(ats, list1, list2, name):
        """
        This function will be used to validate if policy name being added using crd,
        has been added in netscaler config.
        :param list1: list of entries from expected json output
        :param list2: list of entries fecthed from nitro call
        :param compareitems: key values to be matched inside nested dictionary
        :return:
        """
        #if name == 'responderpolicy':
            #pdb.set_trace()
        fullmatch = True
        match = False
        try:
            for l1 in list1:
                idx = 0
                for idx in range(len(list2)):
                    simple_match=[]
                    for item in list2[idx].items():
                        if item[0] in l1.keys():
                            if item in l1.items():
                                simple_match.append(True)
                            else:
                                simple_match.append(False)
                    if simple_match != [] and simple_match[0] == True and len(set(simple_match)) == 1:
                         match = True
                         break
                    if (all(item in l1.items() for item in list2[idx].items() if item[0] in l1.keys())):
                        match = True
                        break
                if not match:
                    #pdb.set_trace()
                    ats.info('Expected config not matched for {}'.format(l1['name']))
                    fullmatch = False
                else:
                    ats.info('Expected config matched for {}'.format(l1['name']))
                    match = False

            if not fullmatch:
                ats.info('Expected config not matched for {}'.format(name))
            else:
                ats.info('Expected config matched for {}'.format(name))
        except Exception as e:
            ats.info("Exception is {}".format(e))
            fullmatch = False
        return fullmatch

    @staticmethod
    def validate_if_config_removed(ats, list1, list2, name):
        """
        This function will be used to validate if policy name being used in crd,
        has been removed from netscaler.
        :param list1: expect list which will contain entries to be searched in list2
        :param list2: expect list where to look for entries passed in list1
        :return: return success if configuration in list1 not found in list2
        """
        config_removed = True
        try:
            policy_name_list = [policy['name'] for policy in list2]

            for l1 in list1:
                if l1['name'] in policy_name_list:
                    ats.info('Config still present for {}'.format(l1['name']))
                    config_removed = False
                else:
                    ats.info('Config removed for {}'.format(l1['name']))

            if not config_removed:
                ats.info('Complete config not removed for {}'.format(name))
            else:
                ats.info("Complete config removed for {}".format(name))
        except Exception as e:
            ats.info("Exception is {}".format(e))
            config_removed = False
        return config_removed

    def custom_ats_log(ats, background_color, font_size, font_color, logs):
        ats.info('</font><br/><font size="' + font_size + '" color="' + font_color +
                 '"><span style="background-color: ' + background_color + '">' + logs + '</span><font size="1">')
