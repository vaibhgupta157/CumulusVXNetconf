from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
import argparse
import datetime
import logging
import os
import platform
import socket
import sys
import time
from netconf import error, server, util
from netconf import nsmap_add, NSMAP
import json
import subprocess
from curses import ascii
from lxml import etree
import dicttoxml
import threading


logging.basicConfig(filename='logs/netconf_server.log', level=logging.DEBUG)

def valid_xml_char_ordinal(c):
    codepoint = ord(c)
    # conditions ordered by presumed frequency
    return (
        0x20 <= codepoint <= 0xD7FF or
        codepoint in (0x9, 0xA, 0xD) or
        0xE000 <= codepoint <= 0xFFFD or
        0x10000 <= codepoint <= 0x10FFFF
        )

def parse_password_arg(password):
    if password:
        if password.startswith("env:"):
            unused, key = password.split(":", 1)
            password = os.environ[key]
        elif password.startswith("file:"):
            unused, path = password.split(":", 1)
            password = open(path).read().rstrip("\n")
    return password


def date_time_string(dt):
    tz = dt.strftime("%z")
    s = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
    if tz:
        s += " {}:{}".format(tz[:-2], tz[-2:])
    return s


class SystemServer(object):
    def __init__(self, port, host_key, auth, debug):
        self.server = server.NetconfSSHServer(auth, self, port, host_key, debug)

    def close():
        self.server.close()

    def nc_append_capabilities(self, capabilities):  # pylint: disable=W0613
        """The server should append any capabilities it supports to capabilities"""
        util.subelm(capabilities,
                    "capability").text = "urn:ietf:params:netconf:capability:candidate:1.0"
        util.subelm(capabilities,
                    "capability").text = "urn:ietf:params:netconf:capability:validate:1.0"

    def rpc_get(self, session, rpc, filter_or_none): 
        """Passed the filter element or None if not present"""

        if filter_or_none is not None:
            cmd = filter_or_none.text
            if cmd.endswith('json'):
                pass
            else:
                cmd = cmd + ' json'
        else:
            cmd = 'net show system json'

        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        if proc_error:
            logging.error('Error while executing '+ cmd + ':' + proc_error)
            clean_proc_error = ''.join(c for c in proc_error if valid_xml_char_ordinal(c))
            raise error.InvalidValueAppError(rpc, message=clean_proc_error)
        json_stdout = json.loads(proc_stdout)
        if json_stdout:
            data = etree.fromstring(dicttoxml.dicttoxml(json_stdout, attr_type=False, custom_root='data'))
        else:
            data = util.elm("data")

        return data
    
    def rpc_get_config(self, session, rpc, source_elm, filter_or_none):  
        """Passed the source element"""
        data = util.elm("config")

        source_accepted = ['{urn:ietf:params:xml:ns:netconf:base:1.0}running', '{urn:ietf:params:xml:ns:netconf:base:1.1}running', 'running']

        if source_elm[0].tag not in source_accepted:
            logging.error('Only running datastore is accepted as source element in get-config operation. Source : ' + source_elm[0].tag)
            raise error.OperationNotSupportedAppError(rpc, message='Operation not permitted')

        if len(source_elm) > 1:
            logging.error('More than one source element for get-config operation')
            raise error.UnknownElementProtoError(rpc, source_elm[1])


        process = subprocess.Popen(['net', 'show', 'configuration', 'commands'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        if proc_error:
            logging.error('Error while executing "net show configuration commands" during get config operation : '+ proc_error)
            clean_proc_error = ''.join(c for c in proc_error if valid_xml_char_ordinal(c))
            raise error.InvalidValueAppError(rpc, message=clean_proc_error)
        temp_list = proc_stdout.split('\n')
        cmd_list = temp_list[:temp_list.index('net commit')+1]

        for cmd in cmd_list:
            data.append(util.leaf_elm("cmd", cmd))

        return util.filter_results(rpc, data, filter_or_none)
    
    def rpc_edit_config(self, session, rpc, target_elm, config):   
        """Passed the target element"""
        result = util.elm("ok")

        target_accepted = ['{urn:ietf:params:xml:ns:netconf:base:1.0}candidate', '{urn:ietf:params:xml:ns:netconf:base:1.1}candidate', 'candidate']

      
        if len(target_elm)==0:
            logging.error('Value of target element missing')
            raise error.InvalidValueProtoError(rpc, message='Missing value for target')
        elif target_elm[0].tag not in target_accepted:
            logging.error('Only candidate datastore is accepted as target element in get-config operation. Target : ' + target_elm[0].tag)
            raise error.OperationNotSupportedAppError(rpc, message='Operation not permitted')
        elif len(target_elm) > 1:
            logging.error('More than one target element for edit-config operation')
            raise error.UnknownElementProtoError(rpc, target_elm[1])

        if config is None:
            logging.error('"config" element is missing in edit-config operation')
            raise error.MissingElementAppError(rpc, 'config')

        if len(config) == 0:
            logging.error('Commands missing under config')
            raise error.MissingElementAppError(rpc, 'config')

        accepted_childs = ['{urn:ietf:params:xml:ns:netconf:base:1.0}cmd', '{urn:ietf:params:xml:ns:netconf:base:1.1}cmd', 'cmd']

        for child in config.iterchildren():
            if child.tag not in accepted_childs:
                logging.error('Unknown element under config in edit-config operation : ' + child.tag)
                raise error.UnknownElementProtoError(rpc, child)

        process = subprocess.Popen(["net", "pending", "json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        json_stdout = json.loads(proc_stdout)

        if json_stdout:
            existing_cmds = []
            for cmd in json_stdout['commands']:
                existing_cmds.append(cmd['command'])     
        
        cmdlist = []
        abort_process = subprocess.Popen(["net", "abort"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        abort_proc_stdout, abort_proc_error = abort_process.communicate()
        for cmd in config.iterchildren():
            command = cmd.text.split()
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc_stdout, proc_error = process.communicate()
            if proc_error:
                logging.error('Error while executing command in edit-config operation : ' + cmd + '. Error : '+  proc_error + ' Rolling back.....')
                abort_process = subprocess.Popen(["net", "abort"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                abort_proc_stdout, abort_proc_error = abort_process.communicate()
                existing_cmds_thread = []
                for cmd in existing_cmds:
                    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    eth = threading.Thread(target=process.communicate)
                    existing_cmds_thread.append(eth)
                    eth.start()
                clean_proc_error = ''.join(c for c in proc_error if valid_xml_char_ordinal(c))
                for eth in existing_cmds_thread:
                    eth.join()
                raise error.InvalidValueAppError(rpc, message=clean_proc_error)
            cmdlist.append(cmd.text)

        abort_process = subprocess.Popen(["net", "abort"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        abort_proc_stdout, abort_proc_error = abort_process.communicate()

        existing_cmds_thread = []
        for cmd in existing_cmds:
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            eth = threading.Thread(target=process.communicate)
            existing_cmds_thread.append(eth)
            eth.start()

        with open('candidate.txt', 'a+') as f:
            f.write('\n'.join(cmdlist))

        for eth in existing_cmds_thread:
            eth.join()

        return util.filter_results(rpc, result, None)

    def rpc_validate(self, session, rpc, source_elm):

        source_accepted = ['{urn:ietf:params:xml:ns:netconf:base:1.0}candidate', '{urn:ietf:params:xml:ns:netconf:base:1.1}candidate', 'candidate']

        if source_elm is None:
            logging.error('Source element missing in validate operation')
            raise error.MissingElementAppError(rpc, 'source')
        elif source_elm[0].tag not in source_accepted:
            logging.error('Only candidate datastore is accepted as source element in validate operation. Source : ' + source_elm[0].tag)
            raise error.OperationNotSupportedAppError(rpc, message='Operation not permitted')

        if len(source_elm) > 1:
            logging.error('More than one source element for validate operation')
            raise error.UnknownElementProtoError(rpc, source_elm[1])

        process = subprocess.Popen(["net", "pending", "json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        json_stdout = json.loads(proc_stdout)

        if json_stdout:
            existing_cmds = []
            for cmd in json_stdout['commands']:
                existing_cmds.append(cmd['command'])

        try:
            with open('candidate.txt', 'r') as f:
                cmdlist = f.readlines()
        except IOError as e:
            logging.error('Error while opening candidate.txt file. Make sure configuration is pushed to candidate datastore : ' + e)
            raise error.MalformedMessageRPCError(rpc)

        process = subprocess.Popen(["net", "abort"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        thread_list = []
        for cmd in cmdlist:
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            th = threading.Thread(target=process.communicate)
            thread_list.append(th)
            th.start()
        for th in thread_list:
            th.join()
        process = subprocess.Popen(["net", "pending", "json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        abort_process = subprocess.Popen(["net", "abort"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        abort_proc_stdout, abort_proc_error = abort_process.communicate()

        existing_cmds_threads = []
        for cmd in existing_cmds:
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            eth = threading.Thread(target=process.communicate)
            existing_cmds_threads.append(th)
            eth.start()
        for eth in existing_cmds_threads:
            eth.join()


        if proc_error:
            logging.error('Error while executing "net pending json" during validate operation : '+ proc_error)
            clean_proc_error = ''.join(c for c in proc_error if valid_xml_char_ordinal(c))
            raise error.InvalidValueAppError(rpc, message=clean_proc_error)
        json_stdout = json.loads(proc_stdout)
        
        result = util.elm('result')

        if 'diffs' in json_stdout.keys():
            for diff in json_stdout['diffs']:
                for i in range(len(diff['content'])):
                    if 'WARNING' in diff['content'][i]:
                        logging.info('Warning found while validating')
                        warn = diff['content'][i]
                        msg = diff['content'][i+1]
                        result.append(util.leaf_elm("warning", warn))
                        result.append(util.leaf_elm("message", msg))
                        return result

        result_ok = util.subelm(result, "ok")
        return result_ok

    def rpc_commit(self, session, rpc):

        process = subprocess.Popen(["net", "pending", "json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        json_stdout = json.loads(proc_stdout)

        if json_stdout:
            existing_cmds = []
            for cmd in json_stdout['commands']:
                existing_cmds.append(cmd['command'])


        try:
            with open('candidate.txt', 'r') as f:
                cmdlist = f.readlines()
        except IOError as e:
            logging.error('Error while opening candidate.txt file. Make sure configuration is pushed to candidate datastore : ' + e)
            raise error.MalformedMessageRPCError(rpc)
        process = subprocess.Popen(["net", "abort"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        thread_list = []
        for cmd in cmdlist:
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            th = threading.Thread(target=process.communicate)
            thread_list.append(th)
            th.start()
        for th in thread_list:
            th.join()
        process = subprocess.Popen(["net", "commit"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        existing_cmds_threads =[]
        for cmd in existing_cmds:
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            eth = threading.Thread(target=process.communicate)
            existing_cmds_threads.append(eth)
            eth.start()
        if proc_error:
            logging.error('Error while committing candidate datastore configuration : '  + proc_error)
            for eth in existing_cmds_threads:
                eth.join()
            clean_proc_error = ''.join(c for c in proc_error if valid_xml_char_ordinal(c))
            raise error.InvalidValueAppError(rpc, message=clean_proc_error)

        os.remove('candidate.txt')
        for eth in existing_cmds_threads:
            eth.join()
        return util.elm("ok")

    def rpc_system_restart(self, session, rpc, *params):
        raise error.AccessDeniedAppError(rpc)

    def rpc_system_shutdown(self, session, rpc, *params):
        raise error.AccessDeniedAppError(rpc)

def main(*margs):

    parser = argparse.ArgumentParser("Example System Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--password", default="admin", help='Use "env:" or "file:" prefix to specify source')
    parser.add_argument('--port', type=int, default=8300, help='Netconf server port')
    parser.add_argument("--username", default="admin", help='Netconf username')
    args = parser.parse_args(*margs)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    args.password = parse_password_arg(args.password)
    host_key = os.path.dirname(__file__) + "/server-key"
    host_key = "/home/cumulus/netconf/server-key"

    auth = server.SSHUserPassController(username=args.username, password=args.password)
    s = SystemServer(args.port, host_key, auth, args.debug)

    if sys.stdout.isatty():
        print("^C to quit server")
    try:
        while True:
            time.sleep(1)
    except Exception:
        print("quitting server")

    s.close()


if __name__ == "__main__":
    main()