#! /usr/bin/python

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
#from netconf import nsmap_add, NSMAP
import json
import subprocess
from curses import ascii
from lxml import etree, objectify
import dicttoxml
import threading
import cumulus_nclu
from pyangbind.lib.serialise import pybindIETFXMLEncoder, pybindIETFXMLDecoder


NETCONF_DIR = '/home/cumulus/CumulusVXNetconf'
'''
try:
    NETCONF_DIR=os.environ[str("NETCONF_DIR")]
except Exception as e:
    print ("Error while fetching env variable NETCONF_DIR. Make sure NETCONF_DIR is set in ~/.profile file.." + str(e))
    sys.exit(1)
'''

logging.basicConfig(filename=NETCONF_DIR+'/logs/netconf_server.log', level=logging.DEBUG)

CANDIDATE = cumulus_nclu.cumulus_nclu()

def cand_run_diff():
    process = subprocess.Popen(['net', 'show', 'configuration', 'commands'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc_stdout, proc_error = process.communicate()
    if proc_error:
        logging.error('Error while executing "net show configuration commands" during difference calculation : '+ proc_error)
        return {'Error' : 'Error while executing "net show configuration commands" during difference calculation : ' + proc_error}
    temp_list = proc_stdout.split('\n')
    running_cmd_list = temp_list[1:temp_list.index('net commit')]
    for cmd in running_cmd_list:
        if ',' in cmd:
            fixed_cmd = cmd[:cmd.rfind(" ")]
            variables = cmd[cmd.rfind(" ")+1:].split(",")
            for variable in variables:
                running_cmd_list.append(fixed_cmd + " " + variable)
            running_cmd_list.remove(cmd)
    global CANDIDATE
    logging.debug("Running datastore commands:")
    logging.debug(str(running_cmd_list))
    logging.debug("Candidate datastore commands:")
    logging.debug(str(CANDIDATE.commands.cmd))
    #candidate_set = set(CANDIDATE)
    #running_set = set(running_cmd_list)
    #return list(candidate_set.difference(running_set))
    return [cmnd for cmnd in CANDIDATE.commands.cmd if cmnd not in running_cmd_list]

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
        util.subelm(capabilities,
                    "capability").text = "http://example.com/cumulus-nclu?module=cumulus-nclu&revision=2019-11-11"

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
        config = objectify.Element("data")
        objectify.deannotate(config, cleanup_namespaces=True, xsi=True, pytype=True)

        source_accepted = ['{urn:ietf:params:xml:ns:netconf:base:1.0}running', '{urn:ietf:params:xml:ns:netconf:base:1.1}running', 'running', '{urn:ietf:params:xml:ns:netconf:base:1.0}candidate', '{urn:ietf:params:xml:ns:netconf:base:1.1}candidate', 'candidate']

        if len(source_elm) == 0:
            logging.error('Value of source element missing')
            logging.error(str(error.InvalidValueProtoError(rpc, message='Missing value for source')))
            raise error.InvalidValueProtoError(rpc, message='Missing value for source')
        elif source_elm[0].tag not in source_accepted:
            logging.error('Only running and candidate datastore is accepted as source element in get-config operation. Source : ' + source_elm[0].tag)
            logging.error(str(error.OperationNotSupportedAppError(rpc, message='Operation not permitted')))
            raise error.OperationNotSupportedAppError(rpc, message='Operation not permitted')

        if len(source_elm) > 1:
            logging.error('More than one source element for get-config operation')
            logging.error(str(error.UnknownElementProtoError(rpc, source_elm[1])))
            raise error.UnknownElementProtoError(rpc, source_elm[1])

        output_object = cumulus_nclu.cumulus_nclu()
        if 'candidate' in source_elm[0].tag:
            global CANDIDATE
            '''
            for command in CANDIDATE:
                output_object.commands.cmd.append(command)
            '''
            output_object_xml = pybindIETFXMLEncoder.encode(CANDIDATE.commands)
            logging.debug(str(output_object_xml))
            config.commands = output_object_xml
            return util.filter_results(rpc, config, None)

        process = subprocess.Popen(['net', 'show', 'configuration', 'commands'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        if proc_error:
            logging.error('Error while executing "net show configuration commands" during get config operation : '+ proc_error)
            clean_proc_error = ''.join(c for c in proc_error if valid_xml_char_ordinal(c))
            logging.error(str(error.InvalidValueAppError(rpc, message=clean_proc_error)))
            raise error.InvalidValueAppError(rpc, message=clean_proc_error)
        temp_list = proc_stdout.split('\n')
        cmd_list = temp_list[1:temp_list.index('net commit')]

        for command in cmd_list:
            if ',' in command:
                fixed_cmd = command[:command.rfind(" ")]
                variables = command[command.rfind(" ")+1:].split(",")
                for variable in variables:
                    output_object.commands.cmd.append(fixed_cmd + " " + variable)
            else:
                output_object.commands.cmd.append(command)

        output_object_xml = pybindIETFXMLEncoder.encode(output_object.commands)
        logging.debug(str(output_object_xml))
        config.commands = output_object_xml
        return util.filter_results(rpc, config, None)

    def rpc_edit_config(self, session, rpc, target_elm, *args):
        """Passed the target element"""
        result = util.elm("ok")
        target_accepted = ['{urn:ietf:params:xml:ns:netconf:base:1.0}candidate', '{urn:ietf:params:xml:ns:netconf:base:1.1}candidate', 'candidate']

        logging.info(rpc)
        if len(target_elm)==0:
            logging.error('Value of target element missing')
            logging.error(str(error.InvalidValueProtoError(rpc, message='Missing value for target')))
            raise error.InvalidValueProtoError(rpc, message='Missing value for target')
        elif target_elm[0].tag not in target_accepted:
            logging.error('Only candidate datastore is accepted as target element in edit-config operation. Target : ' + target_elm[0].tag)
            logging.error(str(error.InvalidValueProtoError(rpc, message='Operation not permitted')))
            raise error.InvalidValueProtoError(rpc, message='Operation not permitted')
        elif len(target_elm) > 1:
            logging.error('More than one target element for edit-config operation')
            logging.error(str(error.UnknownElementProtoError(rpc, target_elm[1])))
            raise error.UnknownElementProtoError(rpc, target_elm[1])

        config = None
        if (len(args))==3:
            config = args[2]
        elif (len(args))==2:
            config = args[1]
        elif (len(args))==1:
            config = args[0]

        if config is None:
            logging.error('"config" element is missing in edit-config operation')
            logging.error(str(error.MissingElementAppError(rpc, 'config')))
            raise error.MissingElementAppError(rpc, 'config')

        if len(config) == 0:
            logging.error('Commands missing under config')
            logging.error(str(error.MissingElementAppError(rpc, 'commands')))
            raise error.MissingElementAppError(rpc, 'commands')

        try:
            for command in config[0]:
                " ".join(command.text.split())
                if 'delete' in command.attrib.values():
                    command.text = command.text.replace('net add', 'net del')
        except Exception as e:
            logging.error("Error while converting xml config into object : " + str(e))
            logging.error(str(error.MissingElementAppError(rpc, 'commands')))
            raise error.MissingElementAppError(rpc, 'commands')

        try:
            config_object = pybindIETFXMLDecoder.decode(etree.tostring(config), cumulus_nclu, "cumulus_nclu")
        except Exception as e:
            logging.error("Error while converting xml config into object : " + str(e))
            logging.error(str(error.MissingElementAppError(rpc, 'commands')))
            raise error.MissingElementAppError(rpc, 'commands')


        process = subprocess.Popen(["net", "pending", "json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        json_stdout = json.loads(proc_stdout)

        existing_cmds = []

        if json_stdout:
            for cmd in json_stdout['commands']:
                existing_cmds.append(cmd['command'])

        global CANDIDATE
        edit_candidate = CANDIDATE.commands.cmd[:]
        for cmd in edit_candidate:
            if ',' in cmd:
                fixed_cmd = cmd[:cmd.rfind(" ")]
                variables = cmd[cmd.rfind(" ")+1:].split(",")
                for variable in variables:
                        edit_candidate.append(fixed_cmd + " " + variable)
                edit_candidate.remove(cmd)

        #cmdlist = []
        abort_process = subprocess.Popen(["net", "abort"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        abort_proc_stdout, abort_proc_error = abort_process.communicate()
        for cmd in config_object.commands.cmd:
            command = cmd.split()
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc_stdout, proc_error = process.communicate()
            if proc_error:
                logging.error('Error while executing command in edit-config operation : ' + cmd + '. Error : '+  proc_error + ' Rolling back.....')
                abort_process = subprocess.Popen(["net", "abort"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                abort_proc_stdout, abort_proc_error = abort_process.communicate()
                existing_cmds_thread = []
                for excmd in existing_cmds:
                    process = subprocess.Popen(excmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    eth = threading.Thread(target=process.communicate)
                    existing_cmds_thread.append(eth)
                    eth.start()
                clean_proc_error = ''.join(c for c in proc_error if valid_xml_char_ordinal(c))
                #clean_proc_error = cmd + ': ' + proc_error.split("\n")[0]
                for eth in existing_cmds_thread:
                    eth.join()
                logging.error(str(error.InvalidValueAppError(rpc, message=clean_proc_error)))
                raise error.InvalidValueAppError(rpc, message=clean_proc_error)
            if cmd not in edit_candidate:
                edit_candidate.append(cmd)

        abort_process = subprocess.Popen(["net", "abort"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        abort_proc_stdout, abort_proc_error = abort_process.communicate()

        existing_cmds_thread = []
        for cmd in existing_cmds:
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            eth = threading.Thread(target=process.communicate)
            existing_cmds_thread.append(eth)
            eth.start()

        
        #edit_candidate.extend(cmdlist)
        #CANDIDATE = list(SEt(edit_candidate))
        #CANDIDATE = list( dict.fromkeys(edit_candidate) )
        
        global CANDIDATE
        CANDIDATE.commands.cmd = edit_candidate
        


        logging.debug("Candidate Datastore Updated:")
        logging.debug(str(CANDIDATE.commands.cmd))
        for eth in existing_cmds_thread:
            eth.join()

        return util.filter_results(rpc, result, None)

    def rpc_validate(self, session, rpc, source_elm):

        source_accepted = ['{urn:ietf:params:xml:ns:netconf:base:1.0}candidate', '{urn:ietf:params:xml:ns:netconf:base:1.1}candidate', 'candidate']

        if len(source_elm)==0:
            logging.error('Value of source element missing')
            logging.error(str(error.InvalidValueProtoError(rpc, message='Missing value for source')))
            raise error.InvalidValueProtoError(rpc, message='Missing value for source')
        elif source_elm[0].tag not in source_accepted:
            logging.error('Only candidate datastore is accepted as source element in validate operation. Source : ' + source_elm[0].tag)
            logging.error(str(error.OperationNotSupportedAppError(rpc, message='Operation not permitted')))
            raise error.OperationNotSupportedAppError(rpc, message='Operation not permitted')

        if len(source_elm) > 1:
            logging.error('More than one source element for validate operation')
            logging.error(str(error.UnknownElementProtoError(rpc, source_elm[1])))
            raise error.UnknownElementProtoError(rpc, source_elm[1])

        process = subprocess.Popen(["net", "pending", "json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        json_stdout = json.loads(proc_stdout)

        existing_cmds = []
        if json_stdout:
            for cmd in json_stdout['commands']:
                existing_cmds.append(cmd['command'])


        cmdlist = cand_run_diff()

        process = subprocess.Popen(["net", "abort"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        for cmd in cmdlist:
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc_stdout, proc_error = process.communicate()
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
            logging.error(str(error.InvalidValueAppError(rpc, message=clean_proc_error)))
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

        existing_cmds = []
        if json_stdout:
            for cmd in json_stdout['commands']:
                existing_cmds.append(cmd['command'])

        cmdlist = cand_run_diff()
        logging.debug("Commands to be committed:")
        logging.debug(str(cmdlist))
        process = subprocess.Popen(["net", "abort"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        for cmd in cmdlist:
            logging.debug("Adding cmd:" + cmd)
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc_stdout, proc_error = process.communicate()
            logging.debug("stdout : " + str(proc_stdout))
            logging.debug("error : " + str(proc_error))
        logging.info("Committing the commands")
        process = subprocess.Popen(["net", "commit"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()

        abort_process = subprocess.Popen(["net", "abort"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        abort_stdout, abort_error = abort_process.communicate()

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
            #clean_proc_error = proc_error.split("\n")[0]
            logging.error(str(error.InvalidValueAppError(rpc, message=clean_proc_error)))
            raise error.InvalidValueAppError(rpc, message=clean_proc_error)

        process = subprocess.Popen(['net', 'show', 'configuration', 'commands'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        if proc_error:
            logging.error('Error while executing "net show configuration commands" : '+ proc_error)
            logging.error(str(error.OperationFailedProtoError(rpc)))
            raise error.OperationFailedProtoError(rpc)
        temp_list = proc_stdout.split('\n')
        running_cmd_list = temp_list[1:temp_list.index('net commit')]
        global CANDIDATE
        CANDIDATE.commands.cmd = running_cmd_list
        for eth in existing_cmds_threads:
            eth.join()
        return util.elm("ok")

    def rpc_copy_config(self, session, rpc, target_elm, source_elm):
        source_accepted = ['{urn:ietf:params:xml:ns:netconf:base:1.0}running', '{urn:ietf:params:xml:ns:netconf:base:1.1}running', 'running']
        target_accepted = ['{urn:ietf:params:xml:ns:netconf:base:1.0}candidate', '{urn:ietf:params:xml:ns:netconf:base:1.1}candidate', 'candidate']
        logging.debug("Performing copy config operation....")
        if not source_elm or not target_elm:
            logging.error('Source and target missing')
            logging.error(str(error.InvalidValueProtoError(rpc, message='Missing Source or target')))
            raise error.InvalidValueProtoError(rpc, message='Missing source or target')
        if len(source_elm)==0:
            logging.error('Value of source element missing')
            logging.error(str(error.InvalidValueProtoError(rpc, message='Missing value for source')))
            raise error.InvalidValueProtoError(rpc, message='Missing value for source')
        elif len(target_elm)==0:
            logging.error('Value of target element missing')
            logging.error(str(error.InvalidValueProtoError(rpc, message='Missing value for target')))
            raise error.InvalidValueProtoError(rpc, message='Missing value for target')
        elif source_elm[0].tag not in source_accepted or target_elm[0].tag not in target_accepted:
            logging.debug("Source: " + str(source_elm[0].tag))
            logging.debug("Target: " + str(target_elm[0].tag))
            logging.error('copy-config can be performed from source "running" to target "candidate"')
            logging.error(str(error.OperationNotSupportedAppError(rpc, message='Operation not permitted')))
            raise error.OperationNotSupportedAppError(rpc, message='Operation not permitted')

        process = subprocess.Popen(['net', 'show', 'configuration', 'commands'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        if proc_error:
            logging.error('Error while executing "net show configuration commands" : '+ proc_error)
            logging.error(str(error.OperationFailedProtoError(rpc)))
            raise error.OperationFailedProtoError(rpc)
        temp_list = proc_stdout.split('\n')
        running_cmd_list = temp_list[1:temp_list.index('net commit')]
        global CANDIDATE
        CANDIDATE.commands.cmd = running_cmd_list
        logging.info("Copy-config operation finished")
        return util.elm("ok")

    def rpc_lock(self, session, rpc, target_elm, *args):
        return util.elm("ok")

    def rpc_unlock(self, session, rpc, target_elm, *args):
        return util.elm("ok")

    def rpc_discard_changes(self, session, rpc):
        process = subprocess.Popen(['net', 'show', 'configuration', 'commands'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_stdout, proc_error = process.communicate()
        if proc_error:
            logging.error('Error while executing "net show configuration commands" : '+ proc_error)
            raise error.OperationFailedProtoError(rpc)
        temp_list = proc_stdout.split('\n')
        running_cmd_list = temp_list[1:temp_list.index('net commit')]
        for cmd in running_cmd_list:
            if ',' in cmd:
                fixed_cmd = cmd[:cmd.rfind(" ")]
                variables = cmd[cmd.rfind(" ")+1:].split(",")
                for variable in variables:
                    running_cmd_list.append(fixed_cmd + " " + variable)
                running_cmd_list.remove(cmd)
        global CANDIDATE
        CANDIDATE.commands.cmd = running_cmd_list

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

    process = subprocess.Popen(['net', 'show', 'configuration', 'commands'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc_stdout, proc_error = process.communicate()
    if proc_error:
        logging.error('Error while executing "net show configuration commands" : '+ proc_error)
        raise error.OperationFailedProtoError(rpc)
    temp_list = proc_stdout.split('\n')
    running_cmd_list = temp_list[1:temp_list.index('net commit')]
    for cmd in running_cmd_list:
        if ',' in cmd:
            fixed_cmd = cmd[:cmd.rfind(" ")]
            variables = cmd[cmd.rfind(" ")+1:].split(",")
            for variable in variables:
                running_cmd_list.append(fixed_cmd + " " + variable)
            running_cmd_list.remove(cmd)
    global CANDIDATE
    CANDIDATE.commands.cmd = running_cmd_list

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    args.password = parse_password_arg(args.password)
#    host_key = os.path.dirname(__file__) + "/server-key"
    host_key = NETCONF_DIR+'/netconf-key'

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

