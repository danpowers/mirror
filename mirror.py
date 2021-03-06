#!/usr/bin/python

# Copyright 2015 University of Chicago
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Requires python library for the Globus Online Transfer API, available here:

https://github.com/globusonline/transfer-api-client-python

Globus mirror script:

Will mirror contents of directory tree at source_path on source_endpoint to destination_path on destination_endpoint.
Files in the destination directory will be overwritten if there is a file with the same name in the source directory
with a different hash value. Files in the destination directory that do not correspond to any file of the same name in
the source directory will not be overwritten or deleted.

When run in either batch_setup or interactive mode, script will authenticate to Globus Online and retrieve a GOAUTH
token for Globus account to be used. Script will cache this token if run in batch_setup mode. When run in batch_start
mode, script will use the GOAUTH token cached from batch_setup mode.

Script will attempt to autoactivate endpoints. Failing autoactivation, script will - in interactive or batch_setup
modes - determine if endpoint uses myproxy or oauth, and will prompt user for myproxy credentials or refer them to a
URL for oauth activation as appropriate. When run in batch mode, all endpoints must be activated or able to be
autoactivated, or the script will log an appropriate message and exit.
"""

import time
import json
import getpass
import argparse
import os
from globusonline.transfer import api_client
from globusonline.transfer.api_client import get_access_token

def log_message(message, config_file_paths):
    print(message + "\n")
    with open(config_file_paths['log_file'], "a") as lf:
        lf.write(time.strftime("%d/%m/%Y %H:%M:%S") + " " + message + "\n")


def set_config_file_paths():
    config_dir = os.path.expanduser("~/.globusonline/mirror/")

    config_file_paths = dict(config_dir=config_dir, config_file=os.path.join(config_dir, "mirror.cfg"),
                             token_file=os.path.join(config_dir, "mirror_token_file"),
                             log_file=os.path.join(config_dir, "mirror.log"))
    return config_file_paths


def init_config_dir(config_file_paths):
    if not os.path.exists(config_file_paths['config_dir']):
        os.makedirs(config_file_paths['config_dir'])


def get_token(username, password):
    try:
        _, _, get_token.token = get_access_token(username, password, ca_certs=None)
    except Exception as e:
        print ("Unable to get GOAUTH token:" + "\n" + str(e))
        exit(1)
    return get_token.token


def input_transfer_list():
    transfer_list = []
    more = True

    while more:
        transfer = dict(source_endpoint=raw_input("Enter source endpoint name: "),
                             source_path=raw_input("Enter source endpoint path: "),
                             destination_endpoint=raw_input("Enter destination endpoint name: "),
                             destination_path=raw_input("Enter destination endpoint path: "),
                             deadline=raw_input("Enter transfer deadline in hours (enter '0' for none): "))
        try:
            transfer['deadline'] = int(transfer['deadline'])
            if transfer['deadline'] < 0:
                print("Transfer deadline must be >= 0\n")
                exit(1)
        except Exception as e:
            print("Bad value: " + transfer['deadline'] + "\n" + str(e))
            exit(1)
        c = raw_input("Add another transfer (y/n): ")
        if c != "y":
            more = False
        transfer_list.append(transfer)

    return transfer_list


def get_user_and_pass():
    username = raw_input("Enter Username: ")
    password = getpass.getpass("Enter Password: ")
    return username, password


def activate_endpoints(username, token, transfer, config_file_paths, batch=False):
    api = api_client.TransferAPIClient(username, goauth=token)
    for endpoint in transfer['source_endpoint'], transfer['destination_endpoint']:
        try:
            _, _, data = api.endpoint(endpoint)
            if data['activated'] is not True:
                code, reason, requirements = api.endpoint_autoactivate(endpoint)
                if requirements['code'] == "AutoActivationFailed":
                    log_message("Autoactivate of " + endpoint + " failed.", config_file_paths)
                    if requirements['oauth_server'] is not None:
                        if batch is True:
                            log_message(endpoint + " requires new oauth activation. This cannot be done " +
                                        "in batch mode.", config_file_paths)
                            exit(1)
                        print(endpoint + " requires OAuth activation.\n")
                        print("Activate this endpoint at the following URL and then run the script again:\n")
                        p1, p2 = endpoint.split("#")
                        print("https://www.globus.org/xfer/ManageEndpoints#endpoint=" + p1 + "%23" + p2 + "\n")
                        exit(1)
                    elif requirements['DATA'][5]['value'] is not None:
                        if batch is True:
                            log_message(endpoint + " requires new myproxy activation. This cannot be done " +
                                        "in batch mode.", config_file_paths)
                            exit(1)
                        print("Enter myproxy credentials to activate " + endpoint + "\n")
                        username, password = get_user_and_pass()
                        requirements['DATA'][3]['value'] = username
                        requirements['DATA'][4]['value'] = password
                        code, reason, data = api.endpoint_activate(endpoint, requirements)
                        if data['code'] == "AutoActivationFailed":
                            log_message("Activation of " + endpoint + " failed:\n" + str(code) + " " + str(reason) +
                                        " " + str(data), config_file_paths)
                            exit(1)
                    else:
                        log_message("Unexpected response:\n" + str(code) + " " + str(reason) + " " +
                                    str(requirements), config_file_paths)
                        exit(1)
        except Exception as e:
            log_message("Error during endpoint activation: " + endpoint + "\n" + str(e), config_file_paths)
            exit(1)
    return api


def mirror_directories(username, token, transfer, config_file_paths, batch=False):
    api = activate_endpoints(username, token, transfer, config_file_paths, batch)
    _, _, result = api.transfer_submission_id()
    submission_id = result["value"]

    deadline = None

    try:
        if transfer['deadline'] != 0:
            deadline = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() + (transfer['deadline']*3600)))

        t = api_client.Transfer(submission_id, transfer['source_endpoint'], transfer['destination_endpoint'],
                                deadline=deadline, sync_level=3, label="Mirror script transfer")
        t.add_item(transfer['source_path'], transfer['destination_path'], recursive=True)
        status, reason, result = api.transfer(t)
        if result['code'] != "Accepted":
            log_message("Transfer job: " + submission_id + " not accepted:\n" +
                        status + " " + reason + " " + result, config_file_paths)
            exit(1)
        log_message("Submitted job with task ID = " + submission_id, config_file_paths)
    except Exception as e:
        log_message("Unable to initiate transfer:\n" + str(e), config_file_paths)
        exit(1)


def batch_start_mode(config_file_paths):
    with open(config_file_paths['config_file'], "r") as cf:
        transfer_list = json.load(cf)

    with open(config_file_paths['token_file'], "r") as tf:
        token = tf.read()

    username, _ = token.split("|", 1)
    _, username = username.split("=", 1)

    for transfer in transfer_list:
        mirror_directories(username, token, transfer, config_file_paths, batch=True)


def batch_setup_mode(config_file_paths):
    if os.path.exists(config_file_paths['config_file']):
        os.remove(config_file_paths['config_file'])

    if os.path.exists(config_file_paths['token_file']):
        os.remove(config_file_paths['token_file'])

    print("Enter Globus Credentials:\n")
    username, password = get_user_and_pass()
    token = get_token(username, password)
    transfer_list = input_transfer_list()
    for transfer in transfer_list:
        activate_endpoints(username, token, transfer, config_file_paths)

    with open(config_file_paths['token_file'], "w") as tf:
        tf.write(token)
    print("Token saved to: " + config_file_paths['token_file'] + "\n")

    with open(config_file_paths['config_file'], "w") as cf:
        json.dump(transfer_list, cf)
    print("Config saved to: " + config_file_paths['config_file'] + "\n")


def interactive_mode(config_file_paths):
    print("Enter Globus Credentials:\n")
    username, password = get_user_and_pass()
    token = get_token(username, password)
    transfer_list = input_transfer_list()
    for transfer in transfer_list:
        mirror_directories(username, token, transfer, config_file_paths)


def parse_arguments():
    p = argparse.ArgumentParser()

    p.add_argument("-t", "--test", action="store_true",
                   help="Write config file, pull GOAUTH token and cache it to prepare for batch operation.\n" +
                        "Must run this prior to running script in batch mode.")
    p.add_argument("-b", "--batch_start", action="store_true",
                   help="Run script in batch mode using stored token and options stored in config file.")
    p.add_argument("-i", "--interactive", action="store_true",
                   help="Run script in interactive mode.")

    a = p.parse_args()

    if (a.test and a.batch_start) or (a.test and a.interactive) or (a.interactive and a.batch_start):
        print "Set only one of --config, --batch, or --interactive"
        exit(1)

    if not a.test and not a.batch_start and not a.interactive:
        p.print_help()
        exit(0)

    return a


def main():
    args = parse_arguments()
    paths = set_config_file_paths()
    init_config_dir(paths)

    if args.batch_start:
        batch_start_mode(paths)
        exit(0)
    elif args.test:
        batch_setup_mode(paths)
        exit(0)
    elif args.interactive:
        interactive_mode(paths)
        exit(0)
    else:
        print ("Should not be here!")
        exit(1)


if __name__ == "__main__":
    main()
