#!/usr/bin/python3
"""
Usage: %(scriptName)s

Configures a Nessus scanner based on a systems environment variables.

"""

from __future__ import print_function

import json
import os
import pexpect
import socket
import requests
import subprocess
import sys
import time

from datetime import datetime

__version__ = "1"

requests.packages.urllib3.disable_warnings()

# General
GLOBAL_DB_TIMEOUT = os.getenv("GLOBAL_DB_TIMEOUT", 120)
ACTIVATION_CODE = os.getenv("ACTIVATION_CODE", None)
NAME = os.getenv("NAME", socket.gethostname())
USERNAME = os.getenv("USERNAME", None)
PASSWORD = os.getenv("PASSWORD", None)

# Update options:
AUTO_UPDATE = os.getenv("AUTO_UPDATE", "all")
DISABLE_CORE_UPDATES = os.getenv("DISABLE_CORE_UPDATES", "no") # For managed scanners

# Linking options
LINKING_KEY = os.getenv("LINKING_KEY", None)
MANAGER_HOST = os.getenv("MANAGER_HOST", "cloud.tenable.com")
MANAGER_PORT = os.getenv("MANAGER_PORT", "443")
SELF_HOST = os.getenv("SELF_HOST", NAME)
SELF_PORT = os.getenv("SELF_PORT", "8834")
RETRY_ON_FAIL = os.getenv("RETRY_ON_FAIL", False)
RETRY_ON_FAIL_SLEEP = os.getenv("RETRY_ON_FAIL_SLEEP", 30)

# Proxy config:
PROXY = os.getenv("PROXY", None)
PROXY_PORT = os.getenv("PROXY_PORT", None)
PROXY_USER = os.getenv("PROXY_USER", None)
PROXY_PASS = os.getenv("PROXY_PASS", None)


def nessus_config(setting, value, secure=False):
    """
    Configure nessuscli fix related options.

    :param str setting: Nessus advanced setting name
    :param str value: Nessus advanced setting value
    :param bool secure: False to enable a secure advanced setting.
    """
    custom_print("Setting {0} to {1}.".format(setting, value))

    cmd = ["/opt/nessus/sbin/nessuscli", "fix", "--set"]
    if secure:
        cmd.extend(["--secure"])
    cmd.extend(["{0}={1}".format(str(setting), str(value))])

    command_output = subprocess.call(cmd)
    if command_output != 0:
        custom_print("Failed to set {0}. Error code: {1}".format(setting, str(command_output)))
        return False
    else:
        return True


def activate(code):
    """
    Activate Nessus using a provided activation code.

    :param str code: the activation code for Nessus.
    """
    custom_print("Activating with code: {0}".format(code))

    subprocess.call(["supervisorctl", "stop", "nessusd"])

    nessus_activated = subprocess.call(["/opt/nessus/sbin/nessuscli", "fetch", "--register", code])
    if nessus_activated != 0:
        custom_print("Failed to activate Nessus using code {0}.".format(str(code)))
        return False

    custom_print("Activated scanner successfully.")

    if AUTO_UPDATE == "all":
        custom_print("Auto updates are on.")

    if AUTO_UPDATE == "plugins":
        custom_print("Core updates are off but plugin updates are turned on.")

    if AUTO_UPDATE == "no":
        custom_print("Updates are turned off.")

    start = subprocess.call(["supervisorctl", "start", "nessusd"])
    if start != 0:
        custom_print("Failed to start Nessus after activation")
        return False

    return True


def add_user():
    """Add a user to Nessus using nessuscli tool."""
    custom_print("Adding user to scanner.")
    if (ACTIVATION_CODE or LINKING_KEY) and USERNAME is None and PASSWORD is None:
        custom_print('Activation code or linking key provided but no username and password provided; exiting.')
        return False

    if (ACTIVATION_CODE or LINKING_KEY) and USERNAME is not None and PASSWORD is None:
        custom_print('Activation code or linking key provided and username was provided, but not a password; exiting.')
        return False

    if USERNAME is None or PASSWORD is None:
        custom_print('Username and password not provided. Skipping user creation.')
        return True


    child = pexpect.spawn("/opt/nessus/sbin/nessuscli" + ' adduser')

    a = child.expect(['Login:',
                      'Your license does not allow you to create more than one user'])
    if a == 0:
        child.sendline(USERNAME)
    elif a == 1:
        custom_print("Note: User {0} failed to create because of licensing constraints. "
                     "There is already a user created, continuing..".format(USERNAME))
        return True

    i = child.expect(['Login password:', 'already exists'])
    if i == 0:
        custom_print("Setting Password.")
        child.sendline(PASSWORD)

        custom_print("Confirming Password..")
        child.expect('Login password .*')
        child.sendline(PASSWORD)

        custom_print("Adding administrator privileges.")
        child.expect('Do you want this user to be .*')
        child.sendline('y')

        custom_print("No Rules needed.")
        child.expect('the user can have an empty rules set')
        child.sendline('')

        custom_print("Confirming user addition.")
        child.expect('Is that ok?')
        child.sendline('y\n')
        child.expect('User added')
        custom_print("Successfully added user: {0}/{1}".format(USERNAME, PASSWORD))

        return True

    elif i == 1:
        custom_print("User {0} exists on the scanner. Skipping.".format(USERNAME))
        child.kill(0)
        return True


def cli_configure():
    """
    Configure various Nessus advanced options with nessuscli.

    :return: True when complete.
    """

    # General Settings
    nessus_config(setting="ms_name", value=NAME, secure=True)

    if AUTO_UPDATE == "all":
        nessus_config(setting="auto_update", value=True)

    if AUTO_UPDATE == "plugins":
        nessus_config(setting="auto_update_ui", value="no")
        nessus_config(setting="auto_update", value=True)

    if AUTO_UPDATE == "no":
        nessus_config(setting="auto_update", value=False)

    if LINKING_KEY:
        nessus_config(setting="disable_core_updates", value=DISABLE_CORE_UPDATES)

    restarted = subprocess.call(["supervisorctl", "restart", "nessusd"])
    if restarted != 0:
        custom_print("Failed to restart nessusd")

    return True


def managed_link(remote_port):
    """Link Managed scanner to a Nessus, or T.io."""
    try:
        # Python 2.6 and older does not support check_output. Popen could be used instead. Using call for now tho.
        min_version = (2, 7)
        if sys.version_info < min_version:
            # Python 2.6 and lower.
            if PROXY:
                linked = subprocess.call(["/opt/nessus/sbin/nessuscli", "managed", "link",
                                          "--key=" + str(LINKING_KEY),
                                          "--name=" + str(NAME),
                                          "--host=" + str(MANAGER_HOST),
                                          "--port=" + str(remote_port),
                                          "--proxy-host=" + str(PROXY),
                                          "--proxy-port=" + str(PROXY_PORT),
                                          "--proxy-username=" + str(PROXY_USER),
                                          "--proxy-password=" + str(PROXY_PASS)])
            else:
                linked = subprocess.call(["/opt/nessus/sbin/nessuscli", "managed", "link",
                                          "--key=" + str(LINKING_KEY),
                                          "--name=" + str(NAME),
                                          "--host=" + str(MANAGER_HOST),
                                          "--port=" + str(remote_port)])

            if linked == 0:
                custom_print("Scanner successfully linked to {0}:{1}".format(MANAGER_HOST, remote_port))
                return True
            else:
                custom_print("Scanner failed to link to controller at {0}:{1}.".format(MANAGER_HOST, remote_port))
                return False

        else:
            # Python 2.7+
            if PROXY:
                linked = subprocess.check_output(["/opt/nessus/sbin/nessuscli", "managed", "link",
                                                  "--key=" + str(LINKING_KEY),
                                                  "--name=" + str(NAME),
                                                  "--host=" + str(MANAGER_HOST),
                                                  "--port=" + str(remote_port),
                                                  "--proxy-host=" + str(PROXY),
                                                  "--proxy-port=" + str(PROXY_PORT),
                                                  "--proxy-username=" + str(PROXY_USER),
                                                  "--proxy-password=" + str(PROXY_PASS)])
            else:
                linked = subprocess.check_output(["/opt/nessus/sbin/nessuscli", "managed", "link",
                                                  "--key=" + str(LINKING_KEY),
                                                  "--name=" + str(NAME),
                                                  "--host=" + str(MANAGER_HOST),
                                                  "--port=" + str(MANAGER_PORT)])

    except subprocess.CalledProcessError as error:
        custom_print("Scanner failed to link to controller at {0}:{1}. Reason: {2}".format(MANAGER_HOST,
                                                                                           remote_port, str(error)))
        return False

    if linked:
        if "Failed" in linked.decode("utf-8"):
            custom_print("Scanner failed to link to controller at {0}:{1}. Reason: {2}".format(MANAGER_HOST,
                                                                                               remote_port, linked))
            return False
        else:
            custom_print("Scanner successfully linked to controller {0}:{1}".format(MANAGER_HOST, remote_port))
            return linked
    else:
        return False


def configure_managed_scanner():
    """
    Configure Nessus Scanner as a managed scanner. If MANAGER_REMOTE_PORT is set, connect to that port instead of
    MANAGER_PORT.

    :return: True if success, False if failed.
    """
    custom_print("Linking scanner to configured controller.")
    subprocess.call(["/opt/nessus/sbin/nessuscli", "fix", "--secure", "--set", "managed=managed"])

    linked = managed_link(MANAGER_PORT)

    if not linked:
        if RETRY_ON_FAIL:
            while not linked:
                custom_print("Failed to link to controller. Trying again in {0} secs.".format(str(RETRY_ON_FAIL_SLEEP)))
                time.sleep(int(RETRY_ON_FAIL_SLEEP))
                linked = managed_link(remote_port)
        else:
            custom_print("Managed scanner failed to link to controller.")

    if linked:
        return True
    else:
        return False


def custom_print(message):
    """
    Prints a message with date and consistent formatting.

    :param str message: A string with a message to print.
    """
    print("[{0}] {1}".format(datetime.now(), str(message)))


def wait_for_global_db():
    """Wait for nessusd to create a global.db database so that adduser etc work correctly."""
    timeout = int(GLOBAL_DB_TIMEOUT)
    for i in range(0, timeout):
        if os.path.exists("/opt/nessus/var/nessus/global.db") and os.path.getsize("/opt/nessus/var/nessus/global.db") > 0:
            return True
        time.sleep(1)
    custom_print("Nessus does not seem to have created global.db after %d seconds. Exiting." % timeout)
    return False


if __name__ == "__main__":

    custom_print("Waiting for Nessus to create global.db.")
    gdb_created = wait_for_global_db()
    if not gdb_created:
        sys.exit(3)

    custom_print("Starting to configure Nessus.")

    user_added = add_user()
    if not user_added:
        custom_print("Failed to add user to scanner.")
        sys.exit(3)

    # General nessuscli options / configuration:
    cli_configured = cli_configure()
    if not cli_configured:
        custom_print("Failed to configure scanner using nessuscli.")
        sys.exit(3)

    # Handle Activation.
    if not ACTIVATION_CODE and not LINKING_KEY:
        custom_print("Activation code or Linking key was not provided. Will use the welcome wizard.")
        sys.exit(0)

    if ACTIVATION_CODE:
        custom_print("Attempting to configure Nessus with provided activation code.")
        activated = activate(ACTIVATION_CODE)

        if not activated:
            custom_print("Failed to activate using code: {0}".format(str(ACTIVATION_CODE)))
        sys.exit(0)

    # Check for managed scanner configuration:
    if LINKING_KEY:
        custom_print("Attempting to configure as managed scanner")

        configured = configure_managed_scanner()
        if configured:
            custom_print("Successfully configured scanner as Managed.")
            sys.exit(0)
        else:
            custom_print("Failed to configure scanner as Managed.")
            sys.exit(3)
