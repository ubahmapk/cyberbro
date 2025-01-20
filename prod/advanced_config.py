import os
import json
import configparser

# Path to the secrets file
secrets_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'secrets.json')

# Path to the supervisord.conf file
supervisord_conf_file = os.path.join(os.path.dirname(__file__), 'supervisord.conf')

# Read the secrets file
with open(secrets_file, 'r') as f:
    secrets = json.load(f)

# Read the existing supervisord.conf
config = configparser.ConfigParser()
config.read(supervisord_conf_file)

supervisor_conf_edited = False

# Update the supervisord.conf with the new parameters if they exist
if 'supervisord_workers_count' in secrets:
    config['program:cyberbro']['command'] = config['program:cyberbro']['command'].replace(
        '-w ' + config['program:cyberbro']['command'].split('-w ')[1].split()[0],
        f"-w {secrets['supervisord_workers_count']}"
    )
    supervisor_conf_edited = True

if 'supervisord_threads_count' in secrets:
    config['program:cyberbro']['command'] = config['program:cyberbro']['command'].replace(
        '-t ' + config['program:cyberbro']['command'].split('-t ')[1].split()[0],
        f"-t {secrets['supervisord_threads_count']}"
    )
    supervisor_conf_edited = True

if supervisor_conf_edited:
    # Write the updated supervisord.conf
    with open(supervisord_conf_file, 'w') as configfile:
        config.write(configfile)
