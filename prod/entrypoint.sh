#!/bin/bash

# Launch advanced_config.py
python prod/advanced_config.py

# copy the config file to the correct location - doesn't change the conf if required variables are not set
cp prod/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Start supervisord
/usr/bin/supervisord -c /etc/supervisor/supervisord.conf