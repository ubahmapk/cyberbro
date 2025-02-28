#!/bin/bash

# Deletes the version cache file if it exists - useful after updating the app
if [ -f "data/version_cache.json" ]; then
    rm "data/version_cache.json"
fi

# Launch advanced_config.py
python prod/advanced_config.py

# copy the config file to the correct location - doesn't change the conf if required variables are not set
cp prod/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Start supervisord
/usr/bin/supervisord -c /etc/supervisor/supervisord.conf