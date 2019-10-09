#!/bin/bash
cd $(dirname $0)
uwsgi --protocol=http --plugin python3 -p 1 -w server:app --logto /dev/null