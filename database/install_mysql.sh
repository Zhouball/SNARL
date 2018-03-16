#!/bin/bash

# This script installs MySQL Server.
# Args: password
# Call with:
# $./install_mysql.sh `password`

if [[ $# -eq 0 ]] ; then
    echo 'Please enter password to set up database'
    exit 1
fi

echo "[client]
user=root
password="$1"
host=localhost" > mysql.cnf

DEFAULT_PW=$1
SET_PW="mysql-server mysql-server/root_password password "$DEFAULT_PW
SET_PW_AGAIN="mysql-server mysql-server/root_password_again password "$DEFAULT_PW

sudo debconf-set-selections <<< $SET_PW
sudo debconf-set-selections <<< $SET_PW_AGAIN
sudo apt-get update
sudo apt-get -y install mysql-server
