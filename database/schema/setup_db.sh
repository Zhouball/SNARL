#!/bin/bash

PW=$1
DB_NAME="escality"

# Create db named escality
mysql -u root -p < 2018-02-21-00-create_db.sql

# Create salts table
mysql -u root -p$PW $DB_NAME < 2018-02-21-02-salts.sql

# Create users table
mysql -u root -p$PW $DB_NAME < 2018-02-21-01-users.sql
