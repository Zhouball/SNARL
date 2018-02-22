#!/bin/bash

DB_NAME="escality"

# Create db named escality
#mysql -u root -p < 2018-02-21-00-create_db.sql

# Create users table
mysql -u root -p $DB_NAME < 2018-02-21-01-users.sql
