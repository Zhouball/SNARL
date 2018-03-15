#!/bin/bash

PW="escality1" #$1
ADMIN_DB="administrative"
GAME_DB="game"
CONF=$HOME/src/SNARL/database/mysql.cnf
# Create db named escality
mysql --defaults-extra-file=$CONF < 2018-02-21-00-create_db.sql

# Create salts table
mysql --defaults-extra-file=$CONF $ADMIN_DB < 2018-02-21-02-salts.sql

# Create users table
mysql --defaults-extra-file=$CONF $ADMIN_DB < 2018-02-21-01-users.sql

# Create general_objects table
mysql --defaults-extra-file=$CONF $GAME_DB < 2018-03-10-00-general_object.sql

# Create weapon_objects table
mysql --defaults-extra-file=$CONF $GAME_DB < 2018-03-10-01-weapon_object.sql

# Create dropped_objects table
mysql --defaults-extra-file=$CONF $GAME_DB < 2018-03-10-02-dropped_objects.sql
