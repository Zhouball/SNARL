#!/bin/bash

PW="escality1" #$1
ADMIN_DB="administrative"
GAME_DB="game"

# Create db named escality
mysql -u root -p < 2018-02-21-00-create_db.sql

# Create salts table
mysql -u root -p$PW $ADMIN_DB < 2018-02-21-02-salts.sql

# Create users table
mysql -u root -p$PW $ADMIN_DB < 2018-02-21-01-users.sql

# Create general_objects table
mysql -u root -p$PW $GAME_DB < 2018-03-10-00-general_object.sql

# Create weapon_objects table
mysql -u root -p$PW $GAME_DB < 2018-03-10-01-weapon_object.sql

# Create dropped_objects table
mysql -u root -p$PW $GAME_DB < 2018-03-10-02-dropped_objects.sql
