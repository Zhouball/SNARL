# SNARL

### INSTALLATION
These dependences are required to build and run SNARL.

##### Proxygen
SNARL depends on Facebook's [Proxygen](https://github.com/facebook/proxygen). Installation is
```
git clone git@github.com:facebook/proxygen.git
cd proxygen/proxygen
./deps.sh
./reinstall.sh
```

More information can be found at https://github.com/facebook/proxygen.

##### OpenSSL
```
sudo apt-get install libssl-dev
```

##### MySQL
```
sudo apt-get install mysql-server
sudo apt-get install libmysqlcppconn-dev
```
Start the background service with
```
service mysql start
```
##### boost

If boost is already inside /usr/include then there is nothing to do. If not, please
download the binary archive and put it in some location. Change the PATHS macro in
the Makefile to reflect this location

