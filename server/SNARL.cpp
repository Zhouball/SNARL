#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <random>
#include <sstream>
#include <ctime>
#include <cassert>       //For testing only
#include "openssl/sha.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "SNARL.h"
#include <algorithm>

#include "mysql_connection.h"
#include <mysql_driver.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>

// All times sent to database are in UTC


/*..........................
        Account_Manager
 ...........................*/


/* private */
void Account_Manager::openssl_init() {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
}

unsigned long Account_Manager::salt_generator() { //unsigned 32-bit int from uniform distribution
  std::random_device seed;
  std::mt19937 generator(seed());
  std::uniform_int_distribution<unsigned long> dist(0, (unsigned long) 4294967295);
  return dist(generator);
}

int Account_Manager::count_digits(unsigned long x) {
  return (x < 10 ? 1 :
	  (x < 100 ? 2 :
	   (x < 1000 ? 3 :
	    (x < 10000 ? 4 :
	     (x < 100000 ? 5 :
	      (x < 1000000 ? 6 :
	       (x < 10000000 ? 7 :
		(x < 100000000 ? 8 :
		 (x < 1000000000 ? 9 :
		  10))))))))); 
}

char *Account_Manager::hash_plaintext(const char *plaintext, int len, unsigned long salt) {
  /* final value is hash(concatenate(hash(plaintext), salt)) 
     returns NULL upon error 
     the size of returned array is SHA512_DIGEST_LENGTH */
  
  SHA512_CTX ctx1;
  unsigned char md1[SHA512_DIGEST_LENGTH];
  int n = SHA512_Init(&ctx1);
  if (n == 0)
    return NULL;
  
  n = SHA512_Update(&ctx1, (const unsigned char *) plaintext, len);
  if (n == 0)
    return NULL;
  
  n = SHA512_Final(md1, &ctx1);
  if (n == 0)
    return NULL;

  SHA512_CTX ctx_fin;
  unsigned char *md_fin = (unsigned char *) malloc(sizeof(unsigned char) * (SHA512_DIGEST_LENGTH + 1));
  unsigned char input[SHA512_DIGEST_LENGTH + 12];    // 32-bit number has < 12 digits
  
  memcpy(input, md1, SHA512_DIGEST_LENGTH);
  sprintf(((char *) input) + SHA512_DIGEST_LENGTH, "%lu", salt);
  int salt_size = count_digits(salt);

  n = SHA512_Init(&ctx_fin);
  if (n == 0)
    return NULL;

  n = SHA512_Update(&ctx_fin, input, SHA512_DIGEST_LENGTH + salt_size);
  if (n == 0)
    return NULL;

  n = SHA512_Final(md_fin, &ctx_fin);
  if (n == 0)
    return NULL;

  md_fin[SHA512_DIGEST_LENGTH] = 0;        //terminating null byte
  return (char *) md_fin;
}

std::string Account_Manager::char_to_hex(char *str, int len) {
  std::stringstream ss;
  for (int i = 0; i < len; i++) {
    ss.width(2);
    ss.fill('0');
    ss << std::hex << (str[i] & 0xff);
  }
  return ss.str();
}


/* public */
Account_Manager::Account_Manager(std::string username, std::string password, std::string db_addr) {
  m_username = username;
  m_password = password;
  m_db_addr = db_addr;
  openssl_init();
}

int Account_Manager::check_credentials(std::string username, std::string email, std::string password) {
  // Returns -1 upon invalid details
  // Returns -2 upon OpenSSL failure. Exception upon mysql failure
  // Returns -3 if both arguments empty
  // at least one of username and email must be non-empty string

  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;
    sql::ResultSet *res;
    unsigned long salt;
  
    if (username == "" && email == "")
      return -3;

    driver = sql::mysql::get_mysql_driver_instance();
    con = driver->connect("tcp://" + m_db_addr, m_username, m_password);
    
    stmt = con->createStatement();
    stmt->execute("USE " + DB_NAME);
    
    std::string hash_and_salt;
    
    if (username != "") {      //search by username
      std::string command = "SELECT salt FROM " + SALT_USERNAME_TABLE + " WHERE username = '"
	+ username + "';";
      res = stmt->executeQuery(command);
    
      if (res->next())
	salt = std::stoul(res->getString("salt")); 
      else {                    //No such username
	delete con;
	delete stmt;
	delete res;
	return -1;
      }
      delete res;
    
      command = "SELECT hash_and_salt FROM " + MAIN_TABLE + " WHERE username = '" +
	username + "';";
      res = stmt->executeQuery(command);  //Obtain hash_and_salt from database
    
      if (res->next())
	hash_and_salt = res->getString("hash_and_salt");
    }

    else {         //search by email
      std::string command = "SELECT username, hash_and_salt FROM " + MAIN_TABLE +
	" WHERE email = '" + email + "';";
      res = stmt->executeQuery(command);
      
      std::string username;
    
      if (res->next()) {
	hash_and_salt = res->getString("hash_and_salt");
	username = res->getString("username");
      }
      else {      //no such email
	delete con;
	delete stmt;
	delete res;
	return -1;
      }
      delete res;

      command = "SELECT salt FROM " + SALT_USERNAME_TABLE + " WHERE username = '" + username + "';";
      res = stmt->executeQuery(command);
      
      if (res->next())
	salt = std::stoul(res->getString("salt"));
    }
  
    char *plaintext = (char *) malloc(sizeof(char) * (password.size() + 1));
    strcpy(plaintext, password.c_str());

    char *recomputed_cstr = hash_plaintext(plaintext, password.size(), salt);
    if (recomputed_cstr == NULL) {
      free(recomputed_cstr);
      free(plaintext);
      delete con;
      delete stmt;
      delete res;
      return -2;
    }

    std::string recomputed = char_to_hex(recomputed_cstr, SHA512_DIGEST_LENGTH);
    if (recomputed != hash_and_salt) //recomputed hash is different
      return -1;

    free(recomputed_cstr);
    free(plaintext);
    delete con;
    delete stmt;
    delete res;
    return 0;
  }
  
  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}

int Account_Manager::add_user(std::string username, std::string password, std::string firstname,
	     std::string lastname, std::string email, int admin) {

  /* Returns -1 upon OpenSSL failure. Exception upon mysql failure 
     admin should be 1 if the user is an administrator. Else it should be 0 */

  try {
    unsigned long salt = salt_generator();        //generate the salt
    char *plaintext = (char *) malloc(sizeof(const char) * (1 + password.size()));
    strcpy(plaintext, password.c_str());
    char *hash_and_salt_cstr = hash_plaintext(plaintext, password.size(), salt); //hash the password
    
    if (hash_and_salt_cstr == NULL)
      return -1;

    //convert char to two-digit hexadecimal
    std::string hash_and_salt = char_to_hex(hash_and_salt_cstr, SHA512_DIGEST_LENGTH);

    free(hash_and_salt_cstr);
    free(plaintext);

    /* actual mysql stuff starts here */
    
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;
  
    driver = sql::mysql::get_mysql_driver_instance();
    con = driver->connect("tcp://" + m_db_addr, m_username, m_password);
    
    stmt = con->createStatement();
    stmt->execute("USE " + DB_NAME);
  
    std::string command = "INSERT INTO " + SALT_USERNAME_TABLE + " VALUES ('" + //Insert (username, salt)
      username + "', " + std::to_string(salt) + ");";
    stmt->execute(command);
  
    std::time_t rawtime; //Obtain time
    std::tm* timeinfo;
    char time_buf[64];
    std::time(&rawtime);
    timeinfo = std::gmtime(&rawtime);
    std::strftime(time_buf, 64,"%Y-%m-%d %H:%M:%S",timeinfo);
    std::string time_str(time_buf);
    
    command = "INSERT INTO " + MAIN_TABLE +
      " (username, first_name, last_name, permission, email, hash_and_salt, create_date, update_date) VALUES ";
  
    command += "('" + username + "', '" + firstname + "', '" + lastname;
    if (admin)
      command += "', 'ADMIN";
    else
      command += "', 'USER";
  
    command += "', '" + email + "', '" + hash_and_salt + "', '" + time_str + "', '"
      + time_str + "');";     //Insert rest of the data
  
    stmt->execute(command);
  
    delete con;
    delete stmt;
    return 0;
  }

  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}

int Account_Manager::details_by_username(std::string username, std::string& email, std::string& firstname,
			std::string& lastname, std::string& create_date, std::string& update_date,
			int& admin) {
  /* Gets details associated with username. Fills the other arguments with data
     If user is an admin, the admin argument will be set to 1. Else to 0.
     Returns -1 if username is not present in database 
     Returns -2 if username is empty string
     Exception upon mysql failure */

  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;
    sql::ResultSet *res;
  
    if (username == "")
      return -2;

    driver = sql::mysql::get_mysql_driver_instance();
    con = driver->connect("tcp://" + m_db_addr, m_username, m_password);

    stmt = con->createStatement();
    stmt->execute("USE " + DB_NAME);

    std::string command = "SELECT email, first_name, last_name, permission, create_date, update_date";
    command += " FROM " + MAIN_TABLE + " WHERE username = '" + username + "';";

    res = stmt->executeQuery(command);

    if (res->next()) {
      email = res->getString("email");
      firstname = res->getString("first_name");
      lastname = res->getString("last_name");
      create_date = res->getString("create_date");
      update_date = res->getString("update_date");
      if (res->getString("permission") == "ADMIN")
	admin = 1;
      else
	admin = 0;
    }
    else
      return -1;

    delete con;
    delete stmt;
    delete res;
    return 0;
  }

  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}

int Account_Manager::delete_user(std::string username) {
  /* Removes the user associated with username from the database 
     Returns -1 if username is empty string. Exception upon mysql error */

  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;

    if (username == "")
      return -1;

    driver = sql::mysql::get_mysql_driver_instance();
    con = driver->connect("tcp://" + m_db_addr, m_username, m_password);

    stmt = con->createStatement();
    stmt->execute("USE " + DB_NAME);

    std::string command = "DELETE FROM " + MAIN_TABLE + " WHERE username = '" + username + "';";
    stmt->execute(command);

    command = "DELETE FROM " + SALT_USERNAME_TABLE + " WHERE username = '" + username + "';";
    stmt->execute(command);
  
    delete con;
    delete stmt;
    return 0;
  }
  
  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}



/*..........................  
        Object_Manager
...........................*/



/* public */
Object_Manager::Object_Manager(std::string username, std::string password, std::vector<std::string> db_addr) {
  m_username = username;
  m_password = password;
  m_db_addr = db_addr;
  m_db_addr.erase(std::remove(m_db_addr.begin(), m_db_addr.end(), "127.0.0.1:3306"), m_db_addr.end());
  m_db_addr.push_back("127.0.0.1:3306");
}

int Object_Manager::insert_general_object(std::string name, std::string desc, int id, double lat, double lon) {
  /* Returns -1 if name is empty string, 0 if no error, error message upon MySQL error
     Objects start as if dropped at specified location, with given id. To give them to a player 
     call pickup_general_object*/
  
  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;

    if (name == "")
      return -1;

    for (int i = 0; i < m_db_addr.size(); i++) {

      std::string time_str = get_time_str();
      std::string command = "INSERT INTO " + GENERAL_OBJECTS_TABLE +
	"(id, object_name, object_desc, create_date,  update_date) VALUES (";
      
      command += std::to_string(id) + ", '" + name + "', '" + desc + "', '" + time_str + "', '" + time_str + "');";

      driver = sql::mysql::get_mysql_driver_instance();
      con = driver->connect("tcp://" + m_db_addr[i], m_username, m_password);
      stmt = con->createStatement();
      stmt->execute("USE " + DB_NAME);
      stmt->execute(command);
      
      command = "INSERT INTO " + DROPPED_TABLE +
	"(lat, lon, general_object, dropped_at) VALUES (";
      command += std::to_string(lat) + ", " + std::to_string(lon) + ", " + std::to_string(id) + ", '" +
	time_str + "');";

      stmt->execute(command);
    }

    delete con;
    delete stmt;
    return 0;
  }

  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}

int Object_Manager::drop_general_object(double lat, double lon, int id) {
  /* If the object exists, it will be dropped at the specified location 
     Returns 0 upon no error, error message upon MySQL error */
  
  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;

    for (int i = 0; i < m_db_addr.size(); i++) {
      std::string time_str = get_time_str();
      std::string command = "UPDATE " + GENERAL_OBJECTS_TABLE +
	" SET status='AVAILABLE', owner=null, update_date= '" + time_str + "' WHERE id = " + std::to_string(id);

      driver = sql::mysql::get_mysql_driver_instance();
      con = driver->connect("tcp://" + m_db_addr[i], m_username, m_password);
      stmt = con->createStatement();
      stmt->execute("USE " + DB_NAME);
      stmt->execute(command);

      command = "INSERT INTO " + DROPPED_TABLE +
	"(lat, lon, general_object, dropped_at) VALUES (";
      command += std::to_string(lat) + ", " + std::to_string(lon) + ", " + std::to_string(id) + ", '" +
	time_str + "');";
      
      stmt->execute(command);
    }

    delete con;
    delete stmt;
    return 0;
  }

  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}

int Object_Manager::pickup_general_object(int object_id, std::string owner_username) {

  /* Returns 0 upon normal operation, error message printed in case of MySQL error
     This function will assign the general_object with the id to the specified user */
  
  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;
    std::string time_str = get_time_str();
    
    for (int i = 0; i < m_db_addr.size(); i++) {
      driver = sql::mysql::get_mysql_driver_instance();
      con = driver->connect("tcp://" + m_db_addr[i], m_username, m_password);

      stmt = con->createStatement();
      stmt->execute("USE " + DB_NAME);
      
      std::string command = "DELETE FROM " + DROPPED_TABLE + " WHERE general_object = "
	+ std::to_string(object_id) + ";";
      stmt->execute(command);

      command = "UPDATE " + GENERAL_OBJECTS_TABLE + " SET status = 'OWNED', owner='" +
	owner_username + "', update_date='" + time_str + "' WHERE id=" + std::to_string(object_id) + ";";
      stmt->execute(command);
    }

    delete con;
    delete stmt;
    return 0;
  }

  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}

int Object_Manager::delete_general_object(int id) {

  /* Returns 0 in case of normal operation, error message in case of MySQL error
     This will remove all traces of the object with the id. Any players carrying it
     will no longer have it */
  
  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;

    for (int i = 0; i < m_db_addr.size(); i++) {
      driver = sql::mysql::get_mysql_driver_instance();
      con = driver->connect("tcp://" + m_db_addr[i], m_username, m_password);

      stmt = con->createStatement();
      stmt->execute("USE " + DB_NAME);

      std::string command = "DELETE FROM " + DROPPED_TABLE + " WHERE general_object = "
	+ std::to_string(id) + ";";
      stmt->execute(command);

      command = "DELETE FROM " + GENERAL_OBJECTS_TABLE + " WHERE id = " + std::to_string(id) + ";";
      stmt->execute(command);
    }
    
    delete con;
    delete stmt;
    return 0;
  }
  
  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}

int Object_Manager::insert_weapon_object(std::string name, std::string desc, std::string weapon_type, int power,
					 int id, double lat, double lon) {
  /* Returns -1 if name is empty string, -2 if weapon_type is not "SWORD", "MACE", or "DAGGER",
     and error message in case of MySQL error. The weapon object is dropped at the specified 
     location. To give it to a player, call pickup_weapon_object */
  
  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;

    if (name == "")
      return -1;
    if (weapon_type != "SWORD" && weapon_type != "MACE" && weapon_type != "DAGGER")
      return -2;

    for (int i = 0; i < m_db_addr.size(); i++) {

      std::string time_str = get_time_str();
      std::string command = "INSERT INTO " + WEAPON_OBJECTS_TABLE +
	"(id, object_name, object_desc, create_date,  update_date, weapon_type, power) VALUES (";

      command += std::to_string(id) + ", '" + name + "', '" + desc + "', '" + time_str + "', '" + time_str + "', '";
      command += weapon_type + "', " + std::to_string(power) + ");";
      
      driver = sql::mysql::get_mysql_driver_instance();
      con = driver->connect("tcp://" + m_db_addr[i], m_username, m_password);
      stmt = con->createStatement();
      stmt->execute("USE " + DB_NAME);
      stmt->execute(command);

      command = "INSERT INTO " + DROPPED_TABLE +
	"(lat, lon, weapon_object, dropped_at) VALUES (";
      command += std::to_string(lat) + ", " + std::to_string(lon) + ", " + std::to_string(id) + ", '" +
	time_str + "');";

      stmt->execute(command);
    }

    delete con;
    delete stmt;
    return 0;
  }

  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}

int Object_Manager::drop_weapon_object(double lat, double lon, int id) {
  /* If the object exists, it will be dropped at the specified location
     Returns 0 upon no error, error message upon MySQL error */

  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;

    for (int i = 0; i < m_db_addr.size(); i++) {
      std::string time_str = get_time_str();
      std::string command = "UPDATE " + WEAPON_OBJECTS_TABLE +
	" SET status='AVAILABLE', owner=null, update_date= '" + time_str + "' WHERE id = " + std::to_string(id);

      driver = sql::mysql::get_mysql_driver_instance();
      con = driver->connect("tcp://" + m_db_addr[i], m_username, m_password);
      stmt = con->createStatement();
      stmt->execute("USE " + DB_NAME);
      stmt->execute(command);

      command = "INSERT INTO " + DROPPED_TABLE +
	"(lat, lon, weapon_object, dropped_at) VALUES (";
      command += std::to_string(lat) + ", " + std::to_string(lon) + ", " + std::to_string(id) + ", '" +
	time_str + "');";

      stmt->execute(command);
    }

    delete con;
    delete stmt;
    return 0;
  }
      
  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5; 
  }
}

int Object_Manager::pickup_weapon_object(int object_id, std::string owner_username) {
  /* Returns 0 upon normal operation, error message printed in case of MySQL error
     This function will assign the weapon_object with the id to the specified user */
  
  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;
    std::string time_str = get_time_str();

    for (int i = 0; i < m_db_addr.size(); i++) {
      driver = sql::mysql::get_mysql_driver_instance();
      con = driver->connect("tcp://" + m_db_addr[i], m_username, m_password);

      stmt = con->createStatement();
      stmt->execute("USE " + DB_NAME);

      std::string command = "DELETE FROM " + DROPPED_TABLE + " WHERE weapon_object = "
	+ std::to_string(object_id) + ";";
      stmt->execute(command);

      command = "UPDATE " + WEAPON_OBJECTS_TABLE + " SET status = 'OWNED', owner='" +
	owner_username + "', update_date='" + time_str + "' WHERE id=" + std::to_string(object_id) + ";";
      stmt->execute(command);
    }

    delete con;
    delete stmt;
    return 0;
  }
  
  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}

int Object_Manager::delete_weapon_object(int id) {
  /* Returns 0 in case of normal operation, error message in case of MySQL error
     This will remove all traces of the object with the id. Any players carrying it
     will no longer have it */
  
  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;

    for (int i = 0; i < m_db_addr.size(); i++) {
      driver = sql::mysql::get_mysql_driver_instance();
      con = driver->connect("tcp://" + m_db_addr[i], m_username, m_password);

      stmt = con->createStatement();
      stmt->execute("USE " + DB_NAME);

      std::string command = "DELETE FROM " + DROPPED_TABLE + " WHERE weapon_object = "
	+ std::to_string(id) + ";";
      stmt->execute(command);

      command = "DELETE FROM " + WEAPON_OBJECTS_TABLE + " WHERE id = " + std::to_string(id) + ";";
      stmt->execute(command);
    }

    delete con;
    delete stmt;
    return 0;
  }
  
  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}


int Object_Manager::general_objects_at(double lat, double lon, std::vector<std::string>& name,
				       std::vector<std::string>& desc, std::vector<int>& id) {
  
  /* This returns all general_objects at the specified location. Names go in name, descriptions go
     in desc, object id goes in id. This function WILL CLEAR vector arguments.
     This function consults ONLY THE LOCAL DATABASE. This greatly decreases latency.
     Returns 0 upon normal operation, or prints error message in case MySQL error */

  name.clear();
  desc.clear();
  id.clear();
  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;
    sql::ResultSet *res;

    driver = sql::mysql::get_mysql_driver_instance();
    con = driver->connect("tcp://127.0.0.1:3306", m_username, m_password);

    stmt = con->createStatement();
    stmt->execute("USE " + DB_NAME);

    std::string command = "select general_object from " + DROPPED_TABLE + " where lat = " + std::to_string(lat);
    command += " and lon = " + std::to_string(lon) + ";";
    res = stmt->executeQuery(command);

    while(res->next())
      id.push_back(std::stoi(res->getString("general_object")));

    for (int i = 0; i < id.size(); i++) {
      command = "select * from " + GENERAL_OBJECTS_TABLE + " where id = " + std::to_string(id[i]) + ";";
      res = stmt->executeQuery(command);

      if (res->next()) {
	name.push_back(res->getString("object_name"));
	desc.push_back(res->getString("object_desc"));
      }
    }
    
    delete con;
    delete stmt;
    delete res;
    return 0;
  }
  
  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}

int Object_Manager::weapon_objects_at(double lat, double lon, std::vector<std::string>& name,
				      std::vector<std::string>& desc, std::vector<std::string>& type,
				      std::vector<int>& power, std::vector<int>& id) {

  /* This returns all weapon_objects at the specified location. Names go in name, descriptions go
     in desc, object id goes in id, weapon type goes in type, power of the weapon goes in power
     This function WILL CLEAR the vector arguments. 
     This function consults ONLY THE LOCAL DATABASE. This greatly decreases latency.
     Returns 0 upon normal operation, or prints error message in case MySQL error */
  
  name.clear();
  desc.clear();
  type.clear();
  power.clear();
  id.clear();
  
  try {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;
    sql::ResultSet *res;

    driver = sql::mysql::get_mysql_driver_instance();
    con = driver->connect("tcp://127.0.0.1:3306", m_username, m_password);

    stmt = con->createStatement();
    stmt->execute("USE " + DB_NAME);

    std::string command = "select weapon_object from " + DROPPED_TABLE + " where lat = " + std::to_string(lat);
    command += " and lon = " + std::to_string(lon) + ";";
    res = stmt->executeQuery(command);

    while(res->next())
      id.push_back(std::stoi(res->getString("weapon_object")));

    for (int i = 0; i < id.size(); i++) {
      command = "select * from " + WEAPON_OBJECTS_TABLE + " where id = " + std::to_string(id[i]) + ";";
      res = stmt->executeQuery(command);

      if (res->next()) {
	name.push_back(res->getString("object_name"));
	desc.push_back(res->getString("object_desc"));
	type.push_back(res->getString("weapon_type"));
	power.push_back(std::stoi(res->getString("power")));
      }
    }

    delete con;
    delete stmt;
    delete res;
    return 0;
  }
  
  catch (sql::SQLException &e) {
    std::cout << "# ERR: SQLException in " << __FILE__;
    std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
    std::cout << "# ERR: " << e.what();
    std::cout << " (MySQL error code: " << e.getErrorCode();
    std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    return -5;
  }
}

/* private */
std::string Object_Manager::get_time_str() {
  std::time_t rawtime; //Obtain time
  std::tm* timeinfo;
  char time_buf[64];
  std::time(&rawtime);
  timeinfo = std::gmtime(&rawtime);
  std::strftime(time_buf, 64,"%Y-%m-%d %H:%M:%S",timeinfo);
  std::string time_str(time_buf);
  return time_str;
}
 
int main(int argc, char **argv) {

  std::vector<std::string> addr;
  addr.push_back("127.0.0.1:3306");
  Object_Manager om("root", "", addr);
  om.insert_general_object("guitar", "two-string", 225, 74.6, 10.5);
  om.insert_general_object("Mac", "11 inch", 447, 74.6, 10.5);
  om.insert_general_object("Apple", "Green", 508, 74.6, 10.5);
  om.insert_general_object("Apple", "Green", 509, 74.6, 10.5);
  om.insert_general_object("Apple", "Black", 510, 74.6, 10.5);
  om.insert_general_object("Apple", "Green", 511, 74.6, 10.5);
  om.insert_general_object("Dell", "PC", 512, 70.6, 10.9);
  assert(om.insert_weapon_object("swiss_knife", "ultra-swiss", "BLAH", 40, 300, 20.9, 32.5) == -2);
  assert(om.insert_weapon_object("swiss_knife", "ultra-swiss", "SWORD", 40, 300, 20.9, 32.5) == 0);
  assert(om.insert_weapon_object("bighammer", "Thor-class", "MACE", 80, 301, 20.9, 32.5) == 0);
  assert(om.insert_weapon_object("khukri", "Gurkha-level", "SWORD", 90, 302, 20.9, 32.5) == 0);
  assert(om.insert_weapon_object("byzantine spear", "deadly", "SWORD", 100, 309, 20, 30.5) == 0);
  
  std::vector<std::string> name;
  std::vector<std::string> desc;
  std::vector<int> id;
  std::vector<int> power;
  std::vector<std::string> type;
  
  om.general_objects_at(74.6, 10.5, name, desc, id);

  for (int i = 0; i < id.size(); i++) {
    std::cout << name[i] << " " << desc[i] << " " << id[i] << std::endl;
  }

  om.weapon_objects_at(20.9, 32.5, name, desc, type, power, id);

  for (int i = 0; i < id.size(); i++) {
    std::cout << name[i] << " " << desc[i] << " " << type[i] << " " << power[i] << " "  << id[i] << std::endl;
  }
  
  om.delete_general_object(225);
  om.delete_general_object(447);
  om.delete_general_object(508);
  om.delete_general_object(509);
  om.delete_general_object(510);
  om.delete_general_object(511);
  om.delete_general_object(512);
  om.delete_weapon_object(300);
  om.delete_weapon_object(301);
  om.delete_weapon_object(302);
  om.delete_weapon_object(309);
  
  /*
  Account_Manager manager("root", "man50sarovar100", "127.0.0.1:3306");
  assert(manager.add_user("billclinton", "passwordclint", "BILL", "CLINTON", "billclinton@g.ucla.edu", 1) == 0);
  assert(manager.add_user("akshaysmit", "password234", "AKSHAY", "SMIT", "akshaysmit@g.ucla.edu", 0) == 0);
  assert(manager.add_user("justint", "424by424", "JUSTIN", "TRUDEAU", "justint@g.ucla.edu", 0) == 0);
  assert(manager.add_user("user1", "password1", "USER", "1", "user1@g.ucla.edu", 0) == 0);
  assert(manager.add_user("user2", "password2", "USER", "2", "user2@g.ucla.edu", 0) == 0);
  assert(manager.add_user("user3", "password3", "USER", "3", "user3@g.ucla.edu", 0) == 0);
  assert(manager.add_user("user4", "password4", "USER", "4", "user4@g.ucla.edu", 0) == 0);

  assert(manager.check_credentials("akshaysmit", "", "password234") == 0);
  assert(manager.check_credentials("", "", "") == -3);
  assert(manager.check_credentials("", "akshaysmit@g.ucla.edu", "password234") == 0);
  assert(manager.check_credentials("", "justint@g.ucla.edu", "wrong") == -1);
  assert(manager.check_credentials("blah", "", "blahpass") == -1);
  assert(manager.check_credentials("", "blah@g.ucla.edu", "wrong") == -1);

  std::string email, firstname, lastname, create_date, update_date;
  int admin;

  manager.details_by_username("akshaysmit", email, firstname, lastname, create_date, update_date, admin);
  std::cout << email << " " << firstname << " " << lastname << " " << create_date << " "
	    << update_date << " " << admin << std::endl;
  
  assert(manager.delete_user("akshaysmit") == 0);
  assert(manager.delete_user("billclinton") == 0);
  assert(manager.delete_user("justint") == 0);
  assert(manager.delete_user("user1") == 0);
  assert(manager.delete_user("user2") == 0);
  assert(manager.delete_user("user3") == 0);
  assert(manager.delete_user("user4") == 0);

  */
}
