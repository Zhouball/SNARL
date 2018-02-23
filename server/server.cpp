#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <random>
#include <sstream>
#include <ctime>
#include "openssl/sha.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "mysql_connection.h"
#include <mysql_driver.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>

const std::string DB_ADDR = "127.0.0.1:3306";          //IP address and port of MySQL server
const std::string DB_NAME = "escality";
const std::string DB_USERNAME = "root";
const std::string DB_PASSWORD = "";
const std::string SALT_USERNAME_TABLE = "salts";      //name of the table containing (username, salt)
const std::string MAIN_TABLE = "users";               //name of the main user details table

/* All times sent to database are in UTC */

void openssl_init() {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
}

unsigned long salt_generator() { //unsigned 32-bit int from uniform distribution
  std::random_device seed;
  std::mt19937 generator(seed());
  std::uniform_int_distribution<unsigned long> dist(0, (unsigned long) 4294967295);
  return dist(generator);
}

int count_digits(unsigned long x) {
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

char *hash_plaintext(const char *plaintext, int len, unsigned long salt) {
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

std::string char_to_hex(char *str, int len) {
  std::stringstream ss;
  for (int i = 0; i < len; i++) {
    ss.width(2);
    ss.fill('0');
    ss << std::hex << (str[i] & 0xff);
  }
  return ss.str();
}

int check_credentials(std::string username, std::string email, std::string password) {
  // Returns -1 upon invalid details
  // Returns -2 upon OpenSSL failure. Exception upon mysql failure
  // Returns -3 if both arguments empty
  // at least one of username and email must be non-empty string

  sql::mysql::MySQL_Driver *driver;
  sql::Connection *con;
  sql::Statement *stmt;
  sql::ResultSet *res;
  unsigned long salt;
  
  if (username == "" && email == "")
    return -3;

  driver = sql::mysql::get_mysql_driver_instance();
  con = driver->connect("tcp://" + DB_ADDR, DB_USERNAME, DB_PASSWORD);

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

int add_user(std::string username, std::string password, std::string firstname,
	      std::string lastname, std::string email) {

  /* Returns -1 upon OpenSSL failure. Exception upon mysql failure */
  
  unsigned long salt = salt_generator();        //generate the salt
  char *plaintext = (char *) malloc(sizeof(const char) * (1 + password.size()));
  strcpy(plaintext, password.c_str());
  char *hash_and_salt_cstr = hash_plaintext(plaintext, password.size(), salt);       //hash the password

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
  con = driver->connect("tcp://" + DB_ADDR, DB_USERNAME, DB_PASSWORD);

  stmt = con->createStatement();
  stmt->execute("USE " + DB_NAME);
  
  std::string command = "INSERT INTO " + SALT_USERNAME_TABLE + " VALUES ('" + username + //Insert (username, salt)
    "', " + std::to_string(salt) + ");";
  stmt->execute(command);
  
  std::time_t rawtime; //Obtain time
  std::tm* timeinfo;
  char time_buf[64];
  std::time(&rawtime);
  timeinfo = std::gmtime(&rawtime);
  std::strftime(time_buf, 64,"%Y-%m-%d %H:%M:%S",timeinfo);
  std::string time_str(time_buf);
  
  command = "INSERT INTO " + MAIN_TABLE +
    " (username, first_name, last_name, email, hash_and_salt, create_date, update_date) VALUES ";
  command += "('" + username + "', '" + firstname + "', '" + lastname + "', '" + email + "', '" +
    hash_and_salt + "', '" + time_str + "', '" + time_str + "');";     //Insert rest of the data
  
  stmt->execute(command);
  
  delete con;
  delete stmt;
  return 0;
}

int main(int argc, char **argv) {
  openssl_init();
  add_user("billclinton", "passwordclint", "BILL", "CLINTON", "billclinton@g.ucla.edu");
  add_user("akshaysmit", "password234", "AKSHAY", "SMIT", "akshaysmit@g.ucla.edu");
  add_user("justint", "424by424", "JUSTIN", "TRUDEAU", "justint@g.ucla.edu");
  
  std::cout << check_credentials("akshaysmit", "", "password234") << std::endl;
  std::cout << check_credentials("", "", "") << std::endl;
  std::cout << check_credentials("", "akshaysmit@g.ucla.edu", "password234") << std::endl;
  
  /*
  sql::mysql::MySQL_Driver *driver;
  sql::Connection *con;
  sql::Statement *stmt;
  sql::ResultSet *res;
  
  driver = sql::mysql::get_mysql_driver_instance();
  con = driver->connect("tcp://127.0.0.1:3306", "root", "");

  if(!con->isValid()) {
    std::cerr << "Couldn't connect!" << std::endl;
  }

  stmt = con->createStatement();
  stmt->execute("USE countries");
  stmt->execute("INSERT INTO Countries VALUES ('Nepal', 'Asia', 28000000);");
  res = stmt->executeQuery("SELECT * FROM Countries;");
  while (res->next()) {
    std::cout << "name=" << res->getString("name");
    std::cout << ", continent=" << res->getString("continent");
    std::cout << ", population=" << res->getInt(3) << std::endl;
  }

  delete con;
  delete stmt;
  delete res; */
}
