#include <vector>
#include <string>
#include "mysql_connection.h"
#include <mysql_driver.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>

/* A class to manage the accounts database. Apart from documentation,
   the implementation file contains description of parameters and return values */

class Account_Manager {
 public:
  /* Constructor */
  Account_Manager(std::string username, std::string password, std::string db_addr);
  
  /* Accessors */
  int check_credentials(std::string username, std::string email, std::string password);
  int details_by_username(std::string username, std::string& email, std::string& firstname,
			  std::string& lastname, std::string& create_date, std::string& update_date,
			  int& admin);

  /* Modifiers */
  int delete_user(std::string username);
  int add_user(std::string username, std::string password, std::string firstname,
	       std::string lastname, std::string email, int admin);
  
 private:
  /* data members */
  std::string m_username;
  std::string m_password;
  std::string m_db_addr;
  const std::string DB_NAME = "escality";
  const std::string SALT_USERNAME_TABLE = "salts"; //name of the table containing (username, salt)
  const std::string MAIN_TABLE = "users";          //name of the main user details table
  
  /* functions */
  void openssl_init();
  unsigned long salt_generator();
  int count_digits(unsigned long x);
  char *hash_plaintext(const char *plaintext, int len, unsigned long salt);
  std::string char_to_hex(char *str, int len);
};
