#ifndef SNARL_H
#define SNARL_H

#include <vector>
#include <string>
#include "mysql_connection.h"
#include <mysql_driver.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>

/* A class to manage the accounts database. Any machine that wants to modify 
   accounts information should have an instance of this object. 
   The implementation file contains description of parameters and return 
   values */

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
  const std::string DB_NAME = "administrative";
  const std::string SALT_USERNAME_TABLE = "salts"; //name of the table containing (username, salt)
  const std::string MAIN_TABLE = "users";          //name of the main user details table
  
  /* functions */
  void openssl_init();
  unsigned long salt_generator();
  int count_digits(unsigned long x);
  char *hash_plaintext(const char *plaintext, int len, unsigned long salt);
  std::string char_to_hex(char *str, int len);
};


/* A class to manage the dynamic objects database. Each machine with a dynamic object database
   must have an instance of this class. The implementation file contains description of parameters 
   and return values */

class Object_Manager {
 public:
  /* Constructor */
  Object_Manager(std::string username, std::string password, std::vector<std::string> db_addr);

  /* Accessors */
  int general_objects_at(double lat, double lon, std::vector<std::string>& name, std::vector<std::string>& desc,
			 std::vector<int>& id);
  int weapon_objects_at(double lat, double lon, std::vector<std::string>& name, std::vector<std::string>& desc,
			std::vector<std::string>& type, std::vector<int>& power, std::vector<int>& id);
  
  /* Modifiers */
  int insert_general_object(std::string name, std::string desc, int id, double lat, double lon);
  int drop_general_object(double lat, double lon, int id);
  int pickup_general_object(int object_id, std::string owner_username);
  int delete_general_object(int id);
  
  int insert_weapon_object(std::string name, std::string desc, std::string weapon_type, int power,
			   int id, double lat, double lon);
  int drop_weapon_object(double lat, double lon, int id);
  int pickup_weapon_object(int object_id, std::string owner_username);
  int delete_weapon_object(int id);
  
 private:
  /* data members */
  std::string m_username;
  std::string m_password;
  std::vector<std::string> m_db_addr;
  const std::string DB_NAME = "game";                           //name of the objects database
  const std::string GENERAL_OBJECTS_TABLE = "general_objects";  //name of the general objects table
  const std::string WEAPON_OBJECTS_TABLE = "weapon_objects";    //name of the weapon objects table
  const std::string DROPPED_TABLE = "dropped_objects";          //name of the dropped objects table

  /* functions */
  std::string get_time_str();
  void CloseDBConnection(sql::Connection *con, sql::mysql::MySQL_Driver *driver);
};

#endif /* SNARL_H */
