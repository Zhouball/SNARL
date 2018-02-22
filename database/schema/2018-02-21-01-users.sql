CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(32) NOT NULL,
  `first_name` varchar(32),
  `last_name` varchar(32),  
  `status` ENUM('ACTIVE','PAUSED') NOT NULL,
  `permission` ENUM('ADMIN', 'USER') NOT NULL,
  `email` varchar(256) NOT NULL,
  `hash_and_salt` varchar(128) NOT NULL,
  `create_date` bigint(20) NOT NULL DEFAULT '0',
  `update_date` bigint(20) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY (`username`),
  UNIQUE KEY (`email`),
  CONSTRAINT `users_0` FOREIGN KEY (`username`) REFERENCES `salts` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8
