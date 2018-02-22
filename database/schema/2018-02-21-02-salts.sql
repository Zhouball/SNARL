CREATE TABLE `salts` (
  `username` varchar(32) NOT NULL,
  `salt` varchar(16) NOT NULL,
  PRIMARY KEY (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8
