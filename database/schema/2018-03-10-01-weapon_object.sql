CREATE TABLE `weapon_objects` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `object_name` VARCHAR(32) NOT NULL,
  `object_desc` VARCHAR(128),
  `weapon_type` ENUM('SWORD','DAGGER','MACE') NOT NULL,
  `power` INT(11) NOT NULL,
  `status` ENUM('OWNED','AVAILABLE') NOT NULL DEFAULT 'AVAILABLE',
  `owner` VARCHAR(32),
  `create_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `update_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY (`owner`),
  CONSTRAINT `weapon_objects_0` FOREIGN KEY (`owner`) REFERENCES `users` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8