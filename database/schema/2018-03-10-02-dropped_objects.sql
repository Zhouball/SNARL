CREATE TABLE `dropped_objects` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `lat` DECIMAL(10,7) NOT NULL,
  `lon` DECIMAL(10,7) NOT NULL,
  `general_object` INT(11),
  `weapon_object` INT(11),  
  `dropped_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `valid` TINYINT(1) NOT NULL DEFAULT 1,  
  PRIMARY KEY (`id`),
  KEY (`lat`),
  KEY (`lon`),  
  CONSTRAINT `dropped_objects_0` FOREIGN KEY (`general_object`) REFERENCES `general_objects` (`id`),
  CONSTRAINT `dropped_objects_1` FOREIGN KEY (`weapon_object`) REFERENCES `weapon_objects` (`id`)  
) ENGINE=InnoDB DEFAULT CHARSET=utf8
