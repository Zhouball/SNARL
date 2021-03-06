CREATE TABLE `general_objects` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `object_name` VARCHAR(32) NOT NULL,
  `object_desc` VARCHAR(128),
  `status` ENUM('OWNED','AVAILABLE') NOT NULL DEFAULT 'AVAILABLE',
  `owner` VARCHAR(32),
  `create_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `update_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY (`owner`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8
