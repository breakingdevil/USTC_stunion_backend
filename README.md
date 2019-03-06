# USTC Student Union backend [![Build Status](https://travis-ci.com/breakingdevil/USTC_stunion_backend.svg?token=9jooK4Qfof8h4FFgpnEK&branch=master)](https://travis-ci.com/breakingdevil/USTC_stunion_backend)

https://blog.csdn.net/lxfHaHaHa/article/details/78490249

修改数据库字符集：

    ALTER DATABASE db_name DEFAULT CHARACTER SET character_name [COLLATE ...];
    
把表默认的字符集和所有字符列（CHAR, VARCHAR, TEXT）改为新的字符集：

    ALTER TABLE tbl_name CONVERT TO CHARACTER SET character_name [COLLATE ...]如：ALTER TABLE logtest CONVERT TO CHARACTER SET utf8 COLLATE utf8_general_ci;

导出表结构

    mysqldump --opt -d 数据库名 -u root -p > export.sql

修改字符集为 UTF-8

重新创建数据库 
