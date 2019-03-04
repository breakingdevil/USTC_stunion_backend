SELECT
  userEmail AS 'Email',
  userSchoolNum AS 'School ID',
  userRealName AS 'Name'
FROM users
WHERE
  (
    SELECT CONCAT(';', cashid, ';')
    FROM selectwishes
    WHERE userSchoolNum = 'PB17111643'
  ) LIKE CONCAT('%;', userEmail, ';%')
;
