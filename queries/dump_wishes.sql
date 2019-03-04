SELECT
  U.userRealName AS 'Name',
  W.wishcontent AS 'Content'
FROM users AS U
INNER JOIN wishes AS W on U.userEmail = W.userEmail
ORDER BY Name ASC
;
