SELECT
  COUNT(*) AS 'MatchCount'
FROM users AS U
INNER JOIN sayLoveU AS L
ON U.userEmail = L.fromEmail
WHERE
  EXISTS (
    SELECT *
    FROM users AS U2
    INNER JOIN sayLoveU AS L2
    ON U2.userEmail = L2.fromEmail
    WHERE
      U.userRealName = L2.toRealname
      AND
      U2.userRealName = L.toRealname
  )
;
