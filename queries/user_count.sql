SELECT
  userSex AS 'Gender',
  COUNT(*) AS 'Count'
FROM users
GROUP BY userSex
ORDER BY userSex ASC
;
