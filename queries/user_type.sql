SELECT
  CASE
    WHEN userSchoolNum LIKE 'PB%' THEN 0
    WHEN userSchoolNum LIKE 'SA%' OR userSchoolNum LIKE 'BA%' THEN 1
    ELSE 2
  END AS 'UserType',
  COUNT(*) AS 'Count'
FROM users
GROUP BY UserType
ORDER BY UserType ASC
;
