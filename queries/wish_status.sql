SELECT
  wishstatus AS 'WishStatus',
  COUNT(*) AS 'Count'
FROM wishes
GROUP BY wishstatus
ORDER BY wishstatus ASC
;
