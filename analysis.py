#!/usr/bin/env python3
# -*- coding=utf8 -*-

import sys
import os

###############################################################################
#  女生节mysql文件分析脚本,将此脚本放入含有mysql文件的文件夹下即可自动分析
#  author : breakingdevil
#  time : 2019年3月2日10:17:04
###############################################################################

for file in os.listdir("."):
	total_user_number = 0
	total_user_number = 0
	total_girl_number = 0
	total_boy_number = 0
	total_undergraduate_number = 0
	total_other_number = 0
	if not file.endswith("sql"):
		continue
	sqlhandler = open( file ,"r")
	sqldata = sqlhandler.read()
	###############################################################################
	# user 表分析
	###############################################################################
	start_pos = sqldata.index("\n/*!40000 ALTER TABLE `users` DISABLE KEYS */;\nINSERT INTO `users` VALUES ") + 75
	end_pos = sqldata.index(";\n/*!40000 ALTER TABLE `users` ENABLE KEYS */;") - 1
	user_data = sqldata[start_pos:end_pos]
	user_data_list = user_data.split("),(")
	total_user_number = len(user_data_list)
	print("********************************************")
	print("时间24小时制:",file[8:-4] , "注册总人数:" ,total_user_number )
	for person_data in user_data_list:
		person_data_list = person_data.split(",")
		userStatus = 3
		userSchoolNum = 6
		userSex = 8
		if person_data_list[userSex] == "NULL" or person_data_list[userSex] == "1":
			total_boy_number += 1
		else:
			total_girl_number += 1
		if person_data_list[userSchoolNum] == "NULL" or person_data_list[userSchoolNum][1:-1].startswith("PB"):
			total_undergraduate_number += 1
		else:
			total_other_number += 1
	print("注册男生人数:", total_boy_number)
	print("注册女生人数:", total_girl_number)
	print("注册本科生人数:", total_undergraduate_number)
	print("注册研究生及博士生人数:", total_other_number)
	#########################################################################
	# wish 表分析
	#########################################################################
	try:
		start_pos = sqldata.index("/*!40000 ALTER TABLE `wishes` DISABLE KEYS */;\nINSERT INTO `wishes` VALUES ") + 76
		end_pos = sqldata.index(";\n/*!40000 ALTER TABLE `wishes` ENABLE KEYS */;") - 1
	except ValueError:
		continue
	wish_data = sqldata[start_pos:end_pos]
	wish_data_list = wish_data.split("),(")
	print("下面是愿望分析数据:")
	print("总共收到", len(wish_data_list), "个愿望")
	unselect_wish_number = 0
	selected_wish_number = 0
	achieved_wish_number = 0
	wish_status = 4
	for wish in wish_data_list:
		wish_list = wish.split(",")
		if wish_list[wish_status] == "0":
			unselect_wish_number += 1
		if wish_list[wish_status] == "1":
			selected_wish_number += 1
		if wish_list[wish_status] == "2":
			achieved_wish_number += 1
	print("未被人选择的愿望数量:", unselect_wish_number)
	print("已被人选中正在完成中的愿望", selected_wish_number)
	print("已完成的愿望", achieved_wish_number)
	####################################################
	# sayloveU 数据分析
	####################################################
	try:
		start_pos = sqldata.index("/*!40000 ALTER TABLE `sayLoveU` DISABLE KEYS */;\nINSERT INTO `sayLoveU` VALUES (") + 80
		end_pos = sqldata.index(";\n/*!40000 ALTER TABLE `sayLoveU` ENABLE KEYS */;") - 1
	except ValueError:
		continue
	sayLoveU_data = sqldata[start_pos:end_pos]
	sayLoveU_data_list = sayLoveU_data.split("),(")
	print("总计收到", len(sayLoveU_data_list), "个表白")
print("自动分析完成")
