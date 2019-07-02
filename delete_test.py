def adjust_arrow(resSet,area_length):
	# print area_length
	resList = list(resSet)
	resList.sort()
	print resList
	#the code below are do the arrow address cluster
	length=len(resList)
	# print length
	reStart=0
	reEnd=0
	start=0
	end=0
	while not end == length:
		if resList[end] - resList[start] > area_length:
			print "end",end
			print "resList1", resList[end]
			print "start",start
			print "resList2", resList[start]

			if end - start > reEnd - reStart:
				reEnd = end
				reStart = start
			start = start + 1
		else:
			end = end + 1
	return resList[reStart:reEnd]


resSet = [5,8,9,11,20,30,65,69,80]
area_length = 15
a = adjust_arrow(resSet, area_length)
print a

