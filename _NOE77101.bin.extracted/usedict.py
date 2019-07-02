# from collections import Counter
# list1 = [1,2,3,4,1,2,3,2,3,1,2]
# print Counter(list1)
# # print dict(Counter(list1)).iteritems()
# print sorted(dict(Counter(list1)).iteritems(),key=lambda x:x[0],reverse=True)


# a = [1,2,3,4,5,3,4]
# a1 = set(a)
# b = [1,2,3,4,3,2,12,3]
# c = a1 & set(b)
#
# d = len(c)
# print a1
# print c
# print d

import re
str1 = "233413RRR231324"
str2 = r'^R'
reObj = re.compile(str2)
matchs = reObj.finditer(str1)
print matchs
for match in matchs:
    a = match.group()
    print a