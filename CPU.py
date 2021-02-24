from __future__ import print_function
from time import sleep


last_idles = []
last_totals = []
for i in range(25): 
    last_idles.append(0)
    last_totals.append(0)
#fields = []
while True:
    print("start")
    fields = []
    uti = []
    f = open('/proc/stat')
    for i in range(25):
        field = [float(column) for column in f.readline().strip().split()[1:]]
        fields.append(field)
    
    idles = []
    totals = []
    for i in range(25):
        #print(fields[i])
        idle = fields[i][3]
        total = sum(fields[i])
        idles.append(idle)
        totals.append(total)
    #print(idles)
    #print(totals)

    for i in range(25):
        idle_delta, total_delta = idles[i] - last_idles[i], totals[i] - last_totals[i]
        #print("idle_delta:", idle_delta, ", total_delta:", total_delta)
        utilisation = (total_delta - idle_delta) / total_delta
        #print('CPU utilization:', utilisation)
        uti.append(utilisation)
    last_idles, last_totals = idles, totals
    f.close()
    print("Average CPU Usage: ", uti[0])
    print(uti[1:])
    print("end")
    sleep(3)
