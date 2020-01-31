import lorem
import random
f = open("ex3_test.txt", "w");
d = {}
for i in range(9000):
    toss_coin = random.randint(0,1)
    if toss_coin == 0:
        #set
        key = chr(random.randint(65, 122))
        f.write("set\n");
        f.write(str(key))
        f.write("\n")
        length = random.choice([100,500, 1000, 4500,5000,8000, 10000, 15000])
        value = ""
        while len(value) < length:
            value = value + " " + lorem.text()
        value = value.replace("\n", "");
        f.write(value + "\n");
        d.update({key : value})
    else:
        if len(d) > 0:
            key = list(d.keys())[random.randint(0, len(d)-1)]
            f.write("get\n")
            f.write(key + "\n")
        else:
            continue;


