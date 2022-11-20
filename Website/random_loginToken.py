import pymysql, string, random, time

db = pymysql.connect(
        host="localhost",
        user="root",
        db="mfadb",
    )

mycursor = db.cursor()

while(True):
    mycursor.execute("select id from user")
    total = mycursor.fetchall()

    for id in total:
        token = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(10))
        mycursor.execute("update user set loginToken='" + token + "' where id=" + str(id[0]))

    db.commit()
    time.sleep(30)

db.close()
