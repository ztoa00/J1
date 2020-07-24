import sqlite3

with sqlite3.connect('database.db') as con:
    cur = con.cursor()

    """
    query = "INSERT INTO gym(name,contact,foundation,phone,description,instagram,facebook) values('Gym 4','Ztoa','2010','+919092749520','Gym 4 is gym where you can practice boxing and whole bunch of fighting sports,\nThere is also a swimming pool, a workout section......','','')"
    print(query)
    cur.execute(query)
    con.commit()

    query = "INSERT INTO gym(name,contact,foundation,phone,description,instagram,facebook) values('Studio A','Marce','2013','+543515222209','Studio A is gym where you can practice all king of exercise and whole bunch of fighting sports,\nThere is also a swimming pool, a workout section......','https://www.instagram.com/instagram/','https://www.facebook.com/faccebook')"
    print(query)
    cur.execute(query)
    con.commit()
    """



    """
    # query = "SELECT * From gym WHERE lower(contact) LIKE lower('%Ztoa%');"
    # query = "SELECT * From gym WHERE lower({0}) LIKE lower('%{1}%');".format(search_choice, search_keyword)
    print(query)
    cur.execute(query)
    rows = cur.fetchall()
    print(rows)

    """