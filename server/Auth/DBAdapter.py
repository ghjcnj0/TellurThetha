import psycopg2
class Adapter():

    def __init__(self, host, port, sslmode, dbname, schema, user, password, target_session_attrs):
        self.host=host
        self.port=port
        self.sslmode=sslmode
        self.dbname=dbname
        self.user=user
        self.password=password
        self.target_session_attrs=target_session_attrs
        self.schema = schema
        self.connect()
    def __del__(self):
        self.conn.close() 
    def connect(self):
        try:
            self.conn = psycopg2.connect(f"""
                host={self.host}
                port={self.port}
                dbname={self.dbname}
                user={self.user}
                password={self.password}
                target_session_attrs={self.target_session_attrs}
            """)
        except Exception as error:
            print(f'connection error: {error}')
            exit(0)
        finally:
            self.cursor = self.conn.cursor()
            return self.conn
        
    def select_sth_by_condition(self, sth, table, condition):
        request = f"""SELECT {sth} FROM "{self.schema}"."{table}" WHERE {condition}"""
        self.cursor.execute(request)
        data = self.cursor.fetchall()
        return data

    def select_sth(self, sth, table):
        request = f"""SELECT {sth} FROM "{self.schema}"."{table}" """
        self.cursor.execute(request)
        data = self.cursor.fetchall()
        return data
    
    def update(self, table, request, id):
        request_update = f'UPDATE "{self.schema}"."{table}" SET {request} WHERE id={id}'
        cursor = self.conn.cursor()
        cursor.execute(request_update)
        self.conn.commit()

    def insert(self, table, columns, values):
        request_insert = f"""INSERT INTO "{self.schema}"."{table}" ({columns}) VALUES ({values})"""
        self.cursor.execute(request_insert)
        self.conn.commit()
    
    def delete_by_id(self,table,id):
        request_delete = f"""DELETE FROM "{self.schema}"."{table}" WHERE id = {id}"""
        self.cursor.execute(request_delete)
        self.conn.commit()

    def sel_userdata_by_username(self,username):
        request = f"""SELECT * FROM "{self.schema}"."users" WHERE username = '{username}' """
        self.cursor.execute(request)
        data = self.cursor.fetchall()
        if data!=[]:
            data = str(data).split(', ')
            data = {'id': data[0][2:], 'username':data[1][1:-1], 'password':data[2][1:-3]}
        return(data)
    def insert_userdata_inDB(self,username,hashed_password):
        request_insert = f"""INSERT INTO "{self.schema}"."users" (username, password) VALUES ( '{username}','{str(hashed_password)}' )"""
        self.cursor.execute(request_insert)
        self.conn.commit()