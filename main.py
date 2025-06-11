import requests
from fastapi import FastAPI, Path, Query, HTTPException, Form, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from typing import Literal, Optional
import psycopg2
import bcrypt
import jwt
import datetime
from functools import wraps
import os
from dotenv import find_dotenv, load_dotenv

load_dotenv( find_dotenv() )
DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_HOST = os.getenv('DB_HOST') #change to localhost in .env when running outside docker container
PRIVATE_KEY = os.getenv('PRIVATE_KEY')
PUBLIC_KEY = os.getenv('PUBLIC_KEY')
EXP_MIN = int(os.getenv('EXP_MIN'))
EXP_TIME = datetime.timedelta(minutes=EXP_MIN)

def with_db(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=5432)
        cur = conn.cursor()
        try:
            result = func(cur,*args, **kwargs)
            conn.commit()
            return result
        except Exception as e:
            conn.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            cur.close()
            conn.close()
    return wrapper

@with_db
def db_exists(cur, dbname: str)-> bool:
    cur.execute("""
    SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_name = %s);
    """, (dbname,))
    exists = cur.fetchall()[0][0]
    return exists

@with_db
def create_table(cur):
    cur.execute("""
    CREATE TABLE randomusers (
        name VARCHAR(40) NOT NULL,
        gender CHAR(1) NOT NULL,
        country VARCHAR(20),
        email VARCHAR(40) NOT NULL,
        username VARCHAR(20) NOT NULL PRIMARY KEY,
        pwd_hash VARCHAR(60) NOT NULL
    );
    ALTER TABLE randomusers ADD CONSTRAINT gender_constr CHECK 
    (gender = 'M' OR gender = 'F');

    INSERT INTO randomusers (name, gender, email, username, pwd_hash)
    VALUES ( %s,%s,%s,%s,%s );
    """, ('admin','M', 'admin@gmail.com', 'admin',
          bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')))

class UserSchema(BaseModel):
    name: str = Field(max_length=40)
    gender: Literal['M','F']
    country: Optional[str] = Field(default=None, max_length=20)
    email: EmailStr = Field(max_length=40)
    username: str = Field(max_length=20)
    password: str = Field(max_length=40)

app = FastAPI()
http_bearer = HTTPBearer()

@app.get('/generate_users/{num}',description='Check connection to remote API')
def generate_users(num: int = Path(ge=1)):
    url = f'https://randomuser.me/api/?results={num}'
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(status_code=502, detail='Failed to retrieve data from remote API')

@with_db
def read_users_with_db(cur,limit_by):
    cur.execute("""
    SELECT username, name, gender, country FROM randomusers LIMIT %s;
    """, (limit_by,))
    results_rows = cur.fetchall()
    results = [{'username': row[0], 'name': row[1], 'gender': row[2], 'country': row[3]} for row in results_rows]
    return {'results': results}

@app.get('/read_users', description='Read entries from database')
def read_users(limit_by:int=Query(default=10, gt=0)):
    if not db_exists('randomusers'):
        return {'results': 'Table does not exist'}
    return read_users_with_db(limit_by)

@with_db
def add_users_with_db(cur, users: list[UserSchema]):
    count = 0
    for user in users:
        pwd_hash = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cur.execute("""
        INSERT INTO randomusers (name, gender, country, email, username, pwd_hash)
        VALUES ( %s,%s,%s,%s,%s,%s );
        """, (user.name, user.gender, user.country, user.email,
              user.username, pwd_hash))
        count += 1
    return {'status': f'{count} user(s) were inserted'}

@app.post('/add_users/{num}', description='Insert random users from remote API to database')
def add_users(num: int = Path(ge=1)):
    response = generate_users(num)
    if not db_exists('randomusers'):
        create_table()
    users = []
    for user in response['results']:
        ResponseUserInfo = {
            'name': f"{user['name']['first']} {user['name']['last']}",
            'gender': user['gender'],
            'country': user['location']['country'],
            'email': user['email'],
            'username': user['login']['username'],
            'password': user['login']['password']
        }
        if ResponseUserInfo['gender'] == 'male':
            ResponseUserInfo['gender'] = 'M'
        elif ResponseUserInfo['gender'] == 'female':
            ResponseUserInfo['gender'] = 'F'
        try:
            UserInfo = UserSchema(**ResponseUserInfo)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
        users.append(UserInfo)
    return add_users_with_db(users)

@app.post('/registrate_user', description='Insert user with data from the from')
def registrate_user(name: str = Form(...), gender: str = Form(...),
                    country: Optional[str] = Form(None), email: str = Form(...),
                    username: str = Form(...), password: str = Form(...)):
    try:
        UserInfo = UserSchema(name=name,gender=gender,country=country,
             email=email,username=username,password=password)
    except Exception as e:
        return {'status': 'registration failed', 'info': str(e)}
    return add_users_with_db([UserInfo])

@with_db
def find_user_with_db(cur,username: str):
    cur.execute("""
    SELECT username, pwd_hash, name, gender, country, email FROM randomusers WHERE username = %s
    """, (username,))
    results = cur.fetchone()
    return results

@app.post('/login', description='Issue JWT token')
def login(username: str = Form(...), password: str = Form(...)):
    if not db_exists('randomusers'):
        return {'status': 'login failed', 'info': 'Table does not exist'}
    results = find_user_with_db(username)
    if results is None:
        return {'status': 'login failed', 'info': 'User not found'}
    elif not bcrypt.checkpw(password.encode('utf-8'), results[1].encode('utf-8')):
        return {'status': 'login failed', 'info': 'Wrong password'}
    else:
        payload = {'sub': username, 'exp': datetime.datetime.utcnow() + EXP_TIME}
        token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256')
        return {'status': 'success', 'token': {'access_token': token, 'token_type': 'Bearer'} }

@with_db
def delete_user_with_db(cur, username: str):
    cur.execute("""
    SELECT EXISTS( SELECT * FROM randomusers WHERE username = %s );
    """, (username,))
    user_exists = cur.fetchone()[0]
    if not user_exists:
        raise HTTPException(status_code=404, detail='No user found with given id')
    cur.execute("""
    DELETE FROM randomusers WHERE username = %s
    """, (username,))
    return {'status': 'User deleted'}

@app.delete('/delete/{username}', description='Delete user by username. To access, login as admin.')
def delete_user(username: str, creds: HTTPAuthorizationCredentials = Depends(http_bearer)):
    token = creds.credentials
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256']) # already checks expiration date
    except Exception as e:
        raise HTTPException(status_code=403, detail=str(e))
    if payload['sub'] != 'admin':
        raise HTTPException(status_code=403)
    if not db_exists('randomusers'):
        raise HTTPException(status_code=500, detail='Table does not exist')
    return delete_user_with_db(username)

@app.get('/me', description='Get info about yourself after successful login')
def get_me(creds: HTTPAuthorizationCredentials = Depends(http_bearer)):
    token = creds.credentials
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256']) # already checks expiration date
    except Exception as e:
        raise HTTPException(status_code=403, detail=str(e))
    username = payload['sub']
    info_db = find_user_with_db(username)
    info = {'username': info_db[0], 'name': info_db[2], 'gender': info_db[3],
            'country': info_db[4], 'email': info_db[5]}
    return {'info': info}