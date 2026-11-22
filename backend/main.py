import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone, date
from decimal import Decimal
from typing import Literal
import jwt
import psycopg
from psycopg.rows import dict_row
from psycopg.errors import UniqueViolation, ForeignKeyViolation
from pwdlib import PasswordHash
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

DB = os.environ['DATABASE_URL']
SECRET = os.environ['JWT_SECRET']
passwords = PasswordHash.recommended()
bearer = HTTPBearer(auto_error=False)

def connect():
    return psycopg.connect(DB, row_factory=dict_row)

@asynccontextmanager
async def lifespan(app):
    with connect() as db:
        db.execute("UPDATE users SET password_hash=%s WHERE password_hash='CHANGE_ME_HASH'", (passwords.hash(os.environ['INITIAL_PASSWORD']),))
    yield

app = FastAPI(title='Пшеница и огонь API', lifespan=lifespan, docs_url='/api/docs', openapi_url='/api/openapi.json')

class Login(BaseModel):
    login: str
    password: str
class Item(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    category_id: int
    price: Decimal = Field(ge=0, max_digits=10, decimal_places=2)
    is_active: bool = True
class Category(BaseModel):
    name: str = Field(min_length=1, max_length=100)
class Employee(BaseModel):
    full_name: str = Field(min_length=1, max_length=100)
    login: str = Field(min_length=1, max_length=50)
    role_id: int
    password: str | None = Field(default=None, min_length=8, max_length=128)
    is_active: bool = True
class Line(BaseModel):
    menu_item_id: int
    quantity: int = Field(ge=1, le=1000)
class NewOrder(BaseModel):
    items: list[Line] = Field(min_length=1, max_length=100)
class Status(BaseModel):
    status: Literal['Готовится', 'Выдан']

def current(auth: HTTPAuthorizationCredentials | None = Depends(bearer)):
    try:
        if not auth or auth.scheme.lower() != 'bearer': raise ValueError()
        payload = jwt.decode(auth.credentials, SECRET, algorithms=['HS256'], options={'require': ['sub', 'exp']})
        with connect() as db:
            user = db.execute('SELECT u.id,u.login,u.full_name,u.is_active,r.code AS role FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=%s', (int(payload['sub']),)).fetchone()
        if not user or not user['is_active']: raise ValueError()
        return user
    except (jwt.PyJWTError, ValueError, KeyError):
        raise HTTPException(401, 'Требуется авторизация')

def allow(*roles):
    def dependency(user=Depends(current)):
        if user['role'] not in roles: raise HTTPException(403, 'Недостаточно прав')
        return user
    return dependency

@app.post('/api/login')
def login(body: Login):
    with connect() as db:
        user = db.execute('SELECT u.*,r.code AS role FROM users u JOIN roles r ON r.id=u.role_id WHERE u.login=%s', (body.login,)).fetchone()
    try: valid = bool(user and user['is_active'] and passwords.verify(body.password, user['password_hash']))
    except (ValueError, TypeError): valid = False
    if not valid: raise HTTPException(401, 'Неверный логин или пароль')
    token = jwt.encode({'sub': str(user['id']), 'exp': datetime.now(timezone.utc)+timedelta(hours=8)}, SECRET, algorithm='HS256')
    return {'token': token, 'user': {k:user[k] for k in ('id','login','full_name','role')}}

@app.get('/api/me')
def me(user=Depends(current)): return user
@app.get('/api/categories')
def categories(user=Depends(current)):
    with connect() as db: return db.execute('SELECT * FROM categories ORDER BY id').fetchall()
@app.post('/api/categories')
def add_category(body: Category, user=Depends(allow('Администратор'))):
    try:
        with connect() as db: return db.execute('INSERT INTO categories(name) VALUES (%s) RETURNING *', (body.name.strip(),)).fetchone()
    except UniqueViolation: raise HTTPException(409, 'Категория уже существует')
@app.get('/api/menu')
def menu(user=Depends(current)):
    with connect() as db:
        return db.execute('SELECT m.*,c.name AS category FROM menu_items m JOIN categories c ON c.id=m.category_id WHERE (%s OR m.is_active) ORDER BY m.id', (user['role']=='Администратор',)).fetchall()
@app.post('/api/menu')
def add_item(body: Item, user=Depends(allow('Администратор'))): return save_item(body, None)
@app.put('/api/menu/{item_id}')
def update_item(item_id: int, body: Item, user=Depends(allow('Администратор'))): return save_item(body, item_id)
def save_item(body, item_id):
    try:
        with connect() as db:
            values=(body.name.strip(),body.category_id,body.price,body.is_active)
            if item_id is None: row=db.execute('INSERT INTO menu_items(name,category_id,price,is_active) VALUES (%s,%s,%s,%s) RETURNING *', values).fetchone()
            else: row=db.execute('UPDATE menu_items SET name=%s,category_id=%s,price=%s,is_active=%s WHERE id=%s RETURNING *', (*values,item_id)).fetchone()
            if not row: raise HTTPException(404, 'Позиция не найдена')
            return row
    except (UniqueViolation, ForeignKeyViolation): raise HTTPException(409, 'Проверьте название и категорию')
@app.get('/api/employees')
def employees(user=Depends(allow('Администратор'))):
    with connect() as db: return db.execute('SELECT u.id,u.full_name,u.login,u.role_id,u.is_active,r.code AS role FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.id').fetchall()
@app.get('/api/roles')
def roles(user=Depends(allow('Администратор'))):
    with connect() as db: return db.execute('SELECT * FROM roles ORDER BY id').fetchall()
@app.post('/api/employees')
def add_employee(body: Employee, user=Depends(allow('Администратор'))): return save_employee(body,None,user)
@app.put('/api/employees/{employee_id}')
def update_employee(employee_id: int, body: Employee, user=Depends(allow('Администратор'))): return save_employee(body,employee_id,user)
def save_employee(body, employee_id, user):
    if employee_id is None and not body.password: raise HTTPException(422, 'Укажите пароль')
    if employee_id == user['id'] and (not body.is_active or body.role_id != 3): raise HTTPException(400, 'Нельзя отключить свою учётную запись или изменить свою роль')
    try:
        with connect() as db:
            if employee_id is None:
                row=db.execute('INSERT INTO users(full_name,login,role_id,is_active,password_hash) VALUES (%s,%s,%s,%s,%s) RETURNING id', (body.full_name,body.login,body.role_id,body.is_active,passwords.hash(body.password))).fetchone()
            else:
                row=db.execute('UPDATE users SET full_name=%s,login=%s,role_id=%s,is_active=%s WHERE id=%s RETURNING id', (body.full_name,body.login,body.role_id,body.is_active,employee_id)).fetchone()
                if row and body.password: db.execute('UPDATE users SET password_hash=%s WHERE id=%s',(passwords.hash(body.password),employee_id))
            if not row: raise HTTPException(404, 'Сотрудник не найден')
            return row
    except (UniqueViolation, ForeignKeyViolation): raise HTTPException(409, 'Логин занят или роль не найдена')
@app.post('/api/orders')
def create_order(body: NewOrder, user=Depends(allow('Кассир'))):
    quantities={}
    for line in body.items: quantities[line.menu_item_id]=quantities.get(line.menu_item_id,0)+line.quantity
    with connect() as db:
        items=db.execute('SELECT id,name,price FROM menu_items WHERE id=ANY(%s) AND is_active FOR SHARE', (list(quantities),)).fetchall()
        if len(items)!=len(quantities): raise HTTPException(400,'Некоторые позиции недоступны')
        order=db.execute("INSERT INTO orders(cashier_id,status_id) VALUES (%s,(SELECT id FROM order_statuses WHERE code='Принят')) RETURNING id,created_at", (user['id'],)).fetchone()
        for item in items: db.execute('INSERT INTO order_items(order_id,menu_item_id,quantity,unit_price) VALUES (%s,%s,%s,%s)', (order['id'],item['id'],quantities[item['id']],item['price']))
        order['items']=[{'name':i['name'],'quantity':quantities[i['id']],'unit_price':i['price']} for i in items]
        order['total']=sum(i['price']*quantities[i['id']] for i in items)
        return order
@app.get('/api/orders')
def orders(user=Depends(allow('Повар'))):
    with connect() as db:
        rows=db.execute("SELECT o.id,o.created_at,s.code AS status FROM orders o JOIN order_statuses s ON s.id=o.status_id WHERE s.code IN ('Принят','Готовится') ORDER BY o.created_at").fetchall()
        for row in rows: row['items']=db.execute('SELECT m.name,oi.quantity FROM order_items oi JOIN menu_items m ON m.id=oi.menu_item_id WHERE oi.order_id=%s ORDER BY oi.id',(row['id'],)).fetchall()
        delivered=db.execute("SELECT count(*) AS n FROM orders o JOIN order_statuses s ON s.id=o.status_id WHERE s.code='Выдан' AND o.updated_at::date=CURRENT_DATE").fetchone()['n']
        return {'orders':rows,'delivered':delivered}
@app.patch('/api/orders/{order_id}')
def order_status(order_id:int, body:Status, user=Depends(allow('Повар'))):
    previous='Принят' if body.status=='Готовится' else 'Готовится'
    with connect() as db:
        row=db.execute('UPDATE orders SET status_id=(SELECT id FROM order_statuses WHERE code=%s),updated_at=now() WHERE id=%s AND status_id=(SELECT id FROM order_statuses WHERE code=%s) RETURNING id',(body.status,order_id,previous)).fetchone()
        if not row: raise HTTPException(409,'Статус заказа уже изменился')
        return row
@app.get('/api/report')
def report(day:date, user=Depends(allow('Администратор'))):
    with connect() as db:
        summary=db.execute('SELECT orders_count,revenue FROM v_daily_sales WHERE sale_date=%s',(day,)).fetchone() or {'orders_count':0,'revenue':0}
        items=db.execute('SELECT item_name,qty_sold,revenue FROM v_daily_item_sales WHERE sale_date=%s ORDER BY revenue DESC,item_name',(day,)).fetchall()
        return {'summary':summary,'items':items}
