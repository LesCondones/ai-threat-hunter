import os
import sqlite3
from dotenv import load_dotenv

load_dotenv()

DATABASE = os.getenv("DATABASE")
def get_connection():
    con = sqlite3.connect(DATABASE)
    return con 

def create_table():
    con = get_connection()
    cur = con.cursor()
    
    cur = con.execute(
        """CREATE TABLE IF NOT EXISTS Jailbreak(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            PROMPT TEXT UNIQUE,
            score REAL,
            model TEXT)"""
        
    )
    con.commit()
    con.close()

def insert_record(name, prompt, score, model):
    con = get_connection()
    cur = con.cursor()
    
    cur = con.execute("""
                      INSERT OR IGNORE INTO Jailbreak (name, prompt, score, model)
                      VALUES (?, ?, ?, ?)""", (name, prompt, score, model))
    con.commit()
    con.close()
    
    
def get_high_priority(threshold=80):
     con = get_connection()
     cur = con.cursor()
     
     cur = con.execute("""SELECT * FROM Jailbreak WHERE score >= ?""",(threshold,))
     results = cur.fetchall()
     
     con.close()
     return results