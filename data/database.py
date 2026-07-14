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
 
def create_feedback_table():
    con = get_connection()
    con.execute(
        """CREATE TABLE IF NOT EXISTS AnalystFeedback(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jailbreak_id INTEGER NOT NULL,
            original_tactic TEXT,
            corrected_tactic TEXT,
            original_severity TEXT,
            corrected_severity TEXT,
            analyst_notes TEXT,
            reviewed_at TEXT,
            FOREIGN KEY (jailbreak_id) REFERENCES Jailbreak(id))"""
    )
    con.commit()
    con.close()


def insert_feedback(jailbreak_id, original_tactic, corrected_tactic,
                     original_severity, corrected_severity, analyst_notes):
    con = get_connection()
    con.execute(
        """INSERT INTO AnalystFeedback
           (jailbreak_id, original_tactic, corrected_tactic,
            original_severity, corrected_severity, analyst_notes, reviewed_at)
           VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
        (jailbreak_id, original_tactic, corrected_tactic,
         original_severity, corrected_severity, analyst_notes)
    )
    con.commit()
    con.close()


def get_feedback_history(jailbreak_id):
    con = get_connection()
    cur = con.execute(
        "SELECT * FROM AnalystFeedback WHERE jailbreak_id = ? ORDER BY reviewed_at DESC",
        (jailbreak_id,)
    )
    results = cur.fetchall()
    con.close()
    return results