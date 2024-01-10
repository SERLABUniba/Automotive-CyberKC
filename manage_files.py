import json
import csv
import sqlite3
from costants import *

def insertAttack(attackName, timestamp, carModel, attackType, capec):
  connection = sqlite3.connect('attacks.db')
  cur = connection.cursor()
  cur.execute('INSERT INTO Attacks(AttackName, Timestamp, CarModel, AttackType, Status, CAPEC, CarBuilder, CarYear) VALUES(?, ?, ?, ?, "Open", ?, "Kia", "2021")', (attackName, timestamp, carModel, attackType, capec))
  connection.commit()
  connection.close()

def getNumberofThreats():
  connection = sqlite3.connect('attacks.db')
  cur = connection.cursor()
  cur.execute('SELECT * FROM Attacks')
  rows = cur.fetchall()
  connection.close()
  return rows

def getCategories():

  with open(MAPSETTINGS) as f:
    my_data = json.load(f)

  categories = []
  for map in my_data:
    categories.append(map['category'])

  return categories

def getCapec(category):

  with open(MAPSETTINGS) as f:
    my_data = json.load(f)

  for row in my_data:
    if category == row["category"]:
      return row["capec"]
    

def getThreat(threat):
  with open(MAPSETTINGS) as f:
    my_data = json.load(f)

  for row in my_data:
    if threat == row["capec"]:
      return row["category"]


def getCarInfomation(id):
  with open(CARSETTINGS) as f:
    my_data = json.load(f)

  for row in my_data:
    if id == row["UUID"]:
      return {"Builder": row['Builder'], "Model": row['Model'], "Year": row['Year']}


def getNumberOfPath():
  
  with open(ATTACKPATH, 'r') as read_obj:
    csv_reader = csv.reader(read_obj)
    list_of_attack_path = list(csv_reader)
  
  return (len(list_of_attack_path))


def getNumberOfAttack():
  connection = sqlite3.connect(DB)
  connection.row_factory = sqlite3.Row
  row = connection.execute( 'SELECT COUNT(*) FROM Attacks').fetchone()
  return row[0]


def getAttackPath():
  with open(ATTACKPATH, 'r', encoding="utf-8") as read_obj:
    csv_reader = csv.reader(read_obj)
    attackPaths = list(csv_reader)
  
  return attackPaths

