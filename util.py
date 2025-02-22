import requests
import json
import datetime
from cvss import CVSS3
from cvss.constants3 import *
from manage_files import *
import os

# Attack path section

def createContentAttackPath(content, list_of_csv, risk_type, builder=str(), model=str(), year=str()):

  connection = sqlite3.connect(DB)
  connection.row_factory = sqlite3.Row

  i = 1
  for l in list_of_csv:
    cards = ""
    j = 1
    vectorCvss = []
    maxWeight = 0
    while j < (len(l)):
      rows = connection.execute( 'SELECT * FROM Attacks WHERE ID = "' + l[j] + '"').fetchall()
      for row in rows:
        cards = cards + createCardAttack(row)

        start = row['Exploitability'].find("CVSS:3.0")
        end = row['Exploitability'].find(";")
        cvss = row['Exploitability'][ start : end ]
        vectorCvss.append(cvss)

        if risk_type == "RS":
          weight = weightRiskScore(row['Vehicle'], builder, model, year )
          if maxWeight < weight: maxWeight = weight
        
      
      j = j+1

    if risk_type == "RS":
      risk = calculateRS(vectorCvss, maxWeight)
    elif risk_type == "severity":
      risk = calculateSeverity(vectorCvss)

    content = content + createRowPaths(str(i), cards, row, risk, risk_type)
    i = i+1

  content = content + "</tbody></table></div>"
  connection.close()
  return content


def createRowPaths(number, cards, row, risk, risk_type):

  if risk_type == "severity":
    if risk <= 33:
      colorRisk = "99cbff"
    elif risk <= 67:
      colorRisk = "yellow"
    else:
      colorRisk = "red"

  elif risk_type == "RS":
    if risk <= 330:
      colorRisk = "99cbff"
    elif risk <= 670:
      colorRisk = "yellow"
    else:
      colorRisk = "red"

  content = '''
   <tr scope="row">
              <th scope="row">
                <label class="control control--checkbox">
                  <input type="checkbox" />
                  <div class="control__indicator"></div>
                </label>
              </th>
              <td class="text-center">
                ''' + number + '''
              </td>
              <td> ''' + row['Consequence'] + ''' </td>
              <td class="text-center"> 
                ''' + str(risk) + '''
              </td>
              <td class="text-center">
                <i class="bi bi-circle-fill bs-light" style="color:''' + colorRisk + ''';"></i>
              </td>
              <td>
                <div class="container text-center">
                  <button type="button" class="btn btn-outline-info" data-bs-toggle="modal" data-bs-target="#GFG''' + number + '''">
                    More details
                  </button>
                  <div class="modal fade" id="GFG''' + number + '''">
                    <div class="modal-dialog  modal-lg modal-dialog-scrollable ">
                      <div class="modal-content">
                        <div class="modal-header" style="background-color: #1e1e1e;">
                          <h5 class="modal-title" id="GFGLabel">
                            Attack path: ''' + number + '''
                          </h5>
                          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close">
                          </button>
                        </div>
                          <div class="modal-body" style="background-color: #1e1e1e;">
                            ''' + cards + '''
                          </div>
                      </div>
                    </div>
                  </div>
                </div>


              </td>
            </tr>
   
   
   '''
  return content


def createCardAttack(row):
    content = '''

    <div class="card border-light mb-3" style="max-width: 100rem;">
  <div class="card-body" style="background-color: #1e1e1e;">
    <h5 class="card-title">ID: ''' + row['ID'] + '''</h5>

    <p class="card-text">

      <table class="table table-borderless table-sm" style="color: white;">
  <tbody>

    <tr class="righe-nascoste" style="display:none;">
      <td>Year</td>
      <td>''' + row['Year'] + '''</td>
    </tr>
    <tr>
      <td>Description</td>
      <td>''' + row['Description'] + '''</td>
    </tr>
    <tr>
      <td>Reference</td>
      <td>''' + row['Reference'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Attack Class</td>
      <td>''' + row['Attack Class'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Attack Base</td>
      <td>''' + row['Attack Base'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Attack Type</td>
      <td>''' + row['Attack Type'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Violated Security Property</td>
      <td>''' + row['Violated Security Property'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Affected Asset</td>
      <td>''' + row['Affected Asset'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Vulnerability</td>
      <td>''' + row['Vulnerability'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Interface</td>
      <td>''' + row['Interface'] + '''</td>
    </tr>
    <tr>
      <td>Consequence</td>
      <td>''' + row['Consequence'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Attack Path</td>
      <td>''' + row['Attack Path'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Requirements</td>
      <td>''' + row['Requirements'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Restrictions</td>
      <td>''' + row['Restrictions'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Attack Level</td>
      <td>''' + row['Attack Level'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Acquired Privileges</td>
      <td>''' + row['Acquired Privileges'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Vehicle</td>
      <td>''' + row['Vehicle'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Component</td>
      <td>''' + row['Component'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Tool</td>
      <td>''' + row['Tool'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Attack Motivation</td>
      <td>''' + row['Attack Motivation'] + '''</td>
    </tr>
    <tr class="righe-nascoste" style="display:none;">
      <td>Vulnerability Database</td>
      <td>''' + row['Vulnerability Database'] + '''</td>
    </tr>
    <tr>
      <td>Exploitability</td>
      <td>''' + row['Exploitability'] + '''</td>
    </tr>


  </tbody>
 </table>
 <button class="btn btn-secondary btn-sm" onclick="mostraRighe(this)">Mostra altre righe</button>

    </p>
  </div>
</div>
    '''
    return content


def createAttackPaths(capec=None):

  allAttackPath = getAttackPath()

  if capec != None:
    connection = sqlite3.connect(DB)
    connection.row_factory = sqlite3.Row
    rows = connection.execute('SELECT * FROM Attacks WHERE "Attack Class" LIKE "%' + str(capec) + '%"').fetchall()
    connection.close()

    listAttack = []
    for row in rows:
      listAttack.append(row['ID'])

    attackPaths = []
    for attack in listAttack:
      for l in allAttackPath:
        if (attack in l) and (l not in attackPaths):
          attackPaths.append(l)
  
    return attackPaths
  
  else:
    return allAttackPath


def getRSM(capec=None, builder=str(), model=str(), year=str()):
  
  attackPaths = createAttackPaths(capec)
  
  connection = sqlite3.connect(DB)
  connection.row_factory = sqlite3.Row
  
  maxRisk = 0
  i = 1
  for l in attackPaths:
    j = 1
    vectorCvss = []
    maxWeight = 0
    while j < (len(l)):
      rows = connection.execute( 'SELECT * FROM Attacks WHERE ID = "' + l[j] + '"').fetchall()
      for row in rows:

        start = row['Exploitability'].find("CVSS:3.0")
        end = row['Exploitability'].find(";")
        cvss = row['Exploitability'][ start : end ]
        vectorCvss.append(cvss)

        weight = weightRiskScore(row['Vehicle'], builder, model, year )
        if maxWeight < weight: maxWeight = weight
      
      j = j+1

    risk = calculateRS(vectorCvss, maxWeight)
    if risk > maxRisk:
      maxRisk = risk

    i = i+1

  connection.close()

  return maxRisk


def getTRM(offenses):

  maxRisk=0
  for offense in offenses:
   
    uuid = offense['offense_source']
    categories = offense['categories'][0]
    capec = getCapec(categories)
    infoCar = getCarInfomation(uuid)
    builder = infoCar['Builder']
    model = infoCar['Model']
    year = infoCar['Year']
  
    risk = getRSM(capec, builder, model, year)
    if risk > maxRisk: maxRisk = risk

  return maxRisk


def contentHeaderThreatCapec(capec, builder, model):
  threatName = str(getThreat( int(capec[capec.index('-')+1:]) ))
  
  if (builder != "") and (model != ""):
    return f'<h2 style="color: white; padding-top: 1%">Threat: {threatName} on {builder} {model} </h2>'
  elif (builder != ""):
    return f'<h2 style="color: white; padding-top: 1%">Threat: {threatName} on {builder} </h2>'
  elif (model != ""):
    return f'<h2 style="color: white; padding-top: 1%">Threat: {threatName} on {model} </h2>'
  else:
    return f'<h2 style="color: white; padding-top: 1%">Threat: {threatName}</h2>'




# Threats section

def tableThreats(offenses, orderBy):

   rows = ""
   for offense in offenses:
      rows = rows + rowTableThreats(offense)

   content = '''

   <table id="table-threats" data-sort-name="''' + orderBy +'''" data-sort-order="desc" class="table table-hover table-dark">
  <thead>
    <tr>
      <th scope="col">ID</th>
      <th scope="col">Description</th>
      <th scope="col">Car</th>
      <th scope="col">Category</th>
      <th data-field="time" scope="col">Last updated time</th>
      <th data-field="risk" scope="col">RS<sub>M</sub></th>
      <th scope="col">Status</th>
    </tr>
  </thead>
  <tbody>
  ''' + rows + '''

  </tbody>
</table>

   '''
   return content


def rowTableThreats(offense):
   
  converted_time  = datetime.datetime.fromtimestamp(offense['last_updated_time'] / 1000.0)
  formatted_time  = converted_time .strftime("%Y-%m-%d %H:%M:%S")

  uuid = offense['offense_source']
  categories = offense['categories'][0]
  capec = getCapec(categories)
  infoCar = getCarInfomation(uuid)
  builder = infoCar['Builder']
  model = infoCar['Model']
  year = infoCar['Year']
  
  content = f'''
        <tr>
          <td>{offense['id']}</td>
          <td><a href="threat?capec={capec}&builder={builder}&model={model}&year={year}"
            class="color-white link-hover" style="font-weight:500;">{offense['description']}</a></td>
          <td>{ ' '.join(infoCar.values()) }</td>
          <td>{categories}</td>
          <td>{formatted_time}</td>
          <td>{getRSM(capec, builder, model, year)}</td>
          <td>{offense['status']}</td>
        </tr>
  '''

  return content
   


def connQradar(limit):

  SEC_TOKEN = json.load(open(os.path.join(os.path.abspath(os.getcwd()), 'configuration.json'), 'r'))['SEC_TOKEN']
  URL = f"https://{DOMAIN}:{PORT}/api/siem/offenses?filter=status%20%3D%20%22OPEN%22"

  header = {
    'SEC': SEC_TOKEN,
    'Content-Type': 'application/json',
    'accept': 'application/json',
    'Range': 'items=0-' + str(limit-1)
  }

  r = requests.get(URL, headers=header, verify=False, timeout=10)
  json_data = json.loads(r.content)

  content = []
  for offense in json_data:
    content.append(offense)

  return content, len(json_data)


# Search section

def optionThreatSearch():
  content = ""
  categories = getCategories()
  i = 1
  for category in categories:
    content = f'{content} <option value="{getCapec(category)}">{category}</option>'
    i += 1
  
  return content



def calculateSeverity(vectorCvss):

  if len(vectorCvss) == 1:
    c = CVSS3(vectorCvss[0])
    return int ( (c.base_score) * 10 ) 
  
  else:
    newCvss = "CVSS:3.0"
    for metric in METRICS_MANDATORY:
      newCvss = newCvss + "/" + metric + ":" + getDescription(metric, getMaxValue(vectorCvss, metric))
    
    c = CVSS3(newCvss)
    return int ( (c.base_score) * 10 )


def calculateRS(vectorCvss, weight):
  return int(10 * weight * calculateSeverity(vectorCvss))


def weightRiskScore(vehicleName, builder, model, year):

  if builder in vehicleName and model in vehicleName and year in vehicleName:
    return 1
  elif builder in vehicleName and model in vehicleName:
    return 0.95
  elif builder in vehicleName:
    return 0.90
  else:
    return 0.80
    

def getMaxValue(vectorCvss, metric):
  if metric == 'S':
    return None
  
  else:
    c = CVSS3(vectorCvss[0])
    max = c.get_value(metric)
    for c in vectorCvss:
      c = CVSS3(c)
      if max < c.get_value(metric):
        max = c.get_value(metric)
  
    return max


def getDescription(metric, value):

  if metric == 'S':
    return 'U'

  for key, val in METRICS_VALUES[metric].items():
    if val == value: return key
  return "None"



   