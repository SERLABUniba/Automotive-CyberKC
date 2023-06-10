from flask import Flask, render_template, request
from varHTML import *
from util import *
from manage_files import *

app = Flask(__name__, static_folder='static')

@app.route('/')
def index():

  return render_template(INDEX)


@app.route('/dashboard')
def dashboard():
  
  try:  
    offenses = connQradar(limit=LIMIT)
    numberThreats = connQradar(limit=500)[1]
    
    return render_template(DASHBOARD, 
                         content = tableThreats(offenses[0], orderBy="time" ), 
                         numberThreats = numberThreats, 
                         numberOfPath = getNumberOfPath(),
                         numberofAttack = getNumberOfAttack(),
                         maxRisk = getTRM(offenses[0])
                         )
  
  except:
    return render_template(THREATS, content = getHTML_radarError() )


@app.route('/threats')
def threats():

  try:
    offenses = connQradar(limit=LIMIT)
    return render_template(THREATS, content = tableThreats(offenses[0], orderBy="risk") )
  
  except:
    return render_template(THREATS, content = getHTML_radarError() )


@app.route('/threat', methods=['GET'])
def threat():

  args = request.args
  capec = f"capec-{args.get('capec')}"
  builder = args.get('builder')
  model = args.get('model')
  year = args.get('year')

  contentThreatCapec = createContentAttackPath(getHTML_contentThreatCapec(), 
                                               createAttackPaths(capec), 
                                               risk_type="RS", 
                                               builder=builder, 
                                               model=model, 
                                               year=year)
  

  header = contentHeaderThreatCapec(capec, builder, model)
  
  return render_template(THREATS, content=contentThreatCapec, header=header)
  
   
@app.route('/knowledgebase')
def knowledgebase():

  contentKB = createContentAttackPath(getHTML_contentKB(), 
                                      createAttackPaths(), 
                                      risk_type="severity")

  return render_template(KNOWLEDGEBASE,  content=contentKB)


@app.route('/search')
def search():

  return render_template(SEARCH, content=optionThreatSearch())