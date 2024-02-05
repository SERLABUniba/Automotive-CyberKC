from flask import Flask, render_template, request, session, make_response
from varHTML import *
from util import *
from manage_files import *

from datetime import datetime

app = Flask(__name__, static_folder='static')

count = 0

def get_timestamp():

    current_time = datetime.now().time()
    
    formatted_time = current_time.strftime("%H:%M:%S")
    
    print("Current local time:", formatted_time)


@app.route('/')
def index():

  return render_template(INDEX)

# @app.route('/debug')
# def debug():
    
#     data = {
#         'sid': 'scheduler__guido__search__RMD5657edf9e349a2147_at_1707128400_5',
#         'search_name': 'SpoofingGear: detected value out of the range',
#         'app': 'search',
#         'owner': 'guido',
#         'results_link': 'http://Air-di-Guido.homenet.telecomitalia.it:8000/app/search/@go?sid=scheduler__guido__search__RMD5657edf9e349a2147_at_1707128400_5',
#         'result': {
#             'CAN_ID': '043f',
#             'DATA_0': '00',
#             'DATA_1': '00',
#             'DATA_2': '00',
#             'DATA_3': '00',
#             'DATA_4': '00',
#             'DATA_5': '00',
#             'DATA_6': '00',
#             'DATA_7': '00',
#             'DLC': '8',
#             'LABEL': 'T',
#             'TIMESTAMP': '1478200651.438389',
#             '_bkt': 'hcrl-car-hacking-dos-index~4~12741995-8D9B-47B2-8A24-24F0BBEC7F94',
#             '_cd': '4:10702711',
#             '_eventtype_color': '',
#             '_indextime': '1706975996',
#             '_raw': '1478200651.438389,0000,8,00,00,00,00,00,00,00,00,T',
#             '_serial': '990094',
#             '_si': ['Air-di-Guido.homenet.telecomitalia.it', 'hcrl-car-hacking-dos-index'],
#             '_sourcetype': 'csv',
#             '_time': '1706975704',
#             'eventtype': '',
#             'host': 'Vehicle1',
#             'index': 'hcrl-car-hacking-gear-index',
#             'isDoS': 'Yes',
#             'linecount': '1',
#             'punct': '.,,,,,,,,,,,',
#             'source': 'gear_datasetpadding.csv',
#             'sourcetype': 'csv',
#             'splunk_server': 'Air-di-Guido.homenet.telecomitalia.it',
#             'splunk_server_group': '',
#             'timestamp': 'none'
#         }
#     }

    
#     attackName, timestamp = parseSplunkRequest(data)
#     attackType, capec = defineAttackType(attackName)
    
#     carModel = "Sportage"
    
#     insertAttack(attackName, timestamp, carModel, attackType, capec)

@app.route('/webhook', methods=['POST'])
def webhook():
    if request.method == "POST":
        
        data = request.json
        
        print('################### RECEIVED DATA ###################')
        
        print(data)
        
        print(f'type(data) = {type(data)}')
        
        print('################### RECEIVED DATA ###################')
        
        attackName, timestamp = parseSplunkRequest(data)
        attackType, capec = defineAttackType(attackName)
        
        get_timestamp()
        
        carModel = "Sportage"
        
        insertAttack(attackName, timestamp, carModel, attackType, capec)
        
        return "Webhook received"

@app.route('/checkUpdate')
def checkDatabaseUpdate():
    threats = getNumberofThreats()
    numberofThreats = len(threats)
    return "", str(numberofThreats)

@app.route('/splunkDashboard', methods=["GET", "POST"])
def splunkDashboard():
    threats = getNumberofThreats()
    numberofThreats = len(threats)
    return render_template(DASHBOARD, content=generateThreatsTable(threats, orderBy="time"), numberThreats=numberofThreats, numberOfPath=getNumberOfPath(), numberofAttack=getNumberOfAttack(), maxRisk=getSplunkTRM(threats))

@app.route('/splunkThreats')
def splunkThreats():
    threats = getNumberofThreats()
    return render_template(THREATS, content=generateThreatsTable(threats, orderBy="time"))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    try:
        offenses = connQradar(limit=LIMIT)
        numberThreats = connQradar(limit=500)[1]
    
        return render_template(DASHBOARD, 
                         content = tableThreats(offenses[0], orderBy="time"), 
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

@app.route('/attackImpact', methods=['GET'])
def attackImpact():
    args = request.args
    capec = f"capec-{args.get('capec')}"
    builder = args.get('builder')
    model = args.get('model')
    year = args.get('year')
    attackName = args.get('attackName')
    contentImpact = generateAttackImpact(getHTML_contentAttackImpact(),
                                               createAttackPaths(capec),
                                               risk_type="RS",
                                               builder=builder,
                                               model=model,
                                               year=year)

    header = generateAttackImpactHeader(attackName, builder, model, year)
    return render_template(ATTACKIMPACT, content=contentImpact, header=header)
  
   
@app.route('/knowledgebase')
def knowledgebase():

  contentKB = createContentAttackPath(getHTML_contentKB(), 
                                      createAttackPaths(), 
                                      risk_type="severity")

  return render_template(KNOWLEDGEBASE,  content=contentKB)


@app.route('/search')
def search():

  return render_template(SEARCH, content=optionThreatSearch())