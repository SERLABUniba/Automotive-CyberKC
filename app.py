from flask import Flask, abort, redirect, render_template, request, jsonify, url_for
from varHTML import (
    getHTML_contentAttackImpact,
    getHTML_contentKB,
    getHTML_contentThreatCapec,
    getHTML_radarError,
)
from util import (
    createContentAttackPath,
    generateThreatsTable,
    connQradar,
    defineAttackType,
    parseSplunkRequest,
    getSplunkTRM,
    getTRM,
    createAttackPaths,
    contentHeaderThreatCapec,
    generateAttackImpact,
    generateAttackImpactHeader,
    optionThreatSearch,
    tableThreats,
    get_similarity_score,
    get_top_three,
    # get_top_three_request,
)
from manage_files import (
    getNumberOfAttack,
    insertAttack,
    getNumberOfPath,
    getNumberofThreats,
)

from datetime import datetime

from costants import (
    INDEX,
    DASHBOARD,
    THREATS,
    LIMIT,
    ATTACKIMPACT,
    KNOWLEDGEBASE,
    SEARCH,
)

# import ast

app = Flask(__name__, static_folder="static")

count = 0


def get_timestamp():
    current_time = datetime.now().time()

    formatted_time = current_time.strftime("%H:%M:%S")

    print("Current local time:", formatted_time)


@app.route("/")
def index():
    return render_template(INDEX)


@app.route("/webhook", methods=["POST"])
def webhook():
    if request.method == "POST":
        data = request.json

        print("################### RECEIVED DATA ###################")

        print(data)

        print(f"type(data) = {type(data)}")

        print("################### RECEIVED DATA ###################")

        attackName, timestamp = parseSplunkRequest(data)
        attackType, capec = defineAttackType(attackName)

        get_timestamp()

        carModel = "Sportage"

        insertAttack(attackName, timestamp, carModel, attackType, capec)

        return "Webhook received"


@app.route("/checkUpdate")
def checkDatabaseUpdate():
    threats = getNumberofThreats()
    numberofThreats = len(threats)
    return "", str(numberofThreats)


@app.route("/splunkDashboard", methods=["GET", "POST"])
def splunkDashboard():
    threats = getNumberofThreats()
    numberofThreats = len(threats)
    return render_template(
        DASHBOARD,
        content=generateThreatsTable(threats, orderBy="time"),
        numberThreats=numberofThreats,
        numberOfPath=getNumberOfPath(),
        numberofAttack=getNumberOfAttack(),
        maxRisk=getSplunkTRM(threats),
    )


@app.route("/splunkThreats")
def splunkThreats():
    threats = getNumberofThreats()
    return render_template(
        THREATS, content=generateThreatsTable(threats, orderBy="time")
    )


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    try:
        offenses = connQradar(limit=LIMIT)
        numberThreats = connQradar(limit=500)[1]
        print(numberThreats)
        return render_template(
            DASHBOARD,
            content=tableThreats(offenses[0], orderBy="time"),
            numberThreats=numberThreats,
            numberOfPath=getNumberOfPath(),
            numberofAttack=getNumberOfAttack(),
            maxRisk=getTRM(offenses[0]),
        )
    except:
        return render_template(THREATS, content=getHTML_radarError())


@app.route("/threats")
def threats():
    try:
        offenses = connQradar(limit=LIMIT)
        return render_template(
            THREATS, content=tableThreats(offenses[0], orderBy="risk")
        )

    except:
        return render_template(THREATS, content=getHTML_radarError())


@app.route("/threat", methods=["GET"])
def threat():
    import re

    args = request.args

    if not bool(re.search(r"\d+", f"capec-{args.get('capec')}")):
        error_content = '<p class="text-danger">Please, select a threat.</p>'
        return render_template(SEARCH, error_content=error_content)

    capec = f"capec-{args.get('capec')}"
    builder = args.get("builder")
    model = args.get("model")
    year = args.get("year")

    contentThreatCapec = createContentAttackPath(
        getHTML_contentThreatCapec(),
        createAttackPaths(capec),
        risk_type="RS",
        builder=builder,
        model=model,
        year=year,
    )

    header = contentHeaderThreatCapec(capec, builder, model)

    # if header is False:
    #     error_content = '<p class="text-danger">Please, select a threat.</p>'
    #     return redirect(url_for("search", error_content=error_content))
    #     return render_template(SEARCH, error_content=error_content)

    return render_template(THREATS, content=contentThreatCapec, header=header)


@app.route("/nvd", methods=["POST"])
def nvdInformation():
    json_body_request = request.get_json()
    # list_descriptions = request.form["description"]
    list_descriptions = json_body_request["description"]
    # list_descriptions = ast.literal_eval(list_descriptions)

    json_sentences = get_similarity_score(list_descriptions)
    result_top_three = get_top_three(json_sentences)
    # result_top_three = get_top_three_request(json_sentences)

    return jsonify(result_top_three)


@app.route("/attackImpact", methods=["GET"])
def attackImpact():
    args = request.args
    capec = f"capec-{args.get('capec')}"
    builder = args.get("builder")
    model = args.get("model")
    year = args.get("year")
    attackName = args.get("attackName")
    contentImpact = generateAttackImpact(
        getHTML_contentAttackImpact(),
        createAttackPaths(capec),
        risk_type="RS",
        builder=builder,
        model=model,
        year=year,
    )

    header = generateAttackImpactHeader(attackName, builder, model, year)
    return render_template(ATTACKIMPACT, content=contentImpact, header=header)


@app.route("/knowledgebase")
def knowledgebase():
    contentKB = createContentAttackPath(
        getHTML_contentKB(), createAttackPaths(), risk_type="severity"
    )

    return render_template(KNOWLEDGEBASE, content=contentKB)


@app.route("/search")
def search():
    return render_template(SEARCH, content=optionThreatSearch())


@app.before_request
def limit_ip():
    if request.remote_addr != "10.11.10.2":
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0")
