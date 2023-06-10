def getHTML_radarError():
    
    error = '''
      <div class="alert alert-info" role="alert" style="margin-top: 2%;">
        Connection Error. Make sure Qradar is open and working properly.
      </div>
    '''

    return error

def getHTML_contentKB():
    
    content = '''
          <div class="table-responsive custom-table-responsive">
        <table data-toggle="table" data-search="true" data-show-columns="true" data-pagination="true" class="table table-dark">
          <thead>
            <tr>
              <th scope="col" data-switchable="false">
                <label class="control control--checkbox">
                  <input type="checkbox" class="js-check-all" />
                  <div class="control__indicator"></div>
                </label>
              </th>

              <th data-sortable="true" class="text-center" style="width:8%" scope="col">Attack path</th>
              <th data-sortable="true" scope="col">Consequence</th>
              <th data-sortable="true" class="text-center" style="width:8%" scope="col">Severity</th>
              <th class="text-center" style="width:8%" scope="col">SC</th>
              <th class="text-center" scope="col">Details</th>
            </tr>
          </thead>
          <tbody>
    
    '''

    return content

def getHTML_contentThreatCapec():
    
  content = '''
          <div class="table-responsive custom-table-responsive">
        <table data-toggle="table" data-search="true" data-show-columns="true" data-pagination="true" data-sort-name="risk" data-sort-order="desc" class="table custom-table table-hover table-dark ">
          <thead>
            <tr>
              <th scope="col" data-switchable="false">
                <label class="control control--checkbox">
                  <input type="checkbox" class="js-check-all" />
                  <div class="control__indicator"></div>
                </label>
              </th>

              <th data-sortable="true" class="text-center" style="width:8%" scope="col">Attack path</th>
              <th data-sortable="true" scope="col">Consequence</th>
              <th data-sortable="true" data-field="risk" class="text-center" style="width:8%" scope="col">RS</th>
              <th class="text-center" style="width:8%" scope="col">RI</th>
              <th class="text-center" scope="col">Details</th>
            </tr>
          </thead>
          <tbody>
  '''

  return content