//get data
function getDataByEmail(email){
  var sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
  var data = sheet.getDataRange().getValues();
  var result = null;
  for(var i=1; i<data.length; i++){
    if(data[i][0] == email){
      result = data[i];
      break;
    }
  }
  return result;
}

//login function
function login(email, password){
  var data = getDataByEmail(email);
  var error = null;

  if(data == null){
    error = "email not registered";
  }else if(data[1] != password){
    error = "invalid password";
  }

  if(error == null){
    return {
      status: "success",
      data: data
    }
  }else{
    return {
      status: "error",
      message: error
    }
  }
}


//signup function
function signup(email, password, name){
  var check = getDataByEmail(email);
  if(check != null){
    return {
      status: "error",
      message: "email already exist"
    }
  }else{
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
    var data = [[email,password,name]];
    var row = sheet.getLastRow() + 1;
    var cel = 1;
    var rowLength = data.length;
    var celLength = data[0].length;
    sheet.getRange(row, cel, rowLength, celLength).setValues(data);
    return {
      status: "success",
      message: "signup successfully"
    }
  }
}


// handle POST request
function doPost(e){
  var error = null;
  if(typeof e.parameter.action == 'undefined'){
    error = "action parameter required";
  }else if(e.parameter.action == "login"){ //LOGIN  PROCCESS
    if(typeof e.parameter.email == 'undefined'){
      error = "email required";
    }else if(typeof e.parameter.password == 'undefined'){
      error = "password required";
    }else if(e.parameter.email.trim() == ""){
      error = "email could not be empty";
    }else if(e.parameter.password.trim() == ""){
      error = "password could not be empty";
    }else{
      var result = login(e.parameter.email.trim(), e.parameter.password.trim());
    }
  }else if(e.parameter.action == "signup"){ //SIGNUP PROCCESS
    if(typeof e.parameter.email == 'undefined'){
      error = "email required";
    }else if(typeof e.parameter.password == 'undefined'){
      error = "password required";
    }else if(typeof e.parameter.name == 'undefined'){
      error = "name required";
    }else if(e.parameter.email.trim() == ""){
      error = "email could not be empty";
    }else if(e.parameter.password.trim() == ""){
      error = "password could not be empty";
    }else if(e.parameter.name.trim() == ""){
      error = "name could not be empty";
    }else{
      var result = signup(e.parameter.email.trim(), e.parameter.password.trim(), e.parameter.name.trim());
    }
  }else{
    error = "unknown action";
  }

  if(error != null){
    var result = {
      status: 'error',
      message: error
    }
  }

  return ContentService.createTextOutput(JSON.stringify(result));
}


//handle GET request
function doGet(e){
  return ContentService.createTextOutput(JSON.stringify({
    status: "error",
    message: "Method GET not allowed"
  }))
}

function test(){
  var data = signup("user2@example.com", "1234567", "user two");
  Logger.log(JSON.stringify(data));
}










