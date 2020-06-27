	/**
	 *
	 * Copyright 2015 IBM Corp. All Rights Reserved.
	 *
	 * Licensed under the Apache License, Version 2.0 (the "License");
	 * you may not use this file except in compliance with the License.
	 * You may obtain a copy of the License at
	 *
	 *      http://www.apache.org/licenses/LICENSE-2.0
	 *
	 * Unless required by applicable law or agreed to in writing, software
	 * distributed under the License is distributed on an "AS IS" BASIS,
	 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	 * See the License for the specific language governing permissions and
	 * limitations under the License.
	 */
	'use strict';

	var express = require('express'); // app server
	var cookieParser = require('cookie-parser');//Cookies
	var bodyParser = require('body-parser'); // parser for post requests
	var AssistantV2 = require('ibm-watson/assistant/v2'); // watson sdk
	

	var request = require('request');
	const path = require('path');
	const multer = require('multer');
	const fs = require('fs');
	const url = require('url');
	const querystring = require('querystring');
	const propertiesReader = require('properties-reader');
	var cors = require('cors');
	const ejs = require('ejs');
	const cryptoRandomString = require('crypto-random-string');
	var token="";
	
	var app = express();
	//require('./public/js/conversation.js')(app,multer,request,path,fs);
    //Cookies
	app.use(cookieParser());
	const {
	    IamAuthenticator,
	    BearerTokenAuthenticator
	} = require('ibm-watson/auth');

	app.all('/', function (req, res, next) {
	  console.log('Accessing the secret section ...',req.query.authHeader);
	  token=req.query.authHeader;
	  res.cookie('authToken',token);
	  console.log(token);
	  const enstr = cryptoRandomString({length: 10, type: 'url-safe'});
	  console.log(enstr);
	  res.cookie(token,enstr);   
	  console.log('cookies -->',req.cookies);
	  console.log('authToken -->',req.cookies.authToken);
	
	  
	//   const cookies = req.cookies;
	//   const tokenTest = cookies.authToken;
	//   console.log('1',cookies.authToken);
	//   //console.log('2',cookiestokenTest);
	//   console.log('test cookie-->',req.cookies);
	  next() // pass control to the next handler

	})
	
	require('./health/health')(app);
	//Bootstrap application settings
	app.use(bodyParser.urlencoded({ extended: true }));
    app.use(express.static(path.join(__dirname + '/public')));
	app.use(bodyParser.json());
	app.set('view engine', 'ejs');
	//added by Anuram
	app.use(cors());
	//console.log('authHeader');

	app.use(function(req, res, next) {
	    res.header('Access-Control-Allow-Origin', 'http://10.10.1.40:3000'); // update to match the domain you will make the request from
		res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
		var cookie = req.cookies.authheader;
   		var cookie = req.cookies.authToken;

  //console.log(":::",url.URL.name);
	if (cookie === undefined) {

	 // no: set a new cookie
	  //const queryObject = req.query.authheader;
	  //console.log(queryObject+"sdlfddfl");

	//  console.log(queryObject);

	// res.cookie('authToken',token);

//	 console.log('cookie created successfully');

	} else {

	 // yes, cookie was already present 
	 	// const url = require('url');
		// const current_url = new URL('http://localhost:3001/?authHeader=Basic:NzYxMTA0OkFiY0AxMjM0');
		// const search_params = current_url.searchParams;
		// const authHeader = search_params.get('authHeader');
		// var fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
	  	//console.log(authHeader+"sdlfddfl"+fullUrl);

	 	console.log('cookie exists', cookie);

	}
	    next();
	});

	// till here added by anuram
	//Create the service wrapper

	//added by anuram

	//added by ayyan
	app.get('/',(req,res)=> {
		res.render('index');
	});
	const storage = multer.diskStorage({
	    destination: process.env.MULTER_DESTINATION,
	    filename: function(req, file, cb) {
	        cb(null, file.originalname);
	    }
	});

	const upload = multer({
	    storage: storage
	}).single('filename');

	app.post('/api/upload', (req, res) => {
		var filep = "";
	    console.log("inside app post");
	    upload(req, res, (err) => {
	        if (err) {
	            console.log(err);
	        } else {
	            if (req.file === undefined) {
	                return res.send('not selecting files');
	            }
	            console.log("request", req.file.filename);
				filep = path.join(__dirname, "./public/uploads/" + req.file.filename);
				var claimNumber = JSON.parse(req.body.claimNumber);
	            const options = {
	                method: "POST",
					url: process.env.FILE_UPLOAD_API,
	                headers: {
						"Content-Type": "multipart/form-data",
						'Authorization': req.cookies.authToken
	                },
	                formData: {
						"uploadFile": fs.createReadStream(filep),
						"claimNumber": claimNumber.claimNumber,
						"fileName":req.file.filename
					}
	            };
	            request(options, function(err, httpResponse, body) {
	                if (err)
	                    return res.send(err);
	                else
	                    return res.send(body);
	            });
	            fs.unlink(filep, err => console.log(err));
	        }
	    });
	});	

	app.post('/api/documentSearch', (req, res) => {
				var claimNumber = req.body.claimNumber;
				request.get({
					url: process.env.DOCUMENT_SEARCH_API + claimNumber,
					headers:{
					'Authorization': req.cookies.authToken
					}
				}, function(error, response, body) {
					if (!error && (response.statusCode == 200 || response.statusCode == 201)) {
						res.send(body);
					} else {
						console.log("Error is", error);
						res.send(error);
					}
	    		});
	});

	
	//});
	//added by ayyan
	//app.get()
	var caseData='';
	
	app.post('/api/caseSearch', (req, res) => {
				var claimNumber = req.body.claimNumber;
				
				console.log('claimnumber',claimNumber);
				request.get({
					url: 'http://localhost:8080/caseSearch?claimNumber='+claimNumber,
					headers:{
					'Authorization': req.cookies.authToken
					}
				}, function(error, response, body) {
					if (!error && (response.statusCode == 200 || response.statusCode == 201)) {
						caseData = JSON.parse(body);
						console.log(caseData);
						let tokenUpdated=token.replace('==','');
	  					let encryptedStr = req.cookies[tokenUpdated];
						res.send(encryptedStr);
					} else {
						console.log("Error is", error);
						res.status(401).send(error);
					}
	    		});
	});
	var verifyToken = function (req, res, next) {
		var tokenStr = req.cookies.authToken;
		var urlToken = req.query.token;
		if(tokenStr==undefined || urlToken==undefined){
			console.log('inside error 1');
			res.status(401).send('Your dont have permissions to access this page');
		}else if(tokenStr==null || urlToken==null){
			console.log('inside error 2');
			res.status(401).send('Your dont have permissions to access this page');
		}else{
			var tokenUpdated=tokenStr.replace('==','');		
			var encryptedStr = req.cookies[tokenUpdated];
			console.log(urlToken+'   '+encryptedStr+'  '+tokenStr+'  '+tokenUpdated);
			if(encryptedStr.trim()!=urlToken.trim())
				{	
					console.log('inside error');
					res.status(401).send('Your dont have permissions to access this page');
				}
				else{
					next();
				}
		}  		
	}

	app.get('/search',verifyToken,(req,res)=>{
		res.render('Search',{'search':caseData,'symbolicName':['CmAcmCaseIdentifier','DateCreated','CmAcmCaseState','Creator','DateLastModified','LastModifier'],'columnHeader':['Case Id','Created Date','Status','Created By','Last Modified Date','Last Modified By']});
	});
	
	app.post('/api/validateclaim', function(req, res) {
	    console.log(req);
	    var claimNumber = req.body.claimNumber;
	    console.log(process.env.VALIDATE_CLAIM_API + claimNumber);
	    request.get({
			url: process.env.VALIDATE_CLAIM_API + claimNumber,
			headers:{
				'Authorization': req.cookies.authToken
			}
	    }, function(error, response, body) {
	        if (!error && (response.statusCode == 200 || response.statusCode == 201)) {
	            console.log("Body is", body);
	            res.send(body);
	        } else {
	            console.log("Error is", error);
				res.status(400).json(error);	        
			}

	    });
	});

	app.post('/api/claimnumber', function(req, res) {
	    console.log(req);
	    var claimNumber = req.body.claimNumber;
	    console.log(process.env.CREATE_CLAIM_API + claimNumber);
	    request.get({
			url: process.env.CREATE_CLAIM_API + claimNumber,
			headers:{
				'Authorization': req.cookies.authToken
			}
	    }, function(error, response, body) {

	        if (!error && (response.statusCode == 200 || response.statusCode == 201)) {
	            console.log("Body is", body);
	            res.send(body);
	        } else {
	            console.log("Error is", error);
	            res.status(400).json(error);
	        }

	    });
	});

	app.post('/api/createCase', function(req, res) {

	    var username = process.env.CASEMANAGER_USERNAME;
	    var password = process.env.CASEMANAGER_PASSWORD;
	    var options = {
	        url: process.env.IBM_CREATE_CASE_API,
	        headers: {
	            'Content-type': 'application/json',
	            'Access-Control-Allow-Credential': 'true',
	            'Authorization': req.cookies.authToken
	        },
	        auth: {
	            user: username,
	            password: password
	        },
	        method: 'POST',
	        json: req.body
	    }
	    request(options, function(error, response, body) {
	        if (response.statusCode == 200 || response.statusCode == 201) {
	            res.send(body);
	        } else {
	            res.status(401).send(error);
	        }

	    });
	});

	//added by ayyan



	let authenticator;
	if (process.env.ASSISTANT_IAM_APIKEY) {
	    authenticator = new IamAuthenticator({
	        apikey: process.env.ASSISTANT_IAM_APIKEY
	    });
	} else if (process.env.BEARER_TOKEN) {
	    authenticator = new BearerTokenAuthenticator({
	        bearerToken: process.env.BEARER_TOKEN
	    });
	}

	var assistant = new AssistantV2({
	    version: process.env.WATSON_VERSION,
	    authenticator: authenticator,
	    url: process.env.ASSISTANT_URL,
	    disableSslVerification: process.env.DISABLE_SSL_VERIFICATION === 'true' ? true : false
	});

	//Endpoint to be call from the client side
	app.post('/api/message', function(req, res) {
	    let assistantId = process.env.ASSISTANT_ID || '<assistant-id>';
	    if (!assistantId || assistantId === '<assistant-id>') {
	        return res.json({
	            output: {
	                text: 'The app has not been configured with a <b>ASSISTANT_ID</b> environment variable. Please refer to the ' +
	                    '<a href="https://github.com/watson-developer-cloud/assistant-simple">README</a> documentation on how to set this variable. <br>' +
	                    'Once a workspace has been defined the intents may be imported from ' +
	                    '<a href="https://github.com/watson-developer-cloud/assistant-simple/blob/master/training/car_workspace.json">here</a> in order to get a working application.',
	            },
	        });
	    }

	    var textIn = '';

	    if (req.body.input) {
	        textIn = req.body.input.text;
	    }

	    var payload = {
	        assistantId: assistantId,
	        sessionId: req.body.session_id,
	        input: {
	            message_type: 'text',
	            text: textIn,
	            'options': {
	                'return_context': true
	            }
	        },
	    };

	    // Send the input to the assistant service

	    assistant.message(payload, function(err, data) {
	        if (err) {
	            const status = err.code !== undefined && err.code > 0 ? err.code : 500;
	            return res.status(status).json(err);
	        }
	        /* if(typeof(data.result.context.skills['main skill'].user_defined.Claim_Number)!=undefined)
	        {
	        	console.log('Data JSON ---->', data.result.context.skills['main skill'].user_defined.Claim_Number);
	        } */
	        console.log('Generics ----> ', data.result.output.generic);
	        console.log('Entities --->  ', data.result.output.entities);
	        console.log('Intent ----> ', data.result.output.intents);
	        return res.json(data);
	    });
	});

	app.get('/api/session', function(req, res) {
	    assistant.createSession({
	            assistantId: process.env.ASSISTANT_ID || '{assistant_id}',
	        },
	        function(error, response) {
	            if (error) {
	                return res.send(error);
	            } else {
	                return res.send(response);
	            }
	        }
	    );
	});

	module.exports = app;