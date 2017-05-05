/**
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

require( 'dotenv' ).config( {silent: true} );
var agent = require('bluemix-autoscaling-agent');
var express = require( 'express' );  // app server
var bodyParser = require( 'body-parser' );  // parser for post requests
var Watson = require( 'watson-developer-cloud/conversation/v1' );  // watson sdk

// var passport = require('passport');
// var cookieParser = require('cookie-parser');
// var session = require('express-session');
//
// app.use(cookieParser());
// app.use(session({resave: 'true', saveUninitialized: 'true' , secret: 'keyboard cat'}));
// app.use(passport.initialize());
// app.use(passport.session());
//
// passport.serializeUser(function(user, done) {
//    done(null, user);
// });
//
// passport.deserializeUser(function(obj, done) {
//    done(null, obj);
// });
//
// // VCAP_SERVICES contains all the credentials of services bound to
// // this application. For details of its content, please refer to
// // the document or sample of each service.
// var services = JSON.parse(process.env.VCAP_SERVICES || "{}");
// var ssoConfig = services.SingleSignOn[0];
// var client_id = ssoConfig.credentials.clientId;
// var client_secret = ssoConfig.credentials.secret;
// var authorization_url = ssoConfig.credentials.authorizationEndpointUrl;
// var token_url = ssoConfig.credentials.tokenEndpointUrl;
// var issuer_id = ssoConfig.credentials.issuerIdentifier;
// var callback_url = "auth/sso/callback";
//
// var OpenIDConnectStrategy = require('passport-idaas-openidconnect').IDaaSOIDCStrategy;
// var Strategy = new OpenIDConnectStrategy({
//                  authorizationURL : authorization_url,
//                  tokenURL : token_url,
//                  clientID : client_id,
//                  scope: 'openid',
//                  response_type: 'code',
//                  clientSecret : client_secret,
//                  callbackURL : callback_url,
//                  skipUserProfile: true,
//                  issuer: issuer_id},
// 	function(iss, sub, profile, accessToken, refreshToken, params, done)  {
// 	         	process.nextTick(function() {
// 		profile.accessToken = accessToken;
// 		profile.refreshToken = refreshToken;
// 		done(null, profile);
//          	})
// });
//
// passport.use(Strategy);
// app.get('/login', passport.authenticate('openidconnect', {}));
//
// function ensureAuthenticated(req, res, next) {
// 	if(!req.isAuthenticated()) {
// 	          	req.session.originalUrl = req.originalUrl;
// 		res.redirect('/login');
// 	} else {
// 		return next();
// 	}
// }
// The following requires are needed for logging purposes
var uuid = require( 'uuid' );
var vcapServices = require( 'vcap_services' );
var basicAuth = require( 'basic-auth-connect' );

//Following are needed for MQTT communication
var mqtt = require('mqtt');

var mqttBrokerUrl = 'mqtt://test.mosquitto.org';
var mqttTopicLight = 'cognitive/nexright/light';
var mqttTopicTemp = 'cognitive/nexright/temperature';
var mqttLightOn = '{"value": "on"}';
var mqttLightOff = '{"value": "off"}';
var temperature;
var humidity;

var clientWrite  = mqtt.connect(mqttBrokerUrl);
var clientRead = mqtt.connect(mqttBrokerUrl,
  {
      clientId: 'demo-expo',
      keepalive: 0,
      clean: false
  });
clientWrite.on('connect', () => {
  //Subscribe to Light topic
  clientWrite.subscribe(mqttTopicLight);
  //client.subscribe(mqttTopicTemp);

  clientRead.on('connect', () => {
    clientRead.subscribe(mqttTopicTemp);
    console.log("subscribed to temp");
  })
  //Start reading the temperature reading from Broker
  checkMessageInBroker();
})

// The app owner may optionally configure a cloudand db to track user input.
// This cloudand db is not required, the app will operate without it.
// If logging is enabled the app must also enable basic auth to secure logging
// endpoints
var cloudantCredentials = vcapServices.getCredentials( 'cloudantNoSQLDB' );
var cloudantUrl = null;
if ( cloudantCredentials ) {
  cloudantUrl = cloudantCredentials.url;
}
cloudantUrl = cloudantUrl || process.env.CLOUDANT_URL; // || '<cloudant_url>';
var logs = null;
var app = express();

// Bootstrap application settings
app.use( express.static( './public' ) ); // load UI from public folder
app.use( bodyParser.json() );

// Create the service wrapper
var conversation = new Watson( {
  // If unspecified here, the CONVERSATION_USERNAME and CONVERSATION_PASSWORD env properties will be checked
  // After that, the SDK will fall back to the bluemix-provided VCAP_SERVICES environment property
  // username: '<username>',
  // password: '<password>',
  url: 'https://gateway.watsonplatform.net/conversation/api',
  version_date: '2017-03-26',
  version: 'v1'
} );

// Endpoint to be call from the client side
app.post( '/api/message', function(req, res) {
  var workspace = process.env.WORKSPACE_ID || '<workspace-id>';
  if ( !workspace || workspace === '<workspace-id>' ) {
    return res.json( {
      'output': {
        'text': 'The app has not been configured with a <b>WORKSPACE_ID</b> environment variable. Please refer to the ' +
        '<a href="https://github.com/watson-developer-cloud/conversation-simple">README</a> documentation on how to set this variable. <br>' +
        'Once a workspace has been defined the intents may be imported from ' +
        '<a href="https://github.com/watson-developer-cloud/conversation-simple/blob/master/training/car_workspace.json">here</a> in order to get a working application.'
      }
    } );
  }
  var payload = {
    workspace_id: workspace,
    context: {
      temperature: temperature,
      humidity: humidity
    },
    input: {}
  };
  if ( req.body ) {
    if ( req.body.input ) {
      payload.input = req.body.input;
    }
    if ( req.body.context ) {
      // The client must maintain context/state
      payload.context = req.body.context;
      payload.context.temperature = temperature;
      payload.context.humidity = humidity;
    }
  }
  // Send the input to the conversation service
  conversation.message( payload, function(err, data) {
    if ( err ) {
      return res.status( err.code || 500 ).json( err );
    }
    return res.json( updateMessage( payload, data ) );
  } );
} );

function checkMessageInBroker(){
  console.log("checking temp");
  // var client2  = mqtt.connect(mqttBrokerUrl);
  // var clientRead = mqtt.connect(mqttBrokerUrl,
  //   {
  //       clientId: 'demo-expo',
  //       keepalive: 0,
  //       clean: false
  //   });
  // clientRead.on('connect', () => {
  //   clientRead.subscribe(mqttTopicTemp);
  //   console.log("subscribed to temp");
  // })
  clientRead.on('message', function (topic, message) {
    var tempObj = JSON.parse(message);
    if(tempObj != null || tempObj != undefined){
      if(tempObj.d != null || tempObj.d != undefined){
        temperature = tempObj.d.temp;
        humidity = tempObj.humidity;
        console.log("Temp:"+temperature+", Humidity: "+humidity);
      }else{
        temperature = temperature;
        humidity = humidity;
        console.log("Temp1:"+temperature+", Humidity: "+humidity);
      }
    }else{
      temperature = "0.0*C";
      humidity = "0.0%";
      console.log("Temp2:"+temperature+", Humidity: "+humidity);
    }
  })
  // client2.end();
}

function sendInputToBroker(topic, input){
  //connect to MQTT
  // clientWrite.on('connect', () => {
  //   //client.subscribe(mqttTopicLight);
  //   //client.subscribe(mqttTopicTemp);
  //   // Send data to Broker once subscribed
  //   clientWrite.publish(topic, input);
  //   console.log(topic.toString()+":"+input);
  // });
  clientWrite.publish(topic, input);
  console.log(topic.toString()+":"+input);

  // clientWrite.on('error', function(){
  //   console.log("ERROR");
  //   clientWrite.end();
  // });
}

function validateMQTTInput(output){
  if(output == process.env.TURN_ON_LIGHT){
    sendInputToBroker(mqttTopicLight, mqttLightOn);
  }else if(output == process.env.TURN_OFF_LIGHT){
    sendInputToBroker(mqttTopicLight, mqttLightOff);
  }
}
/**
 * Updates the response text using the intent confidence
 * @param  {Object} input The request to the Conversation service
 * @param  {Object} response The response from the Conversation service
 * @return {Object}          The response with the updated message
 */
function updateMessage(input, response) {
  var responseText = null;
  var id = null;
  if ( !response.output ) {
    response.output = {};
  } else {
    if ( logs ) {
      // If the logs db is set, then we want to record all input and responses
      id = uuid.v4();
      logs.insert( {'_id': id, 'request': input, 'response': response, 'time': new Date()});
    }
    //send response for validation and then to MQTT
    // var respText = response.output.text[0];
    validateMQTTInput(response.output.text[0]);
    //
    // if(respText == "temp"){
    //   // checkMessageInBroker();
    //   response.output.text[0] = "It's "+temperature+" and "+humidity+" humid now. Plan accordingly."
    // }
    return response;

  }
  if ( response.intents && response.intents[0] ) {
    var intent = response.intents[0];
    // Depending on the confidence of the response the app can return different messages.
    // The confidence will vary depending on how well the system is trained. The service will always try to assign
    // a class/intent to the input. If the confidence is low, then it suggests the service is unsure of the
    // user's intent . In these cases it is usually best to return a disambiguation message
    // ('I did not understand your intent, please rephrase your question', etc..)
    if ( intent.confidence >= 0.75 ) {
      responseText = 'I understood your intent was ' + intent.intent;
    } else if ( intent.confidence >= 0.5 ) {
      responseText = 'I think your intent was ' + intent.intent;
    } else {
      responseText = 'I did not understand your intent';
    }
  }
  response.output.text = responseText;
  if ( logs ) {
    // If the logs db is set, then we want to record all input and responses
    id = uuid.v4();
    logs.insert( {'_id': id, 'request': input, 'response': response, 'time': new Date()});
  }
  return response;
}

module.exports = app;
