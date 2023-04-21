'use strict';

var express = require('express');
var serveStatic = require('serve-static');
var bodyParser = require('body-parser')
var cookieParser = require('cookie-parser');

var unless = require('express-unless');
var randomWords = require('random-words');
var Sentencer = require('sentencer');
var fs = require('fs');

//database
const MongoClient = require('mongodb').MongoClient;
const dotenv = require('dotenv');

//auth/token stuff
var jwt = require('jsonwebtoken');

// for the shell exec goodness
const { exec } = require("child_process");

// for the IP address goodness
var Address4 = require('ip-address').Address4;

// Crypto to generate UUIDs
const { v4: uuidv4 } = require('uuid');

// PRIVATE and PUBLIC key
var privateKey = fs.readFileSync('./keys/private.key', 'utf8');
var publicKey = fs.readFileSync('./keys/public.key', 'utf8');

//create express server and register global middleware
//API7 - Express adds powered-by header which gives away internal information.
var api = express();
api.use(bodyParser.json());
api.use(bodyParser.urlencoded({
	extended: true
}));

//api.use(cookieParser());

//accept files in /uploads dir (pictures)
api.use(serveStatic(__dirname + '/uploads'));

//API binds to interface pixiapp:8090
api.listen(8090, function () {
	if (process.env.NODE_ENV === undefined)
		process.env.NODE_ENV = 'development';
	console.log("PixiApp: API running on port %d in %s mode.", this.address().port, process.env.NODE_ENV);
});

// Connect to MongoDB
dotenv.config();
const mongo_url = process.env.MONGO_URL;
console.log('API Server starting - Will connect to Mongo on: ' + mongo_url);

// Mongo V3+ Driver separates url from dbname / uses client
const db_name = 'Pixidb'
let db

MongoClient.connect(mongo_url, { useNewUrlParser: true }, (err, client) => {
	if (err) return err;
	// Store the database connection object
	db = client.db(db_name)
	console.log(`>>> Connected to MongoDB: ${mongo_url}`)
	console.log(`>>> Database is: ${db_name}`)
})

function api_authenticate(user, pass, req, res) {
	console.log('>>> Logging user ' + user + ' with password: ' + pass);
	const users = db.collection('users');

	users.findOne({ email: user, password: pass }, function (err, result) {
		if (err) {
			console.log('>>> Query error...' + err);
			res.status(500).json({ "message": "system error" });
		}
		if (result !== null) {
			// API10: This is bad logging, as it dumps the full user record
			console.log('>>> Found User:  ' + result);
			var user_profile = result;
			// API7/API3: Add full record to JWT token (including clear password)
			var payload = { user_profile };

			var token = jwt.sign(payload, privateKey, {
				algorithm: 'RS384',
				issuer: 'https://issuer.42crunch.demo',
				subject: user_profile.email,
				expiresIn: "30m",
				audience: 'pixiUsers'
			});

			res.status(200).json({ message: "success", token: token, _id: user_profile._id });
		}
		else
			res.status(401).json({ message: "sorry bud, invalid login" });
	});
}

function api_register(user, pass, req, res) {
	console.log('>>> Registering user: ' + user + ' with password: ' + pass);
	const users = db.collection('users');
	// Check if user exists first
	users.findOne({ email: user }, function (err, result) {
		if (err) {
			console.log('>>> Query error...' + err);
			res.status(500).json({ "message": "system error" });
		}
		if (result !== null) {
			// Bad message: the error message should not indicate what the error is.
			res.status(400).json({ "message": "user is already registered" });
		}
		else {
			if (req.body.is_admin) {
				var admin = true;
			}
			else {
				var admin = false
			}
			var name = req.body.name;
			var subject = user;
			console.log(">>> Username: " + name);
			// Voluntary error to return an exception is the account_balance is negative.
			if (req.body.account_balance < 0) {
				var err = new Error().stack;
				res.status(400).json(err);
				return;
			}
			var payload = {
				_id: uuidv4(),
				email: user,
				password: pass,
				name: name,
				account_balance: req.body.account_balance,
				is_admin: admin,
				onboarding_date: new Date()
			};
			// forceServerObjectId forces Mongo to use the specified _id instead of generating a random one.
			users.insertOne(payload, { forceServerObjectId: true }, function (err, user) {
				if (err) {
					console.log('>>> Query error...' + err);
					res.status(500).json({ "message": "system error" });
				}
				if (user.insertedId != null) {
					var user_profile = payload;
					var jwt_payload = { user_profile };
					var token = "";
					try {
						token = jwt.sign(jwt_payload, privateKey, {
							algorithm: 'RS384',
							issuer: 'https://issuer.42crunch.demo',
							subject: subject,
							expiresIn: "30m",
							audience: 'pixiUsers'
						})
						res.status(200).json({ message: "success", token: token, _id: payload._id });
					}
					catch {
						console.log(">>> Error occurred during JWT creation");
						res.status(400).json({ message: "registration failure", token: null, _id: null });
					}
				} //if user
			}) //insert
		} // else
	});
}

function api_token_check(req, res, next) {

	console.log('>>> Validating token: ' + JSON.stringify(req.headers['x-access-token']));
	var token = req.headers['x-access-token'];

	// decode jwt token
	if (token) {
		// Verify token
		jwt.verify(token, publicKey, function (err, user) {
			if (err) {
				console.log(err)
				return res.status(403).json({ success: false, message: 'Failed to authenticate token' });
			} else {
				// if everything is good, save to request for use in other routes
				req.user = user;
				console.log('>>> Authenticated User: ' + JSON.stringify(req.user));
				next();
			}
		});

	} else {
		// if there is no token
		// return an error
		return res.status(403).send({
			success: false,
			message: 'No token provided'
		});
	}
}

function random_sentence() {
	var samples = ["This day was {{ adjective }} and {{ adjective }} for {{ noun }}",
		"The {{ nouns }} {{ adjective }} is back",
		"Breakfast, {{ an_adjective }}, {{ adjective }} for {{ noun }}",
		"Oldie but goodie {{ a_noun }} and {{ a_noun }} {{ adjective }} {{ noun }}",
		"My {{ noun }} is {{ an_adjective }} which is better than yours",
		"That time when your {{ noun }} feels {{ adjective }} and {{ noun }}"
	];

	var my_sentence = samples[Math.floor(Math.random() * (4 - 1)) + 1];
	var sentencer = Sentencer.make(my_sentence);
	return sentencer;
}

api.delete('/api/picture/:id', api_token_check, function (req, res) {
	console.log('>>> Deleting picture ' + req.params.id);
	const pictures = db.collection('pictures');
	// BOLA - API1 Issue here: a user can delete someone's else picture.
	// Code does not validate who the picture belongs too.
	pictures.deleteOne({ _id: req.params.id },
		function (err, result) {
			if (err) {
				console.log('>>> Query error...' + err);
				res.status(500).json({ "message": "system error" });
			}
			if (result.deletedCount == 0) {
				console.log(">>> No picture was deleted")
				res.status(400).json({ "message": "bad input" });
			}
			else {
				console.log('>>> Photo ' + req.params.id + ' was deleted');
				res.status(200).json({ "message": "success" });
			}
		})
});

api.delete('/api/admin/user/:id', api_token_check, function (req, res) {
	console.log('>>> Deleting user ' + req.params.id);
	const users = db.collection('users');
	if (!req.params.id) {
		res.status(400).json({ "message": "missing userid to delete" });
	}
	else {
		// API2 : Authorization issue - This call should enforce admin role, but it does not.
		users.deleteOne({ _id: req.params.id },
			function (err, result) {
				if (err) {
					console.log('>>> Query error...' + err);
					res.status(500).json({ "message": "system error" });
				}
				//console.log("result object:" + result.deletedCount);
				if (result.deletedCount == 0) {
					console.log(">>> No user was deleted")
					res.status(400).json({ "message": "bad input" });
				}
				else {
					res.status(200).json({ "message": "success" });
				}
			});

	}
});

api.post('/api/picture/upload', api_token_check, function (req, res) {
	const pictures = db.collection("pictures")

	if (!req.body.contents) {
		res.status(400).json({ "message": "missing file" });
	}
	else {
		//console.log(">>> Uploading File: " + req.body.contents);
		const imageUUID = uuidv4();
		const imageName = imageUUID + ".img";
		const imageUrl = __dirname + '/uploads/' + imageName;
		console.log(">>> Uploading File: " + imageUrl);
		try {
			const imageBuffer = Buffer.from(req.body.contents, 'base64');
			fs.writeFileSync(imageUrl, imageBuffer);
		}
		catch (exc) {
			console.log ("Exception raised while saving file: " + e );
			res.status(400).json({ "message": "bad data input" });
			return;
		}

		var description = random_sentence();
		var name = randomWords({ exactly: 2 });
		name = name.join(' ');

		var payload = {
			_id: imageUUID,
			title: req.body.title,
			image_url: imageUrl,
			name: name,
			filename: imageName,
			description: description,
			creator_id: req.user.user_profile._id,
			money_made: 0,
			likes: 0,
			created_date: new Date()
		}

		pictures.insertOne(payload, { forceServerObjectId: true }, function (err, result) {
			if (err) {
				console.log('>>> Query error...' + err);
				res.status(500).json({ "message": "system error" });
			}
			console.log("Inserted ID: " + result.insertedId)
			if (result.insertedId !== null) {
				res.status(200).json({ "message": "success", "_id": result.insertedId });
			}
		}); // photo insert
	} //else
});

// user related.
api.post('/api/user/login', function (req, res) {
	if ((!req.body.user) || (!req.body.pass)) {
		res.status(422).json({ "message": "missing username and or password parameters" });
	}
	else {
		api_authenticate(req.body.user, req.body.pass, req, res);
	}
})

api.post('/api/user/register', function (req, res) {
	if ((!req.body.user) || (!req.body.pass)) {
		res.status(422).json({ "message": "missing username and or password parameters" });
	} else if (req.body.pass.length <= 4) {
		res.status(422).json({ "message": "password length too short, minimum of 5 characters" })
	} else {
		api_register(req.body.user, req.body.pass, req, res);
	}
})

api.get('/api/user/info', api_token_check, function (req, res) {
	let jwt_user = req.user.user_profile;
	if (!jwt_user.hasOwnProperty('_id')) {
		res.status(422).json({ "message": "missing userid" })
	}
	else {
		db.collection('users').find({ _id: req.user.user_profile._id }).toArray(function (err, user) {
			if (err) { return err }
			if (user) {
				res.status(200).json(user);
			}
		})
	}
});

api.put('/api/user/edit_info', api_token_check, function (req, res) {
	//console.log('in user put ' + req.user.user_profile._id);

	var objForUpdate = {};
	const users = db.collection('users');
	///console.log('BODY ' + JSON.stringify(req.body));
	if (req.body.email) { objForUpdate.email = req.body.email; }
	if (req.body.password) { objForUpdate.password = req.body.password; }
	if (req.body.name) { objForUpdate.name = req.body.name; }

	// Major issue here (API 6) - anyone can make themselves an admin!
	if (req.body.hasOwnProperty('is_admin')) {
		let is_admin_status = Boolean(req.body.is_admin);
		objForUpdate.is_admin = is_admin_status
	}
	if (!req.body.email && !req.body.password && !req.body.name && !req.body.is_admin) {
		res.status(422).json({ "message": "Bad input" });
	}
	else {
		var setObj = { objForUpdate }
		console.log(">>> Update User Data: " + JSON.stringify(setObj));
		users.findOneAndUpdate(
			{ _id: req.user.user_profile._id },
			{ $set: objForUpdate },
			{ returnNewDocument: true, upsert: true },
			function (err, userupdate) {
				if (err) {
					console.log('>>> Query error...' + err);
					res.status(500).json({ "message": "system error" });
				}
				if (userupdate) {
					console.log(userupdate);
					res.status(200).json({ "message": "User Successfully Updated" });
				}
				else {
					res.status(400).json({ "message": "Bad Request" });
				}
			})
	}
});

api.get('/api/user/pictures', api_token_check, function (req, res) {

	const pictures = db.collection('pictures');

	pictures.find({ creator_id: req.user.user_profile._id }).toArray(function (err, pictures) {
		if (err) {
			console.log('>>> Query error...' + err);
			res.status(500).json({ "message": "system error" });
		}

		if (pictures) {
			console.log(">>> Pictures list: " + pictures);
			res.json(pictures);

		}
	})
});

api.get('/api/admin/all_users', api_token_check, function (req, res) {
	//res.json(req.user);
	//API2 - Authorization issue: can be called by non-admins.
	db.collection('users').find().toArray(function (err, all_users) {
		if (err) { return err }
		if (all_users) {
			res.json(all_users);
		}
	})
});

global.API_KEY = "d318adf3-dd81-4c25-8b28-8df3feb0b9f0";

api.get('/api/admin/ping/:ipAddress', api_token_check, function (req, res) {
	var command_to_run = "ping -c 1 " + req.params.ipAddress;

	exec(command_to_run, (error, stdout, stderr) => {
		if (error) {
			console.log(`error: ${error.message}`);
			res.status(400).send('Error:' + error.message)
			return;
		}
		if (stderr) {
			console.log(`stderr: ${stderr}`);
			res.status(400).send('Error:' + stderr.message)
			return;
		}

		console.log(`stdout: ${stdout}`);

		var my_output = stdout;
		res.status(200).send(my_output);
	});
});