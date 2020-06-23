//********** Authored by: Davide *********//
//********** Date: June, 2020 *********//
//********** Organization: KYC&AML *********//

//*** --- creates an Express application
const express = require('express');
const app = express();

//*** --- provide both HTTP versions of app with the same code base
const http = require('http');
const crypto = require('crypto');
const errorhandler = require('errorhandler');
const axios = require('axios');

//*** --- enable CORS with various options
const cors = require('cors');

//*** --- middleware setup
const bodyParser = require('body-parser');
const session = require('express-session');

//*** --- cors implement
app.use(cors());
//*** --- express default configurations
app.use(require('morgan')('dev'));
app.use(
	bodyParser.urlencoded({
		extended: false,
	})
);
app.use(bodyParser.json());
app.use(require('method-override')());
app.use(express.static(__dirname + '/public'));
app.use(
	session({
		secret: 'KYCAML',
		cookie: {
			maxAge: 60000,
		},
		resave: false,
		saveUninitialized: false,
	})
);

require('dotenv/config');
app.get('/api/', function (req, res) {
	res.json({ msg: 'This is KYC Backend' });
});
app.get('/api/get_token', async function (req, res, next) {
	const { UserID } = req.query;
	try {
		let ts = Math.round(Date.now() / 1000);
		let hmacSha256 = crypto.createHmac('sha256', process.env.APP_TOKEN_SECRET);
		hmacSha256.update(ts + 'POST' + '/resources/accessTokens?userId=' + UserID + '&ttlInSecs=4800');
		console.log('/resources/accessTokens?userId=' + UserID + '&ttlInSecs=4800');
		const hmacHex = hmacSha256.digest('hex');
		res.setHeader('Content-Type', 'application/json');
		res.setHeader('X-App-Token', process.env.APP_TOKEN);
		res.setHeader('X-App-Access-Ts', ts);
		res.setHeader('X-App-Access-Sig', hmacHex);

		const config = {
			headers: {
				'X-App-Token': process.env.APP_TOKEN,
				'X-App-Access-Ts': ts,
				'X-App-Access-Sig': hmacHex,
			},
		};

		// console.log(`${process.env.BASEURL}/resources/accessTokens?userId=${UserID}&ttlInSecs=4800`);
		axios
			.post(`${process.env.BASEURL}/resources/accessTokens?userId=${UserID}&ttlInSecs=4800`, null, {
				headers: {
					'X-App-Token': process.env.APP_TOKEN,
					'X-App-Access-Ts': ts,
					'X-App-Access-Sig': hmacHex,
				},
			})
			.then((response) => {
				// console.log(response);
				res.json({ data: response.data });
			})
			.catch((err) => err);
	} catch (err) {
		next(err);
	}
});

app.post('/api/get_token', function (req, res, next) {
	console.log('Post');
});

//*** --- catch 404 and forward to error handler
app.use(function (req, res, next) {
	const err = new Error('Not Found');
	err.status = 404;
	next(err);
});
//*** --- connect to database && error handler
if (process.env.NODE_ENV === 'development') {
	//*** --- development error handler
	app.use(errorhandler());
	app.use(function (err, req, res) {
		// console.log(err.stack);
		res.status(err.status || 500);
		res.json({
			error: {
				message: err.message,
				error: err,
			},
		});
	});
} else {
	//*** --- production error handler
	app.use(function (err, req, res) {
		res.status(err.status || 500);
		res.json({
			error: {
				message: err.message,
				error: {},
			},
		});
	});
}
//*** --- binds and listens for connections on the specific host and port
http.createServer(app).listen(3030);
