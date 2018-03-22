var express = require("express");
var cookieParser = require("cookie-parser");
var bodyParser = require("body-parser");

var DbApi = require("./libs/DbApi");

var app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}))

app.use(cookieParser("He just kept talking in one long incredibly unbroken sentence, moving from topic to topic..."));

DbApi.createDatabase(); //Create if not exists

app.get("/", (req, res) => {
    console.log(req.signedCookies);
    res.render("home");
})

app.get("/login", (req, res) => {
 	res.render("login");
});

app.post("/login", (req, res) => {

	DbApi.login(req.body.username, req.body.password)
	.then(session => {
		if (session.token != null){
			DbApi.addUserSession(session.token, res);
			res.redirect("/users/" + session.username);
		} else {
			res.redirect("/login");
		}
	}).catch(err => {
		res.redirect("/login");
	});

});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.post("/signup", (req, res) => {
	DbApi.registerUser(req.body.username, req.body.password)
	.then(session => {
		if (session.token != null){
			DbApi.addUserSession(session.token, res);
			res.redirect("/users/" + req.body.username);
		} else {
			res.redirect("/login");
		}
	})
});

app.get("/users/:username", (req, res) => {
	if (!req.signedCookies.session){
	 	res.render("login");
	} else {
		return DbApi.retrieveSessionByToken(req.signedCookies.session)
		.then(session => {
			if (!session)
				throw(1);
			res.render("user", {username: session.username})
		}).catch(err => {
			switch (err) {
				case 1:
					console.log("Session not found");
					res.redirect("/login");
					break;
				default:
					console.log(err);
			}
		});
	}
});

app.get('/logout', (req, res) => {
    var token = req.signedCookies.session;

	DbApi.logout(token)
	.then(result => {
		if (result){
			DbApi.removeUserSession(res);
		  	res.redirect('/login');
		} else {
			console.log('Unable to logout');
		}
	});

});

app.listen(3000, () => {
    console.log("Server has started");
})

