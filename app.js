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
			res.redirect("/secret");
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
			res.redirect("/secret");
		} else {
			res.redirect("/login");
		}
	})
});

app.get("/secret", isAuthenticated, (req, res) => {
	res.render("user", {username: req.username})
});

function isAuthenticated(req, res, next){
    if(req.signedCookies.session){
		DbApi.retrieveSessionByToken(req.signedCookies.session)
		.then(session => {
			if (!session){
				res.redirect("/login");
			}
			req.username = session.username;
			return next();
		}).catch(err => {
			console.log(err);
		});
    } else {
		res.redirect("/login");
	}
}

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
    console.log("Server has started on http://127.0.0.1:3000");
})



