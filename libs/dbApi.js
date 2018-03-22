var Sequelize = require("sequelize");
var bcrypt = require("bcrypt");

var saltRounds = 10;
var cookieAge = 604800000; //1week
var cleanUpInterval = 1000 * 60 * 60 * 24 //24hour

//Create db connection object
const connection = new Sequelize('users', null, null, {
	logging: false,
	operatorsAliases: Sequelize.Op,
    dialect: 'sqlite',
    storage: './db.sqlite'
});

//Create USERS table
const User = connection.define('users', {
    username: {
        type: Sequelize.STRING,
        primaryKey: true
    },
    password: Sequelize.STRING
}, {
    timestamps: false
});

//Add encryption of the password
User.beforeCreate((user, options) => {
  return cryptPassword(user.password)
  	.then(hash => {
		user.password = hash;
	})
});

//Check if hash is correct
function checkPassword (password) {
	hash = this.password;
	return bcrypt.compare(password, hash).then(function(res) {
		return res;
	});
}

User.checkPassword = checkPassword;

User.prototype.checkPassword = checkPassword;

//Create SESSIONS table
const Session = connection.define('sessions', {
	username: {
        type: Sequelize.STRING,
        references: {
            model: User,
            key: "username"
        }
    },
	token: {
    	type: Sequelize.UUID,
    	defaultValue: Sequelize.UUIDV4,
    	primaryKey: true
  	},

	expiration: {
		type: Sequelize.INTEGER,
		defaultValue: Date.now()+cookieAge
	}

});

module.exports = {

	createDatabase: function(){
		return connection.sync({
			force: true //Overwrites the tables
		}).then(() => {
			setInterval(function(){
				Session.findAll({where: {expiration: {[Sequelize.Op.lt]: Date.now()}}})
			}, cleanUpInterval);
		}).catch(err =>{
			console.log(err);
		})
	},

	registerUser: function (user, pass){
		return connection.transaction(t => {
			return this.createUser(user, pass, {transaction: t})
			.then(userRow => {
				return this.createSession(user, {transaction: t});
			}).catch(err => {
				console.log(err);
			})
		})
	},

	createUser: function (user, pass, options){

		return User.create({username: user, password: pass}, options)
		.catch(Sequelize.UniqueConstraintError, err =>{
			console.log("	ERR> Username taken");
		}).catch(err =>{
			console.log(err);
		});
	},

	createSession: function (user, options){
		return Session.create({username: user, expiration: cookieAge}, options)
		.catch(Sequelize.UniqueConstraintError, err =>{
			console.log("	ERR> User already logged in");
		}).catch(err =>{
			console.log(err);
		});
	},

	retrieveUser: function (user, password){
		return User.findOne({where: {username: user}})
		.then(user => {
			if (!user || !user.checkPassword(password))
				throw(new Error());
			else return user;
		});
	},

	retrieveSessionByUser: function (user){
		return Session.findOne({where: {username: user}});
	},

	retrieveSessionByToken: function (token){
		return Session.findOne({where: {token: token}});
	},

	deleteSessionByUser: function(user){
		return Session.destroy({where: {username: user}})
		.then((affected) =>{
			return affected;
		})
	},

	deleteSessionByToken: function(token){
		return Session.destroy({where: {token: token}})
	},

	login: function (user, pass){
		return this.retrieveUser(user, pass)
		.then(user => {
			return this.createSession(user.username);
		}).catch(err => {
			console.log("ERR> Access denied.")
		});
	},

	logout: function(token){
		return this.deleteSessionByToken(token)
		.then(affected => {
			if (affected == 1){
				console.log("User has logged out.");
				return true;
			} else {
				console.log("Session not found");
				return false;
			}
		})
	},

	hasValidToken: function (token){
		return this.retrieveSessionByToken(token)
		.then(session => {
			return session!=null;
		}).catch(err => {
			console.log(err);
		});
	},

	addUserSession: function (token, res){
		res.cookie("session", token, {
			httpOnly: true,
			maxAge: cookieAge,
			signed: true,
			// secure: true	//put it to true if behind https
		})
	},

	removeUserSession: function (res){
		res.clearCookie("session");
	}
}

function cryptPassword(password) {
    return new Promise(function(resolve, reject) {
        bcrypt.hash(password, saltRounds, function(err, hash) {
			if (err) reject(err);
            else resolve(hash);
        });
    })
};
