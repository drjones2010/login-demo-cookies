var Sequelize = require("sequelize");
var bcrypt = require("bcrypt");

var saltRounds = 10;
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

	expiration: Sequelize.INTEGER

}, {
    timestamps: false
});

class DuplicateKeyError extends Error{}

function cryptPassword(password) {
    return new Promise(function(resolve, reject) {
        bcrypt.hash(password, saltRounds, function(err, hash) {
			if (err) reject(err);
            else resolve(hash);
        });
    })
};

module.exports = {

	
	createDatabase: function(){
		return connection.sync({
			force: false //Overwrites the tables
		}).then(() => {
			setInterval(function(){
				Session.findAll({where: {expiration: {[Sequelize.Op.lt]: Date.now()}}})
			}, cleanUpInterval);
		}).catch(err =>{
			console.log(err);
		})
	},

	registerUser: function (user, pass, cookieAge){
		return connection.transaction(t => {
			return this.createUser(user, pass, {transaction: t})
			.then(userRow => {
				return this.createSession(user, cookieAge, {transaction: t});
			}).catch(Sequelize.UniqueConstraintError, err =>{
				throw new this.DuplicateKeyError();
			});
		})
	},

	createUser: function (user, pass, options){
		return User.create({username: user, password: pass}, options);
	},

	createSession: function (user, cookieAge, options){
		return Session.create({username: user, expiration: Date.now()+cookieAge}, options);
	},

	retrieveUser: function (user, password){
		return User.findOne({where: {username: user}})
		.then(user => {
			if (!user)
				return null;
				
			return user.checkPassword(password).then(result => {
				if (result) return user;
				else return null;
			})
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

	login: function (user, pass, cookieAge){
		return this.retrieveUser(user, pass)
		.then(user => {
			return (user ? this.createSession(user.username, cookieAge) : null)
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

	DuplicateKeyError: DuplicateKeyError
}





