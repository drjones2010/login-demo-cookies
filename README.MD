## login-demo-cookie

Authentication using Express and SQLite3 (with sequelize).

----------------
### Why and what

This project has been made to demonstrate a way to implement an auth system using the best practices without too many third party packages.

It uses <code>express</code> as webserver, <code>bcrypt</code> for password hashing, <code>sqlite3</code> for the persistence and <code>sequelize</code> as orm.

I've chosen to use sqlite3 because its very small memory demands for such a didactic exercise, but be aware that probably it's not the best option for big projects ([I mean, more than 100k hits per day, a lot of write ops, etc](https://www.sqlite.org/whentouse.html)).

----------------------
### How to use this project

Install packages:

    npm install express cookie-parser body-parser sqlite3 sequelize bcrypt ejs

Start app:

    node app

Go to localhost:

    http://127.0.0.1:3000/

-----------------
### How it works

#### Log in
1. User logs in with username and password;
2. The server looks in the database for the username that matches with the hashed password;
3. If found, the server generates a uuid4 token and saves it on a signed cookie on the client;
4. The server redirects the user to the secret page.

#### Sign up
1. User signs up with username and password;
2. The server hashes the password with bcrypt and stores it in the users table;
3. The server generates a uuid4 token and saves it in the sessions table;
4. The server saves the token into a signed cookied on client browser;
5. The server redirects the user to the secret page.

#### Access to the secret page
1. User tries to access to the secret page;
2. The server looks for a signed cookie named "session" on the user's browser;
3. If such cookie exists, the server checks into its session table if there is the same token;
4. If found, the server let the user access the secret page, otherwhise redirects to the login page.

#### Log out
1. User clicks on logout link, on secret page;
2. The server deletes the user's token from the sessions table;
3. The server redirects the user to the login page.
