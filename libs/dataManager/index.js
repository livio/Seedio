var assert = require('assert'),
    async = require('async'),
    db = mongoose = require('mongoose'),
    i18n = require('i18next'),
    Mocha = require('mocha'),
    session = require('express-session'),
    _ = require('lodash');

var mocha;

var FixtureAdapter = require('./fixtureAdapter.js'),
  DatabaseAdapter = require('./databaseAdapter.js'),
  MongooseAdapter = require('./mongooseAdapter.js');

var adapterName = 'Mongoose';

/* ************************************************************ *
 * ******************** Constructor
 * ************************************************************ */

DataManager = function(app, config, log) {
  this.app = app;
  this.config = config;
  this.log = log;

  this.setDatabaseAdapter();
};

DataManager.prototype.setDatabaseAdapter = function() {
  this.databaseAdapter = MongooseAdapter(this);
};

DataManager.prototype.load = function(data, cb) {
  var tasks = [];

  for(var key in data) {
    if(data.hasOwnProperty(key)) {
      tasks.push(this.createInsertDataMethod(data[key], key));
    }
  }

  async.parallel(tasks, function(err, results) {
    if(err) {
      cb(err);
    } else {
      cb();
    }
  });
};

DataManager.prototype.createInsertDataMethod = function(data, key) {
  var dm = this;
  return function(cb) {
    if(data.insertAll !== undefined) {
      data.insertAll(cb);
    } else {
      dm.log.warn("Data object %s does not have a insertAll() method.", key);
    }
  }
};

DataManager.prototype.unload = function(data, cb) {
  var tasks = [];

  for(var key in data) {
    if(data.hasOwnProperty(key)) {
      tasks.push(this.createDeleteDataMethod(data[key], key));
    }
  }

  async.parallel(tasks, function(err, results) {
    if(err) {
      cb(err);
    } else {
      cb();
    }
  });
};

DataManager.prototype.createDeleteDataMethod = function(data, key) {
  var dm = this;
  return function(cb) {
    if(data.deleteAll !== undefined) {
      data.deleteAll(cb);
    } else {
      dm.log.warn("Data object %s does not have a deleteAll() method.", key);
    }
  }
};


/* ************************************************************ *
 * ******************** Authentication
 * ************************************************************ */

var getLoginCookie = function(user, cb) {
  if( ! user) {
    user = { username: "admin", password: "password" };
  }

  app.post('/login').send({ username: user.username, password: user.password }).expect('Content-Type', /json/).expect(200).end(function(err, res) {
    if(err) {
      cb(err);
    } else {
      var data;
      try {
        data = JSON.parse(res.text);
      } catch(err) {
        return cb(err);
      }

      assert.noEqual(res.headers['set-cookie'], undefiend);
      cb(undefined, res.headers['set-cookie']);
    }
  });
};

var getUserAccessToken = function(data, userId, cb) {
  var accessTokens = data.AccessToken.getAll();

  for(var accessTokenIndex = 0; accessTokenIndex < accessTokens.length; accessTokenIndex++) {
    if(accessTokens[accessTokenIndex].user == userId) {
      return cb(undefined, accessTokens[accessTokenIndex]);
    }
  }

  cb(new Error("Could not find access token for user with id " + userId));
};

var accessTokenCache = {};

var getAccessToken = function(data, roleIndex, cb) {
  var accessTokens = data.AccessToken.getAll(),
      userRoles = data.UserRole.getAll(),
      users = data.User.getAll();

  if(accessTokenCache[roleIndex] !== undefined) {
    return cb(undefined, accessTokenCache[roleIndex]);
  } else {
    for(var userRoleIndex = 0; userRoleIndex < userRoles.length; userRoleIndex++) {
      if(userRoles[userRoleIndex].index === roleIndex) {
        for(var userIndex = 0; userIndex < users.length; userIndex++) {
          for(var rolesIndex = 0; rolesIndex < users[userIndex].roles.length; rolesIndex++) {
            if(users[userIndex].roles[rolesIndex] === userRoles[userRoleIndex]._id) {
              for(var accessTokenIndex = 0; accessTokenIndex < accessTokens.length; accessTokenIndex++) {
                if(accessTokens[accessTokenIndex].user === users[userIndex]._id) {
                  accessTokenCache[roleIndex] = accessTokens[accessTokenIndex].token;
                  return cb(undefined, accessTokens[accessTokenIndex].token);
                }
              }
            }
          }
        }
      }
    }
  }

  cb();
};

var inherit = function(proto) {
  function F() {}
  F.prototype = proto;
  return new F;
};

/* ************************************************************ *
 * ******************** Public API
 * ************************************************************ */

/**
 * Sets up the database with required documents.
 * @param callback
 */
DataManager.prototype.setup = function (callback) {
  // If the db is already open, just use it. Else wait for the connection to be opened.
  if(mongoose.connection.readyState === 1) {
    setupDb(function() {
      callback();
    })
  } else {
    mongoose.connection.once('open', function () {
      setupDb(function() {
        callback();
      })
    });
  }
};

/**
 * Removes the documents that were added in set-up.
 * @param callback
 */
DataManager.prototype.tearDown = function (cb) {
  dropAllCollections(cb);
};

DataManager.prototype.getLoginCookie = getLoginCookie;


DataManager.prototype.DatabaseAdapter = DatabaseAdapter;
DataManager.prototype.FixtureAdapter = FixtureAdapter;
DataManager.prototype.inherit = inherit;

exports = module.exports = DataManager;
exports = DataManager;
