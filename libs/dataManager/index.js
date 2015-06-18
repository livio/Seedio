var assert = require('assert'),
    async = require('async'),
    db = mongoose = require('mongoose'),
    i18n = require('i18next'),
    Mocha = require('mocha'),
    session = require('express-session'),
    _ = require('lodash');

var app,
    config,
    log,
    mocha;


/* ************************************************************ *
 * ******************** Constructor
 * ************************************************************ */

DataManager = function(_app, _config, _log) {
  app = _app;
  config = _config;
  log = _log;
};


/* ************************************************************ *
 * ******************** Validation Methods.
 * ************************************************************ */

var validateBadRequestObject = function(data, locale) {
  validateErrorObject(data);
  assert.equal(data.error.message, i18n.t(locale ||'server.error.badRequest') || locale);
};

var validateNotFoundObject = function(data, locale) {
  validateErrorObject(data);
  assert.equal(data.error.message, i18n.t(locale ||'server.error.notFound') || locale);
};

var validateUnauthorized = function(data, locale) {
  validateErrorObject(data);
  assert.equal(data.error.message, i18n.t(locale ||'server.error.unauthorized') || locale);
};

var validateForbiddenObject = function(data, locale) {
  validateErrorObject(data);
  assert.equal(data.error.message, i18n.t(locale ||'server.error.forbidden') || locale);
};

var validateErrorObject = function(data, locale) {
  // Make sure the error object is valid.
  assert.notEqual(data.error, undefined);
  assert.notEqual(data.error, null);
  assert.equal(_.isObject(data.error), true);

  // Make sure message is available and valid.
  assert.notEqual(data.error.message, null);
  assert.notEqual(data.error.message, undefined);
  assert.equal(_.isString(data.error.message), true);

  if(config.debug) {
    assert.notEqual(data.error.stack, undefined);
    assert.notEqual(data.error.stack, undefined);
    assert.equal(_.isString(data.error.stack), true);
  }

  if(locale) {
    assert.equal(data.error.message, i18n.t(locale) || locale);
  }
};

var validateResponseObject = function(data) {
  // Check for an error object
  if((data.response == undefined || data.response == null) && (data.error == undefined || data.error == null)) {
    if(data.error == undefined) {
      log.e("Invalid response: %s", JSON.stringify(data));
      throw new Error("Either response or error must be defined.");
    } else {
      validateErrorObject(data);
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

/* ************************************************************ *
 * ******************** Handle Data
 * ************************************************************ */

var addData = function(data, cb) {
  var tasks = [];

  for(var key in data) {
    if(data.hasOwnProperty(key)) {
      tasks.push(createAddDataMethod(data[key], key));
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

var createAddDataMethod = function(data, key) {
  return function(cb) {
    if(data.insertAll !== undefined) {
      data.insertAll(cb);
    } else {
      log.w("Data object %s does not have a insertAll() method.", key);
    }
  }
};

var removeData = function(data, cb) {
  var tasks = [];

  for(var key in data) {
    if(data.hasOwnProperty(key)) {
      tasks.push(createRemoveDataMethod(data[key], key));
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

var createRemoveDataMethod = function(data, key) {
  return function(cb) {
    if(data.deleteAll !== undefined) {
      data.deleteAll(cb);
    } else {
      log.w("Data object %s does not have a deleteAll() method.", key);
    }
  }
};


 /* ************************************************************ *
 * ******************** Add Item(s) to the Database
 * ************************************************************ */

var addItem = function addItem(modelName, obj, cb) {
  var Model = mongoose.model(modelName);
  new Model(obj).save(function(err, newObj) {
    if(err) {
      cb(err);
    } else {
      //log.t("Added %s with id.", modelName, newObj._id);
      cb(undefined, newObj);
    }
  });
};

var addItemMethod = function addItemMethod(modelName, obj) {
  return function(cb) {
    var Model = mongoose.model(modelName);
    new Model(obj).save(function(err, newObj) {
      if(err) {
        return cb(err);
      }

      //log.t("Added %s with id.", modelName, newObj._id);
      cb();
    });
  }
};

var addItems = function addItems(modelName, items, cb) {
  async.each(items, function (item, next) {
    addItem(modelName, item, next);
  }, cb);
};

var addItemsMethod = function addItemsMethod(modelName, items) {
  return function(cb) {
    async.each(items, function (item, next) {
      addItem(modelName, item, next);
    }, cb);
  }
};


/* ************************************************************ *
 * ******************** Remove Items from Database
 * ************************************************************ */


var removeItem = function(schemaName, id, cb) {
  removeItemById(schemaName, id, cb);
};

var removeItemById = function(schemaName, id, cb) {
  var Schema = mongoose.model(schemaName);

  Schema.findOne({ "_id" : id}, function (err, data) {
    if (err) {
      cb(err);
    } else {
      if (data === undefined || data === null) {
        //log.t("Schema %s with item id %s already removed.", schemaName, id);
        cb();
      } else {
        data.remove(function(err, removedData) {
          if(err) {
            return cb(err);
          }

          //log.t("Schema %s with item id %s removed.", schemaName, data._id);
          cb();
        });
      }
    }
  });
};


var removeItemMethod = function(schemaName, obj) {
  return removeItemByIdMethod(schemaName, obj._id);
};

var removeItemByIdMethod = function(schemaName, id) {
  return function (cb) {
    var Schema = mongoose.model(schemaName);

    Schema.findOne({ "_id" : id}, function (err, data) {
      if (err) {
        cb(err);
      } else {
        if (data === undefined || data === null) {
          //log.t("Schema %s with item id %s already removed.", schemaName, id);
        } else {
          //log.t("Schema %s with item id %s removed.", schemaName, data._id);
        }

        cb();
      }
    });
  };
};

var removeItems = function(schemaName, objs, cb) {
  var ids = [];
  for(var i = 0; i < objs.length; i++) {
    ids.push(objs[i]._id);
  }
  removeItemsById(schemaName, ids, cb);
};

var removeItemsById = function(schemaName, ids, cb) {
  async.each(ids, function (id, next) {
    removeItem(schemaName, id, next)
  }, cb);
};

var removeItemsMethod = function(schemaName, objs) {
  var ids = [];
  for(var i = 0; i < objs.length; i++) {
    ids.push(objs[i]._id);
  }
  return removeItemsByIdMethod(schemaName, ids);
};

var removeItemsByIdMethod = function(schemaName, ids) {
  return function (cb) {
    async.each(ids, function (id, next) {
      removeItemById(schemaName, id, next)
    }, cb);
  }
};


/* ************************************************************ *
 * ******************** Drop Collections from Database
 * ************************************************************ */

/**
 * Remove all data in a specified collection from the currently
 * connected database.
 */
function dropCollectionByName(schema) {
  return function(cb) {
    if( schema === undefined || schema === null) {
      return cb("Cannot drop a collection with an invalid name of " + schema);
    }

    schema = schema.toLowerCase();

    if(db.connection.collections[schema] === undefined || db.connection.collections[schema] === null) {
      return cb("Cannot drop the " + schema + " collection because it does not exist");
    }

    db.connection.collections[schema].drop(function(err) {
      if(err) {
        if(err.message !== undefined && err.message.indexOf("ns not found") > -1) {
          cb(undefined, schema + " collection does not need to be dropped because it has not yet been initialized.");
        } else {
          cb(err);
        }
      } else {
        //log.t("Dropped the %s collection", schema);
        cb(undefined, "Dropped the " + schema + " collection.");
      }
    });
  }
}

function dropAllCollections(cb) {
  var methods = [];

  // Create the list of tasks to be performed in parallel.
  for(var key in mongoose.connection.collections) {
    if(mongoose.connection.collections.hasOwnProperty(key)) {
      methods.push(dropCollectionByName(key));
    }
  }

  // Execute the tasks in parallel, removing the access tokens.
  async.parallel(methods, function (err, results) {
    cb(err, results);
  });
}


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

DataManager.prototype.addItem = addItem;
DataManager.prototype.addItemMethod = addItemMethod;
DataManager.prototype.addItems = addItems;
DataManager.prototype.addItemsMethod = addItemsMethod;

DataManager.prototype.removeItem = removeItem;
DataManager.prototype.removeItems = removeItems;
DataManager.prototype.removeItemMethod = removeItemMethod;
DataManager.prototype.removeItemsMethod = removeItemsMethod;

DataManager.prototype.removeItemById = removeItemById;
DataManager.prototype.removeItemsById = removeItemsById;
DataManager.prototype.removeItemByIdMethod = removeItemByIdMethod;
DataManager.prototype.removeItemsByIdMethod = removeItemsByIdMethod;

DataManager.prototype.addData = addData;
DataManager.prototype.removeData = removeData;

DataManager.prototype.getAccessToken = getAccessToken;
DataManager.prototype.getUserAccessToken = getUserAccessToken;

DataManager.prototype.validateResponseObject = validateResponseObject;
DataManager.prototype.validateUnauthorized = validateUnauthorized;
DataManager.prototype.validateForbiddenObject = validateForbiddenObject;
DataManager.prototype.validateErrorObject = validateErrorObject;
DataManager.prototype.validateNotFoundObject = validateNotFoundObject;
DataManager.prototype.validateBadRequestObject = validateBadRequestObject;

exports = module.exports = DataManager;
exports = DataManager;