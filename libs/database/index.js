var crypto = require('crypto'),
    path = require('path');

var config, log;

var Database = function(_config, _log) {
  config = _config;
  log = _log;
};

// Method to connect to a MongoDB database.
Database.prototype.connect = function(cb) {
  var mongoose = require('mongoose');

  mongoose.connect(config.database.uri);
  mongoose.connection.on('error', function(err) {
    log.error(err);
  });
  mongoose.connection.once('open', function() {
    initializeDatabase(mongoose, function(err) {
      cb(err, mongoose);
    });
  });
};

var initializeDatabase = function(db, cb) {
  // Check if we should initialize the database when connecting.
  if( ! config.database.initializeOnConnect) {
    return cb();
  }

  var dm = new (require(path.resolve('./libs/dataManager/')))(undefined, config, log);
  initializeUserRoles(db, dm, function(err) {
    if(err) {
      log.error(err.stack);
    } else {
      initializeAdminUser(db, dm, cb);
    }
  });
};

var initializeUserRoles = function(db, dm, cb) {
  return cb()
  var userRoleData = require(path.resolve('./app/users/userRole_data'))(undefined, config, log, dm);
  var UserRole = db.model('UserRole');

  UserRole.find({}, function(err, userRoles) {
    if(err) {
      cb(err);
    } else if( ! userRoles || userRoles.length == 0){
      userRoleData.insertAll(function(err) {
        if(err) {
          cb(err);
        } else {
          UserRole.find({}, function(err, userRoles) {
            if(err) {
              cb(err);
            } else if( ! userRoles || userRoles.length == 0) {
              cb(new Error("No user roles were added to the database."));
            } else {
              for(var i = userRoles.length-1; i >= 0; --i) {
                log.info("%s user role was added to the database.", userRoles[i].name);
              }
              cb();
            }
          });
        }
      });
    } else {
      cb();
    }
  });
};

var initializeAdminUser = function(db, dm, cb) {
  return cb();
  var User = db.model('User');
  var UserRole = db.model('UserRole');

  UserRole.findOne({ index: config.roles.admin }, function(err, adminRole) {
    if(err) {
      cb(err);
    } else if( ! adminRole) {
      cb(new Error("Admin user role does not exist in the database."));
    } else {
      User.find({ roles: adminRole._id }, function(err, adminUsers) {
        if(err) {
          cb(err);
        } else if( ! adminUsers || adminUsers.length == 0) {
          var admin = new User({
            activated: true,
            email: config.admin.email,
            roles: [ adminRole._id ],
            securityQuestion: 'You need to change this.',
            username: 'admin'
          });

          var password = createRandomTextSync(config.crypto.plainTextSize/2).toString('hex');
          admin.setPassword(password, function(err, admin) {
            if(err) {
              cb(err);
            } else {
              User.find({ roles: adminRole._id }, function(err, adminUsers) {
                if(err) {
                  cb(err);
                } else if( ! adminUsers || adminUsers.length == 0) {
                  cb(new Error("An admin user was not added to the database."));
                } else {
                  var notification = new (require(path.resolve('./libs/notification/')))(config, log);

                  notification.sendDefaultAdminEmail(admin, password, function(err, success) {
                    if(err) {
                      cb(err);
                    } else if ( ! success) {
                      log.info("Admin with username %s was added to the database with password %s", admin.username, password);
                    } else {
                      log.info("Admin with username %s was added to the database and the password was emailed.", admin.username);
                      cb();
                    }
                  });
                }
              });
            }
          });
        } else {
          cb();
        }
      });
    }
  });
};


/**
 * Create a random string of text of the given size.
 * @param length is the length of the text.
 * @returns a string of the given length.
 */
var createRandomTextSync = function(length) {
  var text;
  try {
    text = crypto.randomBytes(length || 256);
  } catch(err) {
    log.error(err);
    text = uuid.v4();
  }

  return text;
};

exports = module.exports = Database;
exports = Database;