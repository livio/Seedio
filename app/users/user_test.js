module.exports = function(app, config, log, data, dm) {

  var assert = require('assert'),
    async = require('async'),
    i18n = require('i18next'),
    should = require('should'),
    _ = require('lodash');

  var adminAccessToken = "",
    oemAccessToken = "",
    developerAccessToken = "";

  var adminRole = config.roles.admin,
    oemRole = config.roles.oem,
    developerRole = config.roles.developer;

  /* ************************************************** *
   * ******************** Private Methods
   * ************************************************** */

  var validateUsers = function(users, role, userId, cb) {
    data.User.getUserObject(userId, function(err, user) {
      if(err) {
        cb(err);
      } else {
        var tasks = [];

        for(var i = 0; i < users.length; i++) {
          tasks.push(createValidateUserMethod(users[i], role, userId));
        }

        async.parallel(tasks, function(err, results) {
          cb(err);
        });
      }
    });
  };

  var createValidateUserMethod = function(user, role, userId) {
    return function(cb) {
      validateUser(user, role, userId, cb);
    }
  };

  var validateUser = function(user, role, userId, cb) {
    assert.notEqual(user, undefined);
    assert.notEqual(user, null);

    // User is valid up to this point for an admin.
    if(role <= adminRole) {
      return cb();
    }

    // Developers and OEMs can only view their own account.
    assert.equal(user._id.toString(), userId.toString());

    // Find the original user for comparison since the returned user
    // may not contain all the attributes.
    data.User.findById(user._id, function(err, originalUser) {
      if(err) {
        cb(err);
      } else if( ! originalUser) {
        cb(new Error("User with id "+user._id+ " was not found in data file."));
      } else {

        // Make sure the original user is not deleted if we are not an admin.
        assert.equal(originalUser.deleted, false);

        // OEMs and Developers should never see these attributes
        assert.equal(user.deleted, undefined);
        assert.equal(user.__v, undefined);
        //assert.equal(user.failedLoginAttempts, undefined);
        assert.equal(user.passwordHash, undefined);
        assert.equal(user.passwordResetHash, undefined);
        assert.equal(user.securityAnswerHash, undefined);

        cb();
      }
    });
  };

  var removeUserPrivateAttributes = function(user) {
    delete user.deleted;
    delete user.passwordHash;
    delete user.passwordResetHash;
    delete user.securityAnswerHash;

    return user;
  };

  var removeNonAdminAttributes = function(user, updateUser) {
    delete user.applications;
    delete user.dateCreated;
    delete user.deactivatedMessage;
    delete user.deleted;
    delete user.failedLoginAttempts;
    delete user.lastLogin;
    delete user.lastUpdated;
    delete user.lastUpdatedBy;
    delete user.passwordHash;
    delete user.passwordResetHash;
    delete user.requestedOemAccess;
    delete user.roles;
    delete user.securityAnswerHash;
    delete user.sdlServers;

    if(updateUser) {
      delete user.username;
    }

    return user;
  };

  var compareUserToResponse = function(response, user, isAdmin, original, isUpdate) {
    if(user._id) {
      response._id.should.equal(user._id.toLowerCase());
    }

    // Required to be in response
    assert.notEqual(response.activated, undefined);

    // SDL servers should always be defined, but only compare if present.
    assert.notEqual(response.sdlServers, undefined);
    if(user.sdlServers !== undefined) {
      assert.deepEqual(response.sdlServers, user.sdlServers);
    }

    // Applications should always be defined, but only compare if present.
    assert.notEqual(response.applications, undefined);
    if(user.applications !== undefined) {
      assert.deepEqual(response.applications, user.applications);
    }

    // Compare hashed fields for admins.
    if(isAdmin) {
      if(user.passwordHash) {
        assert.equal(response.passwordHash, user.passwordHash);
      } else {
        assert.notEqual(response.passwordHash, undefined);
      }

      if(user.securityAnswerHash) {
        assert.equal(response.securityAnswerHash, user.securityAnswerHash);
      } else {
        assert.notEqual(response.securityAnswerHash, undefined);
      }

      if(user.passwordResetHash) {
        assert.equal(response.passwordResetHash, user.passwordResetHash);
      } else {
        assert.notEqual(response.passwordResetHash, undefined);
      }

      assert.equal(response.deleted, user.deleted);
    } else {

      // Should not be in a response to non-admins
      assert.equal(response.deleted, undefined);
      assert.equal(response.passwordResetHash, undefined);
      assert.equal(response.passwordHash, undefined);
      assert.equal(response.securityAnswerHash, undefined);
    }

    // Verify attributes that can only be updated by an admin.
    verifyAdminOnlyAttribute('applications', response, user, original, true);
    verifyAdminOnlyAttribute('roles', response, user, original, true);
    verifyAdminOnlyAttribute('deactivatedMessage', response, user, original);
    verifyAdminOnlyAttribute('failedLoginAttempts', response, user, original);
    verifyAdminOnlyAttribute('deactivatedMessage', response, user, original);
    verifyAdminOnlyAttribute('deactivatedMessage', response, user, original);
    verifyAdminOnlyAttribute('deactivatedMessage', response, user, original);
    verifyAdminOnlyAttribute('requestedOemAccess', response, user, original);

    assert.equal(response.oauth2ClientId, user.oauth2ClientId);  //TODO?
    assert.equal(response.securityQuestion, user.securityQuestion);


    if(user.email) {
      user.email = user.email.toLowerCase();
    }
    assert.equal(response.email, user.email);

    if(user.username) {
      user.username = user.username.toLowerCase();
    }
    if( ! isUpdate) {
      assert.equal(response.username, user.username);
    } else {
      verifyAdminOnlyAttribute('username', response, user, original);
    }

    if(user.dateCreated) {
      var d1 = new Date(response.dateCreated),
        d2 = new Date(user.dateCreated);
      assert.notEqual(d1, undefined);
      assert.notEqual(d2, undefined);
    }

    if(user.lastLogin) {
      var d1 = new Date(response.lastLogin),
        d2 = new Date(user.lastLogin);
      assert.notEqual(d1, undefined);
      assert.notEqual(d2, undefined);
      //assert.equal(d1.getTime(), d2.getTime());
    }

    if(user.lastUpdated) {
      var d1 = new Date(response.lastUpdated),
        d2 = new Date(user.lastUpdated);
      assert.notEqual(d1, undefined);
      assert.notEqual(d2, undefined);
      //assert.equal(d1.getTime(), d2.getTime());
    }

    if(user.lastUpdatedBy) {
      assert.equal(response.lastUpdatedBy, user.lastUpdatedBy);
    }
  };

  var verifyAdminOnlyAttribute = function(key, valueObject, updateObject, originalObject, deepEqual) {
    if(updateObject && updateObject[key]) {
      if(deepEqual) {
        assert.deepEqual(valueObject[key], updateObject[key]);
      } else {
        assert.equal(valueObject[key], updateObject[key]);
      }
    } else if(originalObject && originalObject[key]) {
      if(deepEqual) {
        assert.deepEqual(valueObject[key], originalObject[key]);
      } else {
        assert.equal(valueObject[key], originalObject[key]);
      }
    } else {
      assert.notEqual(valueObject[key], undefined);
    }
  };

  var doUsersContainSdlServer = function(userIds, sdlServerId, cb) {
    if( ! userIds || userIds.length <= 0) {
      return cb(new Error("No userIds to check if they contain an SDL server's ID."));
    }

    if( ! sdlServerId) {
      return cb(new Error("SDL server ID is invalid."));
    }

    var tasks = [];
    for(var i = 0; i < userIds.length; i++) {
      tasks.push(createDoesUserContainSdlServerMethod(userIds[i], sdlServerId));
    }

    async.series(tasks, function(err, results) {
      if(err) {
        cb(err);
      } else {
        var usersWithSdlServer = [];
        for(var x = 0; x < results.length; x++) {
          if(results[x] === true) {
            usersWithSdlServer.push(userIds[x]);
          }
        }
        cb(undefined, usersWithSdlServer);
      }
    });
  };

  var createDoesUserContainSdlServerMethod = function(userId, sdlServerId) {
    return function(cb) {
      doesUserContainSdlServer(userId, sdlServerId, cb);
    };
  };

  var doesUserContainSdlServer = function(userId, sdlServerId, cb) {
    app.get('/api/1/users/'+userId+'?access_token='+adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
      if(err) {
        cb(err);
      } else {
        var responseObj = res.body;
        dm.validateResponseObject(responseObj);
        cb(undefined, responseObj.response.sdlServers && (responseObj.response.sdlServers.indexOf(sdlServerId.toLowerCase()) != -1), responseObj.response.sdlServers);
      }
    });
  };

  var updateForbiddenAttributeMethod = function(user, updateObject, accessToken) {
    return function(cb) {
      updateForbiddenAttribute(user, updateObject, accessToken, cb);
    }
  };

  var updateForbiddenAttribute = function(user, updateObject, accessToken, cb) {
    app.put('/api/1/users/' + user._id + '?access_token=' + accessToken.token).send(updateObject).expect('Content-Type', /json/).expect(403).end(function(err, res) {
      if(err) {
        cb(err);
      } else {
        dm.validateForbiddenObject(res.body, i18n.t('server.error.forbiddenAttribute'));
        cb();
      }
    });
  };

  var performUnsuccessfulLoginAttempts = function(user, numLoginAttempts, validationMethod, code, includeCaptcha, cb) {
    var tasks = [];
    for(var i = 0; i < numLoginAttempts; i++) {
      tasks.push(createUnsuccessfulLoginMethod(user, validationMethod, code, includeCaptcha));
    }
    async.series(tasks, cb);
  };

  var performSuccessfulLoginAttempts = function(user, numLoginAttempts, redirect, cb) {
    var tasks = [];
    for(var i = 0; i < numLoginAttempts; i++) {
      tasks.push(createSuccessfulLoginMethod(user, redirect));
    }
    async.series(tasks, cb);
  };

  var createSuccessfulLoginMethod = function(user, redirect) {
    return function(cb) {
      app.post('/api/1/login').send({ username: user.username, password: user.password }).expect('Content-Type', /json/).expect(200).end(function(err, res) {
        if(err) {
          cb(err);
        } else {
          dm.validateResponseObject(res.body);
          validateSuccessfulLogin(res.body, redirect);
          cb(undefined, res.body);
        }
      });
    }
  };

  var createUnsuccessfulLoginMethod = function(user, validationMethod, code, includeCaptcha) {
    validationMethod = (validationMethod) ? validationMethod : dm.validateBadRequestObject;
    code = (code) ? code : 400;

    var postObject = {
      username: user.username,
      password: user.password
    };

    if(includeCaptcha) {
      postObject['g-recaptcha-response'] = "LookACaptcha";
    }

    return function(cb) {
      app.post('/api/1/login').send(postObject).expect('Content-Type', /json/).expect(code).end(function(err, res) {
        if(err) {
          cb(err);
        } else {
          validationMethod(res.body);
          cb(undefined, res.body);
        }
      });
    }
  };

  var validateSuccessfulLogin = function(responseBody, redirect) {
    assert.equal(_.isObject(responseBody.response), true);
    assert.equal(JSON.stringify(responseBody.response), JSON.stringify({ redirect: redirect || '/applications' }));
  };

  var createInvalidPasswordValidationMethod = function(responseBody) {
    return dm.validateUnauthorized(responseBody, 'server.error.invalidPassword');
  };

  var getParameterByName = function(url, name) {
    name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
    var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
      results = regex.exec(url);
    return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
  };


  /* ************************************************** *
   * ******************** Test Suites
   * ************************************************** */

  describe('Users', function() {


    /* ************************************************** *
     * ******************** Lifecycle Methods
     * ************************************************** */

    before(function(done) {
      dm.getAccessToken(data, config.roles.admin, function(err, token) {
        if(err) {
          done(err);
        }
        adminAccessToken = token;

        dm.getAccessToken(data, config.roles.oem, function(err, token) {
          if(err) {
            done(err);
          }
          oemAccessToken = token;

          dm.getAccessToken(data, config.roles.user, function(err, token) {
            if(err) {
              done(err);
            }
            developerAccessToken = token;

            done();
          });
        });
      });
    });

    beforeEach(function(done) {
      dm.addData(data, done);
    });

    afterEach(function(done) {
      dm.removeData(data, done);
    });


    /* ************************************************** *
     * ******************** Query All
     * ************************************************** */

    describe('can all be queried', function() {

      it('by an admin', function(done) {
        app.get('/api/1/users?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);

            // Make sure all the SDL servers were returned for an admin.
            assert.equal(responseObj.response.length, data.User.getAll().length);

            validateUsers(responseObj.response, adminRole, undefined, function(err) {
              done(err);
            });
          }
        });
      });

      it('by an OEM, but only the OEM user account is returned and secret data is not available', function(done) {
        var userId = "000000000000000000000001";
        dm.getUserAccessToken(data, userId, function(err, accessToken) {
          app.get('/api/1/users?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(200).end(function(err, res) {
            if(err) {
              done(err);
            } else {
              var responseObj = res.body;

              dm.validateResponseObject(responseObj);

              // Make sure only 1 user was returned.
              assert.equal(responseObj.response.length, 1);

              validateUsers(responseObj.response, oemRole, userId, function(err) {
                done(err);
              });
            }
          });
        });
      });

      it('by a Developer, but only the Developer user account is returned and secret data is not available', function(done) {
        var userId = "000000000000000000000002";
        dm.getUserAccessToken(data, userId, function(err, accessToken) {
          app.get('/api/1/users?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(200).end(function(err, res) {
            if(err) {
              done(err);
            } else {
              var responseObj = res.body;

              dm.validateResponseObject(responseObj);

              // Make sure only 1 user is returned.
              assert.equal(responseObj.response.length, 1);

              validateUsers(responseObj.response, developerRole, userId, function(err) {
                done(err);
              });
            }
          });
        });
      });

    });

    describe('cannot all be queried', function() {

      it('by an anonymous user', function(done) {
        app.get('/api/1/users?access_token=invalidAccessToken').expect('Content-Type', /json/).expect(401).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            // Make sure an unauthorized error is returned.
            dm.validateUnauthorized(res.body);
            done();
          }
        });
      });

    });


    /* ************************************************** *
     * ******************** Query One
     * ************************************************** */

    describe('can be individually queried', function() {

      it('by an admin with all attributes', function(done) {
        var user = data.User.getAll()[0];

        app.get('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);

            // Ensure the queried SDL server is exactly what we expect.
            compareUserToResponse(responseObj.response, user, true);

            validateUsers(responseObj.response, adminRole, undefined, function(err) {
              done(err);
            });
          }
        });
      });

      it('by an OEM, if it is their user account, but only non-secret data is returned', function(done) {
        var oemUserId = "000000000000000000000001";

        data.User.findById(oemUserId, function(err, oemUser) {
          if(err) {
            done(err);
          } else {
            dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
              if(err) {
                done(err);
              } else {
                app.get('/api/1/users/' + oemUser._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseObj = res.body;

                    dm.validateResponseObject(responseObj);

                    // Ensure the queried SDL server is exactly what we expect.
                    compareUserToResponse(responseObj.response, removeUserPrivateAttributes(oemUser));

                    validateUsers(responseObj.response, oemRole, oemUserId, function(err) {
                      done(err);
                    });
                  }
                });
              }
            });
          }
        });
      });

      it('by a Developer, if it is their user account, but only non-secret data is returned', function(done) {
        var developerUserId = "000000000000000000000002";

        data.User.findById(developerUserId, function(err, developerUser) {
          if(err) {
            done(err);
          } else if( ! developerUser) {
            done(new Error("Could not find user with ID " + developerUserId));
          } else {
            dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
              if(err) {
                done(err);
              } else {
                app.get('/api/1/users/' + developerUser._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseObj = res.body;

                    dm.validateResponseObject(responseObj);

                    // Ensure the queried SDL server is exactly what we expect.
                    compareUserToResponse(responseObj.response, removeUserPrivateAttributes(developerUser));

                    validateUsers(responseObj.response, developerRole, developerUserId, function(err) {
                      done(err);
                    });
                  }
                });
              }
            });
          }
        });
      });

    });

    describe('cannot be individually queried', function() {

      it('by an OEM if not their user account.', function(done) {
        var userId = "000000000000000000000003",
          privateSdlServerId = "200000000000000000000003",
          deactivatedSdlServerId = "200000000000000000000005",
          deletedSdlServerId = "200000000000000000000004";

        data.SdlServer.findById(privateSdlServerId, function(err, sdlServer) {
          if(err) {
            done(err);
          } else {
            dm.getUserAccessToken(data, userId, function(err, accessToken) {
              if(err) {
                done(err);
              } else {
                app.get('/api/1/sdlservers/' + sdlServer._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    dm.validateForbiddenObject(res.body);

                    data.SdlServer.findById(deactivatedSdlServerId, function(err, sdlServer) {
                      if(err) {
                        done(err);
                      } else {
                        app.get('/api/1/sdlservers/' + sdlServer._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                          if(err) {
                            done(err);
                          } else {
                            dm.validateForbiddenObject(res.body);

                            data.SdlServer.findById(deletedSdlServerId, function(err, sdlServer) {
                              if(err) {
                                done(err);
                              } else {
                                app.get('/api/1/sdlservers/' + sdlServer._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(404).end(function(err, res) {
                                  if(err) {
                                    done(err);
                                  } else {
                                    dm.validateNotFoundObject(res.body);
                                    done();
                                  }
                                });
                              }
                            });
                          }
                        });
                      }
                    });
                  }
                });
              }
            });
          }
        });
      });

      it('by a Developer if not their user account', function(done) {
        var userId = "000000000000000000000002",
          privateSdlServerId = "200000000000000000000003",
          deactivatedSdlServerId = "200000000000000000000005",
          deletedSdlServerId = "200000000000000000000004";

        data.SdlServer.findById(privateSdlServerId, function(err, sdlServer) {
          if(err) {
            done(err);
          } else {
            dm.getUserAccessToken(data, userId, function(err, accessToken) {
              if(err) {
                done(err);
              } else {
                app.get('/api/1/sdlservers/' + sdlServer._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    dm.validateForbiddenObject(res.body);

                    data.SdlServer.findById(deactivatedSdlServerId, function(err, sdlServer) {
                      if(err) {
                        done(err);
                      } else {
                        app.get('/api/1/sdlservers/' + sdlServer._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                          if(err) {
                            done(err);
                          } else {
                            dm.validateForbiddenObject(res.body);

                            data.SdlServer.findById(deletedSdlServerId, function(err, sdlServer) {
                              if(err) {
                                done(err);
                              } else {
                                app.get('/api/1/sdlservers/' + sdlServer._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(404).end(function(err, res) {
                                  if(err) {
                                    done(err);
                                  } else {
                                    dm.validateNotFoundObject(res.body);
                                    done();
                                  }
                                });
                              }
                            });
                          }
                        });
                      }
                    });
                  }
                });
              }
            });
          }
        });
      });

      it('by an anonymous user', function(done) {
        var user = data.User.getAll()[0];
        app.get('/api/1/users/' + user._id + '?access_token=InvalidAccessToken').expect('Content-Type', /json/).expect(401).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateUnauthorized(res.body);
            done();
          }
        });
      });

      it('with an invalid objectId', function(done) {
        app.get('/api/1/users/0000?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateBadRequestObject(res.body, 'server.error.invalidObjectId');
            done();
          }
        });
      });

    });


    /* ************************************************** *
     * ******************** Create
     * ************************************************** */

    describe('can be created', function() {

      it('by an admin without a captcha', function(done) {
        var newUser = data.User.getNew();

        // Give the user a non-default user role to make sure we can assign a non-default.
        newUser.roles = [ "300000000000000000000001" ];

        app.post('/api/1/users?access_token=' + adminAccessToken).send(newUser).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, newUser, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              done(err);
            });
          }
        });
      });

      it('by an admin with a captcha', function(done) {
        var newUser = data.User.getNew();

        // Give the user a non-default user role to make sure we can assign a non-default.
        newUser.roles = [ "300000000000000000000001" ];

        // Add a captcha
        newUser['g-recaptcha-response'] = "A Captcha String";

        app.post('/api/1/users?access_token=' + adminAccessToken).send(newUser).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, newUser, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              done(err);
            });
          }
        });
      });

      it('by an OEM with a captcha', function(done) {
        var newUser = data.User.getNew(),
            expectedResponse = data.User.getNew(),
            oemUserId = "000000000000000000000001";

        expectedResponse.deactivatedMessage = "";

        // Add a captcha
        newUser['g-recaptcha-response'] = "A Captcha String";

        dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
          if(err) {
            done(err);
          } else {

            app.post('/api/1/users?access_token=' + accessToken.token).send(removeNonAdminAttributes(newUser)).expect('Content-Type', /json/).expect(200).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                var responseObj = res.body;

                // Make sure the response is valid.
                dm.validateResponseObject(responseObj);

                // Make sure lastUpdatedBy field is correctly populated.
                expectedResponse.lastUpdatedBy = oemUserId;
                expectedResponse.roles = ['300000000000000000000002'];

                // Ensure the created user is exactly what we posted to the server.
                compareUserToResponse(responseObj.response, expectedResponse);

                validateUsers(responseObj.response, oemRole, oemUserId, function(err) {
                  done(err);
                });
              }
            });
          }
        });
      });

      it('by a Developer with a captcha', function(done) {
        var newUser = data.User.getNew(),
          expectedResponse = data.User.getNew(),
          developerUserId = "000000000000000000000002";

        expectedResponse.deactivatedMessage = "";

        // Add a captcha
        newUser['g-recaptcha-response'] = "A Captcha String";

        dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
          app.post('/api/1/users?access_token=' + accessToken.token).send(removeNonAdminAttributes(newUser)).expect('Content-Type', /json/).expect(200).end(function(err, res) {
            if(err) {
              done(err);
            } else {
              var responseObj = res.body;

              // Make sure the response is valid.
              dm.validateResponseObject(responseObj);

              // Make sure lastUpdatedBy field is correctly populated.
              expectedResponse.lastUpdatedBy = developerUserId;
              expectedResponse.roles = [ '300000000000000000000002' ];

              // Ensure the created user is exactly what we posted to the server.
              compareUserToResponse(responseObj.response, expectedResponse);

              validateUsers(responseObj.response, developerRole, developerUserId, function(err) {
                done(err);
              });
            }
          });
        });
      });

      it('by an anonymous user with a captcha', function(done) {
        var newUser = data.User.getNew(),
            expectedResponse = data.User.getNew();

        expectedResponse.deactivatedMessage = "";

        // Add a captcha
        newUser['g-recaptcha-response'] = "A Captcha String";

        app.post('/api/1/users?access_token=InvalidAccessToken').send(removeNonAdminAttributes(newUser)).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Make sure lastUpdatedBy field is correctly populated.
            expectedResponse.lastUpdatedBy = undefined;  //TODO: This should be the new user id.
            expectedResponse.roles = [ '300000000000000000000002' ];

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, expectedResponse);

            validateUsers(responseObj.response, oemRole, newUser._id, function(err) {
              done(err);
            });
          }
        });
      });

    });

    describe('cannot be created', function() {

      it('by an OEM without a captcha', function(done) {
        var newUser = data.User.getNew(),
          oemUserId = "000000000000000000000001";

        dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
          app.post('/api/1/users?access_token=' + accessToken.token).send(removeNonAdminAttributes(newUser)).expect('Content-Type', /json/).expect(400).end(function(err, res) {
            if(err) {
              done(err);
            } else {
              dm.validateBadRequestObject(res.body, 'server.error.badRecaptchaToken');
              done();
            }
          });
        });
      });

      it('by a Developer without a captcha', function(done) {
        var newUser = data.User.getNew(),
          developerUserId = "000000000000000000000002";

        dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
          app.post('/api/1/users?access_token=' + accessToken.token).send(removeNonAdminAttributes(newUser)).expect('Content-Type', /json/).expect(400).end(function(err, res) {
            if(err) {
              done(err);
            } else {
              dm.validateBadRequestObject(res.body, 'server.error.badRecaptchaToken');
              done();
            }
          });
        });
      });

    });


    /* ************************************************** *
     * ******************** Update
     * ************************************************** */

    describe('can be updated', function() {

      it('by an admin', function(done) {
        var user = data.User.getAll()[2],
          newUser = data.User.getNew();

        delete newUser._id;

        app.put('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).send(newUser).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created SDL server is exactly what we posted to the server.
            newUser._id = user._id;
            compareUserToResponse(responseObj.response, newUser, true);

            validateUser(responseObj.response, adminRole, user._id, function(err) {
              done(err);
            });
          }
        });
      });

      it('by an OEM if it is their own account and only non-admin attributes', function(done) {
        var expectedResponse = data.User.getNew(),
            newUser = data.User.getNew(),
            oemUserId = '000000000000000000000001';

        data.User.findById(oemUserId, function(err, user) {
          if(err) {
            done(err);
          } else {

            newUser = removeNonAdminAttributes(newUser, true);
            delete newUser._id;

            dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
              app.put('/api/1/users/' + user._id + '?access_token=' + accessToken.token).send(newUser).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                if(err) {
                  done(err);
                } else {
                  var responseObj = res.body;

                  // Make sure the response is valid.
                  dm.validateResponseObject(responseObj);

                  // Ensure the updated user is exactly what we posted to the server.
                  expectedResponse._id = user._id;
                  compareUserToResponse(responseObj.response, newUser, false, user, true);

                  validateUser(responseObj.response, oemRole, oemUserId, function(err) {
                    done(err);
                  });
                }
              });
            });
          }
        });
      });

      it('by a Developer if it is their own account and only non-admin attributes', function(done) {
        var expectedResponse = data.User.getNew(),
          newUser = data.User.getNew(),
          developerUserId = '000000000000000000000002';

        data.User.findById(developerUserId, function(err, user) {
          if(err) {
            done(err);
          } else {

            newUser = removeNonAdminAttributes(newUser, true);
            delete newUser._id;

            dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
              app.put('/api/1/users/' + user._id + '?access_token=' + accessToken.token).send(newUser).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                if(err) {
                  done(err);
                } else {
                  var responseObj = res.body;

                  // Make sure the response is valid.
                  dm.validateResponseObject(responseObj);

                  // Ensure the updated user is exactly what we posted to the server.
                  newUser._id = user._id;
                  compareUserToResponse(responseObj.response, newUser, false, user, true);

                  validateUser(responseObj.response, developerRole, developerUserId, function(err) {
                    done(err);
                  });
                }
              });
            });
          }
        });
      });

    });

    describe('cannot be updated', function() {

      it('by an OEM if it is not their account', function(done) {
        var user = data.User.getAll()[0],
          newUser = data.User.getNew(),
          oemUserId = '000000000000000000000001';

        // Make sure we are not updating the same user.
        assert.notEqual(user._id, oemUserId);

        newUser = removeNonAdminAttributes(newUser, true);
        delete newUser._id;

        dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
          app.put('/api/1/users/' + user._id + '?access_token=' + accessToken.token).send(newUser).expect('Content-Type', /json/).expect(403).end(function(err, res) {
            if(err) {
              done(err);
            } else {
              dm.validateForbiddenObject(res.body);
              done();
            }
          });
        });
      });

      it('by a Developer if it is not their account', function(done) {
        var user = data.User.getAll()[0],
          newUser = data.User.getNew(),
          developerUserId = '000000000000000000000002';

        // Make sure we are not updating the same user.
        assert.notEqual(user._id, developerUserId);

        newUser = removeNonAdminAttributes(newUser, true);
        delete newUser._id;

        dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
          app.put('/api/1/users/' + user._id + '?access_token=' + accessToken.token).send(newUser).expect('Content-Type', /json/).expect(403).end(function(err, res) {
            if(err) {
              done(err);
            } else {
              dm.validateForbiddenObject(res.body);
              done();
            }
          });
        });
      });

      it('by an anonymous user', function(done) {
        var user = data.User.getAll()[0],
            newUser = data.User.getNew();

        newUser = removeNonAdminAttributes(newUser, true);
        delete newUser._id;

        app.put('/api/1/users/' + user._id + '?access_token=InvalidAccessToken').send(newUser).expect('Content-Type', /json/).expect(401).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateErrorObject(res.body);
            done();
          }
        });
      });

      it('with an invalid ObjectId', function(done) {
        var user = data.User.getAll()[0],
          newUser = data.User.getNew(),
          adminUserId = "000000000000000000000000";

        newUser = removeNonAdminAttributes(newUser, true);
        delete newUser._id;

        dm.getUserAccessToken(data, adminUserId, function(err, accessToken) {
          app.put('/api/1/users/INVALID_USER_ID?access_token=' + accessToken.token).send(newUser).expect('Content-Type', /json/).expect(400).end(function(err, res) {
            if(err) {
              done(err);
            } else {
              dm.validateBadRequestObject(res.body, 'server.error.invalidObjectId');
              done();
            }
          });
        });
      });

    });

    describe('some attributes cannot be updated ', function() {

      it('by an OEM', function(done) {
        var forbiddenAttributes = [ 'applications', 'dateCreated', 'deleted', 'deactivatedMessage', 'failedLoginAttempts', 'lastLogin', 'lastUpdated', 'lastUpdatedBy', 'passwordHash', 'passwordResetHash', 'requestedOemAccess', 'roles', 'securityAnswerHash', 'sdlServers', 'username'],
          newUser = data.User.getNew(),
          oemUserId = '000000000000000000000001';

        newUser.passwordHash = "passwordHash";
        newUser.securityAnswerHash = "securityAnswerHash";
        newUser.passwordResetHash = "passwordResetHash";

        data.User.findById(oemUserId, function(err, user) {
          if(err) {
            done(err);
          } else if( ! user) {
            cb(new Error("User with ID "+oemUserId+" was not found."));
          } else {
            dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
              if(err) {
                done(err);
              } else {
                var tasks = [];
                for(var i = 0; i < forbiddenAttributes.length; i++) {
                  var updateObject = {};
                  if(newUser[forbiddenAttributes[i]] === undefined) {
                    throw new Error("Update object does not contain a forbidden attribute to test: " + forbiddenAttributes[i]);
                  }
                  updateObject[forbiddenAttributes[i]] = newUser[forbiddenAttributes[i]];
                  tasks.push(updateForbiddenAttributeMethod(user, updateObject, accessToken));
                }

                async.series(tasks, function(err, results) {
                  done(err);
                });
              }
            });
          }
        });
      });

    });

    describe('can be activated', function() {

      it('by an admin', function(done) {
        var user = data.User.getAll()[7];

        // Make sure the user is deactivated.
        assert.equal(user.activated, false);

        var body = {
          activated: true
        };

        app.put('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).send(body).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            user.activated = true;
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, user._id, function(err) {
              done(err);
            });
          }
        });
      });

    });

    describe('can be deactivated', function() {

      it('by an admin', function(done) {
        var user = data.User.getAll()[2];

        // Make sure the user is activated.
        assert.equal(user.activated, true);

        var body = {
          activated: false
        };

        app.put('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).send(body).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            user.activated = false;
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, user._id, function(err) {
              done(err);
            });
          }
        });
      });

    });


    /* ************************************************** *
     * ******************** Delete
     * ************************************************** */

    describe('can be deleted', function() {

      it('by an admin', function(done) {
        var user = data.User.getAll()[0];

        app.delete('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);

            // Ensure the created application is exactly what we posted to the server.
            user.deleted = true;
            compareUserToResponse(responseObj.response, user, true);

            validateUsers(responseObj.response, adminRole, undefined, function(err) {
              done(err);
            });
          }
        });
      });

      it('by an OEM if it is their own user account.', function(done) {
        var oemUserId = "000000000000000000000001";

        data.User.findById(oemUserId, function(err, user) {
          if(err) {
            done(err);
          } else {
            dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
              if(err) {
                done(err);
              } else {
                app.delete('/api/1/users/' + user._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseObj = res.body;

                    dm.validateResponseObject(responseObj);

                    // Ensure the created user is exactly what we posted to the server.
                    user.delete = true;
                    compareUserToResponse(responseObj.response, user);

                    validateUsers(responseObj.response, oemRole, oemUserId, function(err) {
                      done(err);
                    });
                  }
                });
              }
            });
          }
        });
      });

      it('by an Developer if it is their own user account.', function(done) {
        var developerUserId = "000000000000000000000002";

        data.User.findById(developerUserId, function(err, user) {
          if(err) {
            done(err);
          } else {
            dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
              if(err) {
                done(err);
              } else {
                app.delete('/api/1/users/' + user._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseObj = res.body;

                    dm.validateResponseObject(responseObj);

                    // Ensure the created user is exactly what we posted to the server.
                    user.delete = true;
                    compareUserToResponse(responseObj.response, user);

                    validateUsers(responseObj.response, developerRole, developerUserId, function(err) {
                      done(err);
                    });
                  }
                });
              }
            });
          }
        });
      });

    });

    describe('cannot be deleted', function() {

      it('by an OEM if it is not their user account.', function(done) {
        var oemUserId = "000000000000000000000001",
            otherUserId = "000000000000000000000003";

        data.User.findById(otherUserId, function(err, user) {
          if(err) {
            done(err);
          } else {
            dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
              if(err) {
                done(err);
              } else {
                app.delete('/api/1/users/' + user._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    dm.validateForbiddenObject(res.body);
                    done();
                  }
                });
              }
            });
          }
        });
      });

      it('by a Developer if it is not their user account.', function(done) {
        var developerUserId = "000000000000000000000002",
            otherUserId = "000000000000000000000001";

        data.User.findById(otherUserId, function(err, user) {
          if(err) {
            done(err);
          } else {
            dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
              if(err) {
                done(err);
              } else {
                app.delete('/api/1/users/' + user._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    dm.validateForbiddenObject(res.body);
                    done();
                  }
                });
              }
            });
          }
        });
      });

      it('by an anonymous user', function(done) {
        var user = data.User.getAll()[0];
        app.delete('/api/1/users/' + user._id + '?access_token=InvalidAccessToken').expect('Content-Type', /json/).expect(401).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateUnauthorized(res.body);
            done();
          }
        });
      });

      it('by an OEM if their account is already deleted', function(done) {
        var oemUserId = "000000000000000000000001";

        dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
          if(err) {
            done(err);
          } else {
            app.delete('/api/1/users/' + oemUserId + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(200).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                app.delete('/api/1/users/' + oemUserId + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(404).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    dm.validateNotFoundObject(res.body);
                    done();
                  }
                });
              }
            });
          }
        });
      });

    });


    /* ************************************************** *
     * ******************** Purge
     * ************************************************** */

    describe('can be purged', function() {

      it('by an admin.', function(done) {
        var user = data.User.getAll()[1];

        app.delete('/api/1/users/' + user._id + '/purge?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateResponseObject(res.body);

            // Make sure the user is deleted.
            app.get('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(404).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                dm.validateNotFoundObject(res.body);
                done();
              }
            });
          }
        });
      });

    });

    describe('cannot be purged', function() {

      it('by an admin, if the user is the admin\'s own account.', function(done) {
        var adminUserId = "000000000000000000000000";

        data.User.findById(adminUserId, function(err, user) {
          if(err) {
            done(err);
          } else {

            app.delete('/api/1/users/' + adminUserId + '/purge?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(403).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                dm.validateForbiddenObject(res.body, 'server.error.permissionDeniedPurgeUser');

                // Make sure the user is not deleted.
                app.get('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseObj = res.body;

                    dm.validateResponseObject(responseObj);

                    // Ensure the queried user is exactly what we expect.
                    compareUserToResponse(responseObj.response, user, true);

                    validateUsers(responseObj.response, adminRole, undefined, function(err) {
                      done(err);
                    });
                  }
                });
              }
            });
          }
        });
      });

      it('by a non-admin user trying to purge their own account.', function(done) {
        var oemUserId = "000000000000000000000001";  // Developer

        data.User.findById(oemUserId, function(err, user) {
          if(err) {
            done(err);
          } else {
            dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
              if(err) {
                done(err);
              } else {
                app.delete('/api/1/users/' + user._id + '/purge?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    dm.validateForbiddenObject(res.body);
                    done();
                  }
                });
              }
            });
          }
        });
      });

      it('by a non-admin user trying to purge someone else\'s account. ', function(done) {
        var oemUserId = "000000000000000000000001",
            otherUserId = "000000000000000000000002";

        data.User.findById(otherUserId, function(err, user) {
          if(err) {
            done(err);
          } else {
            dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
              if(err) {
                done(err);
              } else {
                app.delete('/api/1/users/' + user._id + '/purge?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    dm.validateForbiddenObject(res.body);
                    done();
                  }
                });
              }
            });
          }
        });
      });

      it('by an anonymous user', function(done) {
        var user = data.User.getAll()[0];

        app.delete('/api/1/users/' + user._id + '/purge?access_token=InvalidAccessToken').expect('Content-Type', /json/).expect(401).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateUnauthorized(res.body);
            done();
          }
        });
      });

    });


    /* ************************************************** *
     * ******************** Authentication
     * ************************************************** */

    describe('can login', function() {

      it('with the correct username and password', function(done) {
        var user = data.User.getNew();

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {

                app.post('/api/1/login').send({ username: user.username, password: user.password }).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseBody = res.body;

                    // Make sure the response is valid.
                    dm.validateResponseObject(responseBody);

                    // Redirect should default to applications page.
                    assert.equal(responseBody.response.redirect, '/applications');

                    done();
                  }
                });

              }
            });
          }
        });
      });

      it('with an uppercase username', function(done) {
        var user = data.User.getNew();

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {
                app.post('/api/1/login').send({ username: user.username.toUpperCase(), password: user.password }).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseBody = res.body;

                    // Make sure the response is valid.
                    dm.validateResponseObject(responseBody);

                    // Redirect should default to applications page.
                    assert.equal(responseBody.response.redirect, '/applications');

                    done();
                  }
                });

              }
            });
          }
        });
      });

    });

    describe('cannot login', function() {

      it('with an incorrect username or password', function(done) {
        var user = data.User.getNew();

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {

                app.post('/api/1/login').send({ username: 'invalidUserName', password: user.password }).expect('Content-Type', /json/).expect(400).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    dm.validateUnauthorized(res.body, 'server.error.invalidUsername');

                    app.post('/api/1/login').send({ username: user.username, password: 'invalidPassword' }).expect('Content-Type', /json/).expect(400).end(function(err, res) {
                      if(err) {
                        done(err);
                      } else {
                        dm.validateUnauthorized(res.body, 'server.error.invalidPassword');
                        done();
                      }
                    });
                  }
                });

              }
            });
          }
        });
      });

      it('if the user account is deactivated', function(done) {
        var user = data.User.getNew();

        user.activated = false;

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {

                app.post('/api/1/login').send({ username: user.username, password: user.password }).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    dm.validateUnauthorized(res.body, 'server.error.deactivated');

                    done();
                  }
                });
              }
            });
          }
        });
      });

    });

    describe('can logout', function() {

      it('if the user is already logged in', function(done) {
        var user = data.User.getNew();

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {

                app.post('/api/1/login').send({ username: user.username, password: user.password }).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseBody = res.body;

                    // Make sure the response is valid.
                    dm.validateResponseObject(responseBody);

                    // Redirect should default to applications page.
                    assert.equal(responseBody.response.redirect, '/applications');

                    app.post('/api/1/logout').send().expect(200).end(function(err, res) {
                      if(err) {
                        done(err);
                      } else {
                        var responseBody = res.body;

                        // Make sure the response is valid.
                        dm.validateResponseObject(responseBody);

                        assert.equal(responseBody.response, true);

                        done();
                      }
                    });
                  }
                });
              }
            });
          }
        });
      });

    });

    describe('with too many failed logins', function() {

      it('are deactivated after a set number of attempts', function(done) {
        var user = data.User.getNew();

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {

                user.password = "Invalid Password";

                performUnsuccessfulLoginAttempts(user, config.authentication.failedLoginAttempts.deactivate - 1, createInvalidPasswordValidationMethod, 400, true, function(err, results) {
                  if(err) {
                    done(err);
                  } else {

                    var obj = {
                      username: user.username,
                      password: user.password
                    };

                    obj['g-recaptcha-response'] = "LookACaptcha";

                    app.post('/api/1/login').send(obj).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                      if(err) {
                        done(err);
                      } else {
                        dm.validateUnauthorized(res.body, 'server.error.deactivated');

                        assert.equal(res.body.captchaRequired, true);

                        done();
                      }
                    });
                  }
                });
              }
            });
          }
        });
      });

      it('require a captcha after a set number of attempts', function(done) {
        var user = data.User.getNew();

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {

                user.password = "Invalid Password";

                performUnsuccessfulLoginAttempts(user, config.authentication.failedLoginAttempts.recaptchaRequired, createInvalidPasswordValidationMethod, 400, false, function(err, results) {
                  if(err) {
                    done(err);
                  } else {

                    app.post('/api/1/login').send({ username: user.username, password: user.password }).expect('Content-Type', /json/).expect(400).end(function(err, res) {
                      if(err) {
                        done(err);
                      } else {
                        dm.validateUnauthorized(res.body, 'server.error.badRecaptchaToken');

                        // Make sure the captcha required field is set.
                        assert.equal(res.body.captchaRequired, true);

                        done();
                      }
                    });
                  }
                });
              }
            });
          }
        });
      });

    });

    describe('can request a password reset', function() {

      it('if the user has an email address on record and provides a valid username.', function(done) {
        var user = data.User.getNew();

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {

                app.post('/api/1/passwordReset').send({ 'g-recaptcha-response': "InvalidCaptcha", username: user.username }).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseBody = res.body;

                    // Make sure the response is valid.
                    dm.validateResponseObject(responseBody);

                    // A redirect url should not be present, since it is emailed to the user.
                    assert.equal(res.body.response.redirect, undefined);

                    // A message explaining to the client to check their email should be present.
                    assert.equal(res.body.response.message, i18n.t('server.user.passwordResetEmailSent'));

                    done();
                  }
                });

              }
            });
          }
        });
      });

      it('if the user does not have an email address on record and provides a valid username.', function(done) {
        var user = data.User.getNew();

        user.email = undefined;

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        // Make sure the email is not defined.
        assert.equal(user.email, undefined);

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {

                app.post('/api/1/passwordReset').send({ 'g-recaptcha-response': "InvalidCaptcha", username: user.username }).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseBody = res.body;

                    // Make sure the response is valid.
                    dm.validateResponseObject(responseBody);

                    // A redirect url should be present for the client to be redirected.
                    assert.notEqual(res.body.response.redirect, undefined);

                    // A message should not be present.
                    assert.equal(res.body.response.message, undefined);

                    done();
                  }
                });

              }
            });
          }
        });
      });

    });

    describe('can perform a password reset', function() {

      it('if the user has a valid security answer and new password.', function(done) {
        var user = data.User.getNew(),
            newPassword = "NewPassword";

        user.email = undefined;

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        // Make sure the email is not defined.
        assert.equal(user.email, undefined);

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {

                app.post('/api/1/passwordReset').send({ 'g-recaptcha-response': "InvalidCaptcha", username: user.username }).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseBody = res.body;

                    // Make sure the response is valid.
                    dm.validateResponseObject(responseBody);

                    // A redirect url should be present if the user does not have an email address.
                    assert.notEqual(res.body.response.redirect, undefined);

                    var passwordResetToken = getParameterByName(res.body.response.redirect, 'passwordReset');

                    app.post('/api/1/passwordReset/' + user._id + "?passwordReset=" + passwordResetToken).send({ securityAnswer: user.securityAnswer, password: newPassword }).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                      if(err) {
                        done(err);
                      } else {
                        var responseBody = res.body;

                        // Make sure the response is valid.
                        dm.validateResponseObject(responseBody);

                        app.post('/api/1/login').send({
                          username: user.username,
                          password: newPassword
                        }).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                          if(err) {
                            done(err);
                          } else {
                            var responseBody = res.body;

                            // Make sure the response is valid.
                            dm.validateResponseObject(responseBody);

                            // Redirect should default to applications page.
                            assert.equal(responseBody.response.redirect, '/applications');

                            done();
                          }
                        });
                      }
                    });
                  }
                });
              }
            });
          }
        });
      });

    });

    describe('cannot perform a password reset', function() {

      it('if the user has an invalid security answer and new password', function(done) {
        var user = data.User.getNew(),
          newPassword = "NewPassword";

        user.email = undefined;

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        // Make sure the email is not defined.
        assert.equal(user.email, undefined);

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {

                app.post('/api/1/passwordReset').send({ 'g-recaptcha-response': "InvalidCaptcha", username: user.username }).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseBody = res.body;

                    // Make sure the response is valid.
                    dm.validateResponseObject(responseBody);

                    // A redirect url should be present if the user does not have an email address.
                    assert.notEqual(res.body.response.redirect, undefined);

                    //var passwordResetToken = getParameterByName(res.body.response.redirect, 'passwordReset');

                    app.post('/api/1/passwordReset/' + user._id + "?passwordReset=InvalidPasswordResetToken").send({ securityAnswer: user.securityAnswer, password: newPassword }).expect('Content-Type', /json/).expect(400).end(function(err, res) {
                      if(err) {
                        done(err);
                      } else {
                        // Make sure the response is valid.
                        dm.validateBadRequestObject(res.body, 'server.error.invalidSecurityAnswer');

                        app.post('/api/1/login').send({
                          username: user.username,
                          password: newPassword
                        }).expect('Content-Type', /json/).expect(400).end(function(err, res) {
                          if(err) {
                            done(err);
                          } else {
                            // Make sure the response is valid.
                            dm.validateBadRequestObject(res.body, 'server.error.invalidPassword');
                            done();
                          }
                        });
                      }
                    });
                  }
                });
              }
            });
          }
        });
      });

      it('if the user is deactivated', function(done) {
        var user = data.User.getNew(),
          newPassword = "NewPassword";

        user.email = undefined;
        user.activated = false;

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        // Make sure the email is not defined.
        assert.equal(user.email, undefined);

        // Make sure the user is deactivated
        assert.equal(user.activated, false);

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {

                app.post('/api/1/passwordReset').send({ 'g-recaptcha-response': "InvalidCaptcha", username: user.username }).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseBody = res.body;

                    // Make sure the response is valid.
                    dm.validateResponseObject(responseBody);

                    // A redirect url should be present if the user does not have an email address.
                    assert.notEqual(res.body.response.redirect, undefined);

                    //var passwordResetToken = getParameterByName(res.body.response.redirect, 'passwordReset');

                    app.post('/api/1/passwordReset/' + user._id + "?passwordReset=InvalidPasswordResetToken").send({ securityAnswer: user.securityAnswer, password: newPassword }).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                      if(err) {
                        done(err);
                      } else {
                        dm.validateBadRequestObject(res.body, 'server.error.deactivated');

                        app.post('/api/1/login').send({
                          username: user.username,
                          password: newPassword
                        }).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                          if(err) {
                            done(err);
                          } else {
                            // Make sure the response is valid.
                            dm.validateBadRequestObject(res.body, 'server.error.deactivated');
                            done();
                          }
                        });
                      }
                    });
                  }
                });
              }
            });
          }
        });
      });

    });

    describe('can validate a username', function() {

      it('if the username is defined and not a duplicate.', function(done) {
        app.post('/api/1/validateUsername').send({username: "myUsername"}).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            assert.equal(responseObj.response, true);

            done();
          }
        });
      });

      it('if the username is defined and a duplicate', function(done) {
        app.post('/api/1/validateUsername').send({username: "admin"}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);
            dm.validateBadRequestObject(responseObj, 'server.error.duplicateUsername');

            // Check for case sensitivity.
            app.post('/api/1/validateUsername').send({username: "Admin"}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                var responseObj = res.body;

                dm.validateResponseObject(responseObj);
                dm.validateBadRequestObject(responseObj, 'server.error.duplicateUsername');

                done();
              }
            });
          }
        });
      });

      it('if the username is defined and has spaces', function(done) {
        app.post('/api/1/validateUsername').send({username: "this username is invalid"}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);
            dm.validateBadRequestObject(responseObj, 'server.error.invalidUsernameHasSpaces');

            done();
          }
        });
      });

      it('if the username is defined and is too damn long', function(done) {
        var username = "";
        for(var i = 0; i < 600; i++) {
            username += "a";
        }

        app.post('/api/1/validateUsername').send({username: username}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);
            dm.validateBadRequestObject(responseObj, 'server.error.invalidUsernameTooDamnLong');

            done();
          }
        });
      });

      it('if the username is too damn long', function(done) {
        app.post('/api/1/validateUsername').send({username: "too damn long"}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);
            dm.validateBadRequestObject(responseObj, 'server.error.invalidUsernameTooDamnLong');

            done();
          }
        });
      });

      it('if the username is an email', function(done) {
        app.post('/api/1/validateUsername').send({username: "myemail@emailplace.com"}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);
            dm.validateBadRequestObject(responseObj, 'server.error.invalidUsernameEmailAddress');

            done();
          }
        });
      });

    });

    describe('can validate an email', function() {

      it('if the email is defined and not a duplicate.', function(done) {
        app.post('/api/1/validateEmail').send({email: "myEmail@email.com"}).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            assert.equal(responseObj.response, true);

            done();
          }
        });
      });

      it('if the email is defined and a duplicate.', function(done) {
        var user = data.User.getAll()[0];

        app.post('/api/1/validateEmail').send({email: user.email}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);
            dm.validateBadRequestObject(responseObj, 'server.error.duplicateEmail');

            // Check for case sensitivity.
            app.post('/api/1/validateEmail').send({email: user.email.toUpperCase()}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                var responseObj = res.body;

                dm.validateResponseObject(responseObj);
                dm.validateBadRequestObject(responseObj, 'server.error.duplicateEmail');

                done();
              }
            });
          }
        });
      });

      it('if the email is defined and has spaces.', function(done) {
        app.post('/api/1/validateEmail').send({email: "email @email.com"}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);
            dm.validateBadRequestObject(responseObj, 'server.error.invalidEmailHasSpaces');

            done();
          }
        });
      });

      it('if the email is defined and is too damn long.', function(done) {
        var email = "";
        for(var i = 0; i < 590; i++) {
          email += "a";
        }
        email += "@email.com";

        app.post('/api/1/validateEmail').send({email: email}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);
            dm.validateBadRequestObject(responseObj, 'server.error.invalidEmailTooDamnLong');

            done();
          }
        });
      });

      it('if the email is not in a valid email address format', function(done) {
        app.post('/api/1/validateEmail').send({email: "blah@blah"}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);
            dm.validateBadRequestObject(responseObj, 'server.error.invalidEmail');

            done();
          }
        });
      });

    });

    describe('can validate a username or email', function() {

      it('if an email is defined', function(done) {
        var user = data.User.getAll()[0];
        app.post('/api/1/validateUsernameOrEmail').send({usernameOrEmail: user.email}).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            assert.equal(responseObj.response, true);

            done();
          }
        });
      });

      it('if a username is defined', function(done) {
        var user = data.User.getAll()[0];
        app.post('/api/1/validateUsernameOrEmail').send({usernameOrEmail: user.username}).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            assert.equal(responseObj.response, true);

            done();
          }
        });
      });

      it('if an email is invalid', function(done) {
        app.post('/api/1/validateUsernameOrEmail').send({usernameOrEmail: "invalidemail@address.com"}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateBadRequestObject(res.body, 'server.error.invalidEmail');
            done();
          }
        });
      });

      it('if an email is undefined', function(done) {
        app.post('/api/1/validateUsernameOrEmail').send({usernameOrEmail: ""}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateBadRequestObject(res.body, 'server.error.invalidUsername');
            done();
          }
        });
      });

      it('if a username is invalid', function(done) {
        app.post('/api/1/validateUsernameOrEmail').send({usernameOrEmail: "invalidUsername"}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateBadRequestObject(res.body, 'server.error.invalidUsername');
            done();
          }
        });
      });

      it('if a username is undefined', function(done) {
        app.post('/api/1/validateUsernameOrEmail').send({usernameOrEmail: ""}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateBadRequestObject(res.body, 'server.error.invalidUsername');
            done();
          }
        });
      });

    });

    describe('can set a new password', function() {

      it('if the authenticated user is an admin and the new password is valid', function(done) {
        var user = data.User.getNew();

        user.password = "originalPassword";

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            // Make sure the response is valid.
            dm.validateResponseObject(responseObj);

            // Ensure the created user is exactly what we posted to the server.
            compareUserToResponse(responseObj.response, user, true);

            validateUser(responseObj.response, adminRole, undefined, function(err) {
              if(err) {
                done(err);
              } else {

                app.post('/api/1/users/' + user._id + '/setPassword?access_token=' + adminAccessToken).send({password: 'newPassword'}).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseBody = res.body;

                    // Make sure the response is valid.
                    dm.validateResponseObject(responseBody);

                    user.password = 'newPassword';
                    performSuccessfulLoginAttempts(user, 1, undefined, function(err, body) {
                      done(err);
                    });
                  }
                });
              }
            });
          }
        });
      });

    });

    describe('cannot set a new password', function() {

      it('if the authenticated user is an oem and the new password is valid', function(done) {
        var user = data.User.getNew(),
          oldPassword = 'password1',
          newPassword = 'password2';

        user.roles = [ "300000000000000000000001" ];
        user.password = oldPassword;

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        dm.getUserAccessToken(data, user._id, function(err, accessToken) {
          if(err) {
            done(err);
          } else {
            app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                var responseObj = res.body;

                // Make sure the response is valid.
                dm.validateResponseObject(responseObj);

                // Ensure the created user is exactly what we posted to the server.
                compareUserToResponse(responseObj.response, user, true);

                validateUser(responseObj.response, adminRole, undefined, function(err) {
                  if(err) {
                    done(err);
                  } else {

                    app.post('/api/1/users/' + user._id + '/setPassword?access_token=' + accessToken.token).send({password: newPassword}).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                      if(err) {
                        done(err);
                      } else {
                        dm.validateForbiddenObject(res.body);

                        user.password = oldPassword;
                        performSuccessfulLoginAttempts(user, 1, undefined, function(err, body) {
                          done(err);
                        });
                      }
                    });
                  }
                });
              }
            });
          }
        });
      });

      it('if the authenticated user is a developer and the new password is valid', function(done) {
        var user = data.User.getNew(),
          oldPassword = 'password1',
          newPassword = 'password2';

        user.roles = [ "300000000000000000000002" ];
        user.password = oldPassword;

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        dm.getUserAccessToken(data, user._id, function(err, accessToken) {
          if(err) {
            done(err);
          } else {
            app.post('/api/1/users?access_token=' + adminAccessToken).send(user).expect('Content-Type', /json/).expect(200).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                var responseObj = res.body;

                // Make sure the response is valid.
                dm.validateResponseObject(responseObj);

                // Ensure the created user is exactly what we posted to the server.
                compareUserToResponse(responseObj.response, user, true);

                validateUser(responseObj.response, adminRole, undefined, function(err) {
                  if(err) {
                    done(err);
                  } else {

                    app.post('/api/1/users/' + user._id + '/setPassword?access_token=' + accessToken.token).send({password: newPassword}).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                      if(err) {
                        done(err);
                      } else {
                        dm.validateForbiddenObject(res.body);

                        user.password = oldPassword;
                        performSuccessfulLoginAttempts(user, 1, undefined, function(err, body) {
                          done(err);
                        });
                      }
                    });
                  }
                });
              }
            });
          }
        });
      });

      it('if the authenticated user is anonymous and the new password is valid', function(done) {
        var user = data.User.getAll()[0],
          oldPassword = 'password1',
          newPassword = 'password2';

        user.password = oldPassword;

        // Make sure the username and password are defined.
        assert.notEqual(user.username, undefined);
        assert.notEqual(user.password, undefined);

        app.post('/api/1/users/' + user._id + '/setPassword?access_token=InvalidAccessToken').send({password: newPassword}).expect('Content-Type', /json/).expect(401).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateUnauthorized(res.body);
            done();
          }
        });
      });

    });


    /* ************************************************** *
     * ******************** Request Resource Access
     * ************************************************** */

    describe('can request', function() {

      it('the oem role for themselves if they are logged in.', function(done) {
        var developerUserId = '000000000000000000000002',
          resources = 'oemRole';

        data.User.findById(developerUserId, function(err, user) {
          if(err) {
            done(err);
          } else {

            // Make sure the user does not already have the OEM role.
            assert.equal(user.roles.indexOf('300000000000000000000001'), -1);

            // Make sure the user's requestedOemAccess is disabled.
            assert.equal(user.requestedOemAccess, false);

            dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
              app.post('/api/1/users/' + user._id + '/requestAccess?access_token=' + accessToken.token).send({ resources: resources}).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                if(err) {
                  done(err);
                } else {
                  var responseBody = res.body;

                  // Make sure the response is valid.
                  dm.validateResponseObject(responseBody);

                  // Make sure the response indicates success.
                  assert.equal(_.isArray(responseBody.response), true);
                  assert.equal(responseBody.response.length, 1);
                  assert.equal(responseBody.response[0], true);

                  app.get('/api/1/users/' + user._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                    if(err) {
                      done(err);
                    } else {
                      var responseBody = res.body;

                      dm.validateResponseObject(responseBody);

                      // Make sure user does not have the OEM role.
                      assert.equal(responseBody.response.roles.indexOf('300000000000000000000001'), -1);

                      // Make sure the user's requestedOemAccess is now enabled.
                      assert.equal(responseBody.response.requestedOemAccess, true);

                      validateUsers(responseBody.response, developerRole, developerUserId, function(err) {
                        done(err);
                      });
                    }
                  });
                }
              });
            });
          }
        });
      });

      it('the oem role for themselves if they are logged in, using an array', function(done) {
        var developerUserId = '000000000000000000000002',
          resources = ['server'];

        data.User.findById(developerUserId, function(err, user) {
          if(err) {
            done(err);
          } else {

            // Make sure the user does not already have the OEM role.
            assert.equal(user.roles.indexOf('300000000000000000000001'), -1);

            // Make sure the user's requestedOemAccess is disabled.
            assert.equal(user.requestedOemAccess, false);

            dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
              app.post('/api/1/users/' + user._id + '/requestAccess?access_token=' + accessToken.token).send({ resources: resources}).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                if(err) {
                  done(err);
                } else {
                  var responseBody = res.body;

                  // Make sure the response is valid.
                  dm.validateResponseObject(responseBody);

                  // Make sure the response indicates success.
                  assert.equal(_.isArray(responseBody.response), true);
                  assert.equal(responseBody.response.length, 1);
                  assert.equal(responseBody.response[0], true);

                  app.get('/api/1/users/' + user._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                    if(err) {
                      done(err);
                    } else {
                      var responseBody = res.body;

                      dm.validateResponseObject(responseBody);

                      // Make sure user does not have the OEM role.
                      assert.equal(responseBody.response.roles.indexOf('300000000000000000000001'), -1);

                      // Make sure the user's requestedOemAccess is now enabled.
                      assert.equal(responseBody.response.requestedOemAccess, true);

                      validateUsers(responseBody.response, developerRole, developerUserId, function(err) {
                        done(err);
                      });
                    }
                  });
                }
              });
            });
          }
        });
      });

    });

    describe('cannot request', function() {

      it('the oem role for themselves if they have already requested it', function(done) {
        var developerUserId = '000000000000000000000005',
          resources = ['oemRole'];

        data.User.findById(developerUserId, function(err, user) {
          if(err) {
            done(err);
          } else {

            // Make sure the user does not already have the OEM role.
            assert.equal(user.roles.indexOf('300000000000000000000001'), -1);

            // Make sure the user's requestedOemAccess is enabled.
            assert.equal(user.requestedOemAccess, true);

            dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
              app.post('/api/1/users/' + user._id + '/requestAccess?access_token=' + accessToken.token).send({ resources: resources}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
                if(err) {
                  done(err);
                } else {
                  var responseBody = res.body;

                  dm.validateBadRequestObject(responseBody, 'server.error.accessAlreadyRequested');

                  app.get('/api/1/users/' + user._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                    if(err) {
                      done(err);
                    } else {
                      var responseBody = res.body;

                      dm.validateResponseObject(responseBody);

                      // Make sure user does not have the OEM role.
                      assert.equal(responseBody.response.roles.indexOf('300000000000000000000001'), -1);

                      // Make sure the user's requestedOemAccess is still enabled.
                      assert.equal(responseBody.response.requestedOemAccess, true);

                      validateUsers(responseBody.response, developerRole, developerUserId, function(err) {
                        done(err);
                      });
                    }
                  });
                }
              });
            });
          }
        });
      });

      it('the oem role for themselves if they have already have the oem role.', function(done) {
        var developerUserId = '000000000000000000000006',
          resources = ['oemRole'];

        data.User.findById(developerUserId, function(err, user) {
          if(err) {
            done(err);
          } else {

            // Make sure the user already have the OEM role.
            assert.notEqual(user.roles.indexOf('300000000000000000000001'), -1);

            // Make sure the user's requestedOemAccess is enabled.
            assert.equal(user.requestedOemAccess, false);

            dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
              app.post('/api/1/users/' + user._id + '/requestAccess?access_token=' + accessToken.token).send({ resources: resources}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
                if(err) {
                  done(err);
                } else {
                  var responseBody = res.body;

                  dm.validateBadRequestObject(responseBody, 'server.error.accessAlreadyGranted');

                  app.get('/api/1/users/' + user._id + '?access_token=' + accessToken.token).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                    if(err) {
                      done(err);
                    } else {
                      var responseBody = res.body;

                      dm.validateResponseObject(responseBody);

                      // Make sure user still has the OEM role.
                      assert.notEqual(responseBody.response.roles.indexOf('300000000000000000000001'), -1);

                      // Make sure the user's requestedOemAccess is still disabled.
                      assert.equal(responseBody.response.requestedOemAccess, false);

                      validateUsers(responseBody.response, developerRole, developerUserId, function(err) {
                        done(err);
                      });
                    }
                  });
                }
              });
            });
          }
        });
      });

      it('the oem role for another user, if they are not the admin', function(done) {
        var userId = '000000000000000000000005',
            developerUserId = '000000000000000000000002',
            resources = ['oemRole'];

        data.User.findById(userId, function(err, user) {
          if(err) {
            done(err);
          } else {
            data.User.findById(developerUserId, function(err, developer) {

              // Make sure the user does not have the OEM role.
              assert.equal(developer.roles.indexOf('300000000000000000000001'), -1);

              // Make sure the user's requestedOemAccess is enabled.
              assert.equal(developer.requestedOemAccess, false);

              dm.getUserAccessToken(data, userId, function(err, accessToken) {
                if(err) {
                  done(err);
                } else {
                  app.post('/api/1/users/' + developer._id + '/requestAccess?access_token=' + accessToken.token).send({resources: resources}).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                    if(err) {
                      done(err);
                    } else {
                      dm.validateForbiddenObject(res.body);

                      app.get('/api/1/users/' + developer._id + '?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                        if(err) {
                          done(err);
                        } else {
                          var responseBody = res.body;

                          dm.validateResponseObject(responseBody);

                          // Make sure user still does not have the OEM role.
                          assert.equal(responseBody.response.roles.indexOf('300000000000000000000001'), -1);

                          // Make sure the user's requestedOemAccess is still disabled.
                          assert.equal(responseBody.response.requestedOemAccess, false);

                          done();
                        }
                      });
                    }
                  });
                }
              });
            });
          }
        });
      });

      it('the oem role if they are not logged in.', function(done) {
        var developerUserId = '000000000000000000000005',
            resources = ['oemRole'];

        app.post('/api/1/users/' + developerUserId._id + '/requestAccess?access_token=InvalidAccessToken').send({ resources: resources}).expect('Content-Type', /json/).expect(401).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateUnauthorized(res.body);
            done();
          }
        });
      });

      it('unknown resources.', function(done) {
        var developerUserId = '000000000000000000000002',
          resources = ['blahblahblah'];

        dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
          app.post('/api/1/users/' + developerUserId + '/requestAccess?access_token=' + accessToken.token).send({ resources: resources}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
            if(err) {
              done(err);
            } else {
              dm.validateBadRequestObject(res.body, 'server.error.unknownResource');

              resources = [];
              app.post('/api/1/users/' + developerUserId + '/requestAccess?access_token=' + accessToken.token).send({resources: resources}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
                if(err) {
                  done(err);
                } else {
                  dm.validateBadRequestObject(res.body, 'server.error.badRequest');

                  resources = undefined;
                  app.post('/api/1/users/' + developerUserId + '/requestAccess?access_token=' + accessToken.token).send({resources: resources}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
                    if(err) {
                      done(err);
                    } else {
                      dm.validateBadRequestObject(res.body, 'server.error.badRequest');

                      done();
                    }
                  });
                }
              });
            }
          });
        });
      });

    });

    describe('can grant', function() {

      it('the oem role to a user if they are an admin.', function(done) {
        var developerUserId = '000000000000000000000005',
          resources = 'oemRole';

        data.User.findById(developerUserId, function(err, user) {
          if(err) {
            done(err);
          } else {

            // Make sure the user does not already have the OEM role.
            assert.equal(user.roles.indexOf('300000000000000000000001'), -1);

            // Make sure the user's requestedOemAccess is enabled.
            assert.equal(user.requestedOemAccess, true);

            app.post('/api/1/users/' + user._id + '/grantAccess?access_token=' + adminAccessToken).send({ resources: resources}).expect('Content-Type', /json/).expect(200).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                var responseBody = res.body;

                // Make sure the response is valid.
                dm.validateResponseObject(responseBody);

                // Make sure the response indicates success.
                assert.equal(_.isArray(responseBody.response), true);
                assert.equal(responseBody.response.length, 1);
                assert.equal(responseBody.response[0], true);

                app.get('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseBody = res.body;

                    dm.validateResponseObject(responseBody);

                    // Make sure user now has the OEM role.
                    assert.notEqual(responseBody.response.roles.indexOf('300000000000000000000001'), -1);

                    // Make sure the user's requestedOemAccess is now disabled.
                    assert.equal(responseBody.response.requestedOemAccess, false);

                    done();
                  }
                });
              }
            });
          }
        });
      });

      it('the oem role to a user if they are an admin, using a resources array', function(done) {
        var developerUserId = '000000000000000000000005',
          resources = ['oemRole'];

        data.User.findById(developerUserId, function(err, user) {
          if(err) {
            done(err);
          } else {

            // Make sure the user does not already have the OEM role.
            assert.equal(user.roles.indexOf('300000000000000000000001'), -1);

            // Make sure the user's requestedOemAccess is enabled.
            assert.equal(user.requestedOemAccess, true);

            app.post('/api/1/users/' + user._id + '/grantAccess?access_token=' + adminAccessToken).send({ resources: resources}).expect('Content-Type', /json/).expect(200).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                var responseBody = res.body;

                // Make sure the response is valid.
                dm.validateResponseObject(responseBody);

                // Make sure the response indicates success.
                assert.equal(_.isArray(responseBody.response), true);
                assert.equal(responseBody.response.length, 1);
                assert.equal(responseBody.response[0], true);

                app.get('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseBody = res.body;

                    dm.validateResponseObject(responseBody);

                    // Make sure user now has the OEM role.
                    assert.notEqual(responseBody.response.roles.indexOf('300000000000000000000001'), -1);

                    // Make sure the user's requestedOemAccess is now disabled.
                    assert.equal(responseBody.response.requestedOemAccess, false);

                    done();
                  }
                });
              }
            });
          }
        });
      });

    });

    describe('cannot grant', function() {

      it('the oem role to a user if they are a developer', function(done) {
        var userId = '000000000000000000000005',
            developerUserId = '000000000000000000000002',
            resources = 'oemRole';

        data.User.findById(userId, function(err, user) {
          if(err) {
            done(err);
          } else {

            // Make sure the user does not already have the OEM role.
            assert.equal(user.roles.indexOf('300000000000000000000001'), -1);

            // Make sure the user's requestedOemAccess is enabled.
            assert.equal(user.requestedOemAccess, true);

            dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
              app.post('/api/1/users/' + user._id + '/grantAccess?access_token=' + accessToken.token).send({resources: resources}).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                if(err) {
                  done(err);
                } else {
                  dm.validateForbiddenObject(res.body);

                  // Make sure the user was not modified.
                  app.get('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                    if(err) {
                      done(err);
                    } else {
                      var responseBody = res.body;

                      dm.validateResponseObject(responseBody);

                      // Make sure user does not have the OEM role.
                      assert.equal(responseBody.response.roles.indexOf('300000000000000000000001'), -1);

                      // Make sure the user's requestedOemAccess is not modified.
                      assert.equal(responseBody.response.requestedOemAccess, true);

                      done();
                    }
                  });
                }
              });
            });
          }
        });
      });

      it('the oem role to a user if they are an oem', function(done) {
        var userId = '000000000000000000000005',
          oemUserId = '000000000000000000000001',
          resources = 'oemRole';

        data.User.findById(userId, function(err, user) {
          if(err) {
            done(err);
          } else {

            // Make sure the user does not already have the OEM role.
            assert.equal(user.roles.indexOf('300000000000000000000001'), -1);

            // Make sure the user's requestedOemAccess is enabled.
            assert.equal(user.requestedOemAccess, true);

            dm.getUserAccessToken(data, oemUserId, function(err, accessToken) {
              app.post('/api/1/users/' + user._id + '/grantAccess?access_token=' + accessToken.token).send({resources: resources}).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                if(err) {
                  done(err);
                } else {
                  dm.validateForbiddenObject(res.body);

                  // Make sure the user was not modified.
                  app.get('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                    if(err) {
                      done(err);
                    } else {
                      var responseBody = res.body;

                      dm.validateResponseObject(responseBody);

                      // Make sure user does not have the OEM role.
                      assert.equal(responseBody.response.roles.indexOf('300000000000000000000001'), -1);

                      // Make sure the user's requestedOemAccess is not modified.
                      assert.equal(responseBody.response.requestedOemAccess, true);

                      done();
                    }
                  });
                }
              });
            });
          }
        });
      });

      it('the oem role to a themselves, if they are not an admin.', function(done) {
        var developerUserId = '000000000000000000000005',
          resources = 'oemRole';

        data.User.findById(developerUserId, function(err, user) {
          if(err) {
            done(err);
          } else {

            // Make sure the user does not already have the OEM role.
            assert.equal(user.roles.indexOf('300000000000000000000001'), -1);

            // Make sure the user's requestedOemAccess is enabled.
            assert.equal(user.requestedOemAccess, true);

            dm.getUserAccessToken(data, developerUserId, function(err, accessToken) {
              app.post('/api/1/users/' + user._id + '/grantAccess?access_token=' + accessToken.token).send({resources: resources}).expect('Content-Type', /json/).expect(403).end(function(err, res) {
                if(err) {
                  done(err);
                } else {
                  dm.validateForbiddenObject(res.body);

                  // Make sure the user was not modified.
                  app.get('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                    if(err) {
                      done(err);
                    } else {
                      var responseBody = res.body;

                      dm.validateResponseObject(responseBody);

                      // Make sure user does not have the OEM role.
                      assert.equal(responseBody.response.roles.indexOf('300000000000000000000001'), -1);

                      // Make sure the user's requestedOemAccess is not modified.
                      assert.equal(responseBody.response.requestedOemAccess, true);

                      done();
                    }
                  });
                }
              });
            });
          }
        });
      });

      it('the oem role to a user if they have already have the oem role.', function(done) {
        var developerUserId = '000000000000000000000006',
          resources = 'oemRole';

        data.User.findById(developerUserId, function(err, user) {
          if(err) {
            done(err);
          } else {

            // Make sure the user already has the OEM role.
            assert.notEqual(user.roles.indexOf('300000000000000000000001'), -1);

            // Make sure the user's requestedOemAccess is disabled.
            assert.equal(user.requestedOemAccess, false);

            app.post('/api/1/users/' + user._id + '/grantAccess?access_token=' + adminAccessToken).send({ resources: resources}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                var responseBody = res.body;

                dm.validateBadRequestObject(responseBody, 'server.error.accessAlreadyGranted');

                app.get('/api/1/users/' + user._id + '?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    var responseBody = res.body;

                    dm.validateResponseObject(responseBody);

                    // Make sure user still has the OEM role.
                    assert.notEqual(responseBody.response.roles.indexOf('300000000000000000000001'), -1);

                    // Make sure the user's requestedOemAccess is still disabled.
                    assert.equal(responseBody.response.requestedOemAccess, false);

                    validateUsers(responseBody.response, developerRole, developerUserId, function(err) {
                      done(err);
                    });
                  }
                });
              }
            });
          }
        });
      });

      it('the oem role if they are not logged in.', function(done) {
        var developerUserId = '000000000000000000000005',
          resources = 'oemRole';

        app.post('/api/1/users/' + developerUserId._id + '/grantAccess?access_token=InvalidAccessToken').send({ resources: resources}).expect('Content-Type', /json/).expect(401).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateUnauthorized(res.body);
            done();
          }
        });
      });

      it('unknown or invalid resources.', function(done) {
        var developerUserId = '000000000000000000000002',
            resources = 'blahblahblah';

        app.post('/api/1/users/' + developerUserId + '/grantAccess?access_token=' + adminAccessToken).send({ resources: resources}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            dm.validateBadRequestObject(res.body, 'server.error.unknownResource');

            resources = [];
            app.post('/api/1/users/' + developerUserId + '/grantAccess?access_token=' + adminAccessToken).send({ resources: resources}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
              if(err) {
                done(err);
              } else {
                dm.validateBadRequestObject(res.body, 'server.error.badRequest');

                resources = undefined;
                app.post('/api/1/users/' + developerUserId + '/grantAccess?access_token=' + adminAccessToken).send({resources: resources}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
                  if(err) {
                    done(err);
                  } else {
                    dm.validateBadRequestObject(res.body, 'server.error.badRequest');

                    resources = [1];
                    app.post('/api/1/users/' + developerUserId + '/grantAccess?access_token=' + adminAccessToken).send({resources: resources}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
                      if(err) {
                        done(err);
                      } else {
                        dm.validateBadRequestObject(res.body, 'server.error.badRequest');

                        resources = ['blah'];
                        app.post('/api/1/users/' + developerUserId + '/grantAccess?access_token=' + adminAccessToken).send({resources: resources}).expect('Content-Type', /json/).expect(400).end(function(err, res) {
                          if(err) {
                            done(err);
                          } else {
                            dm.validateBadRequestObject(res.body, 'server.error.unknownResource');

                            done();
                          }
                        });
                      }
                    });
                  }
                });
              }
            });
          }
        });
      });

    });


  });
};