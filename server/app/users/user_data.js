module.exports = function(app, config, log, dm) {

  function UserFixture() {
    dm.FixtureAdapter.call(this, 'User', dm, config, log);
  }

  UserFixture.prototype = dm.inherit(dm.FixtureAdapter.prototype);

  UserFixture.prototype.getNew = function() {
    var now = Date.now();
    return {
      "_id": "000000000000000000000099",
      "activated": true,
      "applications": [],
      "dateCreated": now,
      "deactivatedMessage": "",
      "deleted": false,
      "email": "newUser@localhost.com",
      "failedLoginAttempts": 0,
      "lastLogin": now,
      "lastUpdated": now,
      "lastUpdatedBy": "000000000000000000000000",
      "oauth2ClientId": "ed9d2323-339d-4724-8183-534416a4bd84",
      "password": "password",
      "passwordReset": "f23fasdffgt3h34h34g3r12f12",
      "requestedOemAccess": false,
      "roles": ["300000000000000000000000"],
      "securityQuestion": "What is your favorite color",
      "securityAnswer": "Blue. No, yel...",
      "sdlServers": [],
      "username": "newUser"
    };
  };

  UserFixture.prototype.getAll = function() {
    return [
      {
        "_id": "000000000000000000000000",
        "activated": true,
        "applications": [],
        "deactivatedMessage": "",
        "deleted": false,
        "email": "admin@localhost.com",
        "failedLoginAttempts": 0,
        "oauth2ClientId": "ed9d2323-339d-4724-8183-531616a4bd84",
        "password": "password",
        "passwordResetHash": "f23fasdf4gt3h34h34g3r12f12",
        "requestedOemAccess": false,
        "roles": ["300000000000000000000000"],
        "securityQuestion": "What is your favorite color",
        "securityAnswerHash": "I'm blind",
        "sdlServers": [],
        "username": "admin"
      },
      {
        "_id": "000000000000000000000001",
        "activated": true,
        "applications": ["100000000000000000000002", "100000000000000000000003"],
        "deactivatedMessage": "",
        "deleted": false,
        "email": "oem@localhost.com",
        "failedLoginAttempts": 0,
        "oauth2ClientId": "ed9d2323-339d-4724-8183-531616a4bd84",
        "password": "password",
        "passwordResetHash": "f23fasdf4gt3h34h34g3r12f12",
        "requestedOemAccess": false,
        "roles": ["300000000000000000000001"],
        "securityQuestion": "What is your favorite color",
        "securityAnswerHash": "I'm blind",
        "sdlServers": ["200000000000000000000000", "200000000000000000000001"],
        "username": "oem"
      },
      {
        "_id": "000000000000000000000002",
        "activated": true,
        "applications": ["100000000000000000000000", "100000000000000000000001"],
        "deactivatedMessage": "",
        "deleted": false,
        "email": "developer@localhost.com",
        "failedLoginAttempts": 0,
        "oauth2ClientId": "",
        "password": "password",
        "passwordResetHash": "f23fasdf4gt3h34h34g3r12f12",
        "requestedOemAccess": false,
        "roles": ["300000000000000000000002"],
        "securityQuestion": "What is your favorite color",
        "securityAnswerHash": "I'm blind",
        "sdlServers": [],
        "username": "developer"
      },
      {
        "_id": "000000000000000000000003",
        "activated": true,
        "applications": [],
        "deactivatedMessage": "",
        "deleted": false,
        "email": "oem2@localhost.com",
        "failedLoginAttempts": 0,
        "oauth2ClientId": "40000000-0000-0000-0000-000000000000",
        "password": "password",
        "passwordResetHash": "f23fasdf4gt3h34h34g3r12f121222",
        "requestedOemAccess": false,
        "roles": ["300000000000000000000001"],
        "securityQuestion": "What is your favorite color",
        "securityAnswerHash": "Chicken",
        "sdlServers": ["200000000000000000000000"],
        "username": "oem2"
      },
      {
        "_id": "000000000000000000000004",
        "activated": true,
        "applications": [],
        "deactivatedMessage": "",
        "deleted": true,
        "email": "deletedOem@localhost.com",
        "failedLoginAttempts": 0,
        "oauth2ClientId": "40000000-0000-0000-0000-000000000001",
        "password": "password",
        "passwordResetHash": "f23fasdf4gt3h34h34g3r12f121222",
        "requestedOemAccess": false,
        "roles": ["300000000000000000000001"],
        "securityQuestion": "What is your favorite color",
        "securityAnswerHash": "Double Rainbow",
        "sdlServers": [],
        "username": "deletedOem"
      },
      {
        "_id": "000000000000000000000005",
        "activated": true,
        "applications": [],
        "deactivatedMessage": "",
        "deleted": false,
        "email": "developer2@localhost.com",
        "failedLoginAttempts": 0,
        "oauth2ClientId": "",
        "password": "password",
        "passwordResetHash": "f23fasdf4gt3h34h34g3r12f12",
        "requestedOemAccess": true,
        "roles": ["300000000000000000000002"],
        "securityQuestion": "What is your favorite color",
        "securityAnswerHash": "I'm blind",
        "sdlServers": [],
        "username": "developer2"
      },
      {
        "_id": "000000000000000000000006",
        "activated": true,
        "applications": [],
        "deactivatedMessage": "",
        "deleted": false,
        "email": "developeroem@localhost.com",
        "failedLoginAttempts": 0,
        "oauth2ClientId": "",
        "password": "password",
        "passwordResetHash": "f23fasdf4gt3h34h34g3r12f12",
        "requestedOemAccess": false,
        "roles": ["300000000000000000000002", "300000000000000000000001"],
        "securityQuestion": "What is your favorite color",
        "securityAnswerHash": "I'm blind",
        "sdlServers": [],
        "username": "developeroem"
      },
      {
        "_id": "000000000000000000000007",
        "activated": false,
        "applications": [],
        "deactivatedMessage": "",
        "deleted": false,
        "email": "deactivatedDeveloper@localhost.com",
        "failedLoginAttempts": 0,
        "oauth2ClientId": "",
        "password": "password",
        "passwordResetHash": "f23fasdf4gt3h34h34g3r12f12",
        "requestedOemAccess": false,
        "roles": ["300000000000000000000002"],
        "securityQuestion": "What is your favorite food",
        "securityAnswerHash": "Spagetti",
        "sdlServers": [],
        "username": "deactivateddeveloper"
      }
    ];
  };

  return new UserFixture();
};