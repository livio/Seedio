module.exports = function(app, config, log) {

  var crucial = require("crucial"),
      db = require('mongoose'),
      ObjectId = db.Schema.ObjectId,
      url = require('url'),
      uuid = require('node-uuid');

  var AuthorizationCode = new db.Schema({
    code: { type: String, sparse: true, default: uuid.v4 },  // should this be 16 char?
    client: { type: ObjectId, ref: "SdlServer" },
    redirectUri: { type: String },
    user: { type: ObjectId, ref: "User" }
  });

  AuthorizationCode.statics.findByCode = function(code, cb) {
    db.model('AuthorizationCode').findOne({ code: code }).exec(function(err, authCode) {
      if(err) {
        cb(err);
      } else if ( ! authCode) {
        cb(new Error("Authorization code was not found."));
      } else {
        cb(undefined, authCode);
      }
    });
  };

  AuthorizationCode.methods.sanitize = function(user) {
    var code = (this).toObject();

    delete code.__v;

    return this;
  };

  AuthorizationCode.methods.update = function(obj, user, cb) {
    // TODO: Fix this automatic method in crucial.

    var code = this;
    //code.code = obj.code;
    code.client= obj.client || code.client;
    code.redirectUri= obj.redirectUri || code.redirectUri;
    code.user= obj.user || code.user;
    code.save(cb);
  };

  AuthorizationCode.methods.verifyRedirectUri = function(uri, cb) {
    //return (this.redirectUri === url.parse(uri).pathname);
    console.log("Check auth code uri: %s == %s", this.redirectUri, uri);
    return this.redirectUri === uri;
  };

  db.plugin(crucial.mongoose);

  /* ************************************************** *
   * ******************** Exports
   * ************************************************** *
   * Export the model's methods and data so it can be
   * required by other parts of the application.        */

  db.model('AuthorizationCode', AuthorizationCode);

};