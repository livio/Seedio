module.exports = function(app, config, log) {

  var crucial = require('crucial'),
      crypto = require('crypto'),
      db = require('mongoose'),
      ObjectId = db.Schema.ObjectId,
      uuid = require('node-uuid');

  /* ************************************************** *
   * ******************** Schema
   * ************************************************** */

  var AccessToken = new db.Schema({
    token: { type: String, sparse: true, default: createTokenSync },
    client: { type: ObjectId, ref: "SdlServer" },
    user: { type: ObjectId, ref: "User" }
  });


  /* ************************************************** *
   * ******************** Instance Methods
   * ************************************************** */

  AccessToken.methods.sanitize = function(user, cb) {
    return cb(undefined, this);
  };


  /* ************************************************** *
   * ******************** Private Methods
   * ************************************************** */

  /**
   * Create a hex token with a random string of text
   * using the given size in the config.
   * @returns a string of the given length.
   */
  function createTokenSync() {
    var length = config.crypto.plainTextSize/2,
        text;

    try {
      text = crypto.randomBytes(length);
    } catch(err) {
      log.error(err);
      text = uuid.v4();
    }

    return text.toString('hex');
  };


  /* ************************************************** *
   * ******************** Mongoose Plugins
   * ************************************************** *
   * Enable additional functionality through 3rd party
   * plugins http://plugins.mongoosejs.com/             */

  db.plugin(crucial.mongoose);


  /* ************************************************** *
   * ******************** Exports
   * ************************************************** *
   * Export the model's methods and data so it can be
   * required by other parts of the application.        */

  db.model('AccessToken', AccessToken);


};