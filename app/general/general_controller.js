module.exports = function(app, config, log, policy) {

  var db = require('mongoose'),
      express = require('express'),
      fs = require('fs'),
      Log = db.model('Log'),
      path = require('path');

  var packageJsonPath = path.resolve('./package.json');

  /* ************************************************** *
   * ******************** API Routes and Permissions
   * ************************************************** */

  var api = express.Router();

  api.route('/').get(info);

  app.use('/api/:version/info', api);


  /* ************************************************** *
   * ******************** Web Routes and Permissions
   * ************************************************** */

  var web = express.Router();

  app.use('/', web);

  /* ************************************************** *
   * ******************** Web Route Methods
   * ************************************************** */


  /* ************************************************** *
   * ******************** Route Methods
   * ************************************************** */

  var serverInfo = undefined;

  function info(req, res, next) {
    if(serverInfo !== undefined) {
      res.setData(serverInfo, next);
    } else {
      fs.readFile(packageJsonPath, {encoding: 'utf-8'}, function(err, packageJson) {
        if(err) {
          next(err);
        } else if( ! packageJson) {
          next(new Error("Package.json could not be read by server."));
        } else {
          serverInfo = JSON.parse(packageJson);

          serverInfo.logger = {
            error: config.server.error,
            debug: config.server.debug,
            trace: config.server.trace
          };

          serverInfo.server = {
            url: config.server.url
          };

          delete serverInfo.scripts;
          delete serverInfo.main;
          delete serverInfo.private;

          res.setData(serverInfo, next);
        }
      });
    }
  }

};