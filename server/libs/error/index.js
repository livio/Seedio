exports.build = function(locale, code) {
  var err = new Error(req.i18n.t(locale ||'server.error.generic') || locale);
  err.status = code || 500;
  return err;
};