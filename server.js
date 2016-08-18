require("source-map-support").install();
module.exports =
/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId])
/******/ 			return installedModules[moduleId].exports;
/******/
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			exports: {},
/******/ 			id: moduleId,
/******/ 			loaded: false
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "/";
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _newrelic = __webpack_require__(186);
  
  var _newrelic2 = _interopRequireDefault(_newrelic);
  
  __webpack_require__(160);
  
  var _path = __webpack_require__(20);
  
  var _path2 = _interopRequireDefault(_path);
  
  var _express = __webpack_require__(10);
  
  var _express2 = _interopRequireDefault(_express);
  
  var _react = __webpack_require__(90);
  
  var _react2 = _interopRequireDefault(_react);
  
  var _reactDomServer = __webpack_require__(188);
  
  var _reactDomServer2 = _interopRequireDefault(_reactDomServer);
  
  var _routes = __webpack_require__(85);
  
  var _routes2 = _interopRequireDefault(_routes);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _morgan = __webpack_require__(88);
  
  var _morgan2 = _interopRequireDefault(_morgan);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _fs = __webpack_require__(43);
  
  var _fs2 = _interopRequireDefault(_fs);
  
  var _connectTimeout = __webpack_require__(168);
  
  var _connectTimeout2 = _interopRequireDefault(_connectTimeout);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _process = __webpack_require__(21);
  
  var _process2 = _interopRequireDefault(_process);
  
  var _modulesAnalyticsGoogle = __webpack_require__(33);
  
  var _modulesAnalyticsGoogle2 = _interopRequireDefault(_modulesAnalyticsGoogle);
  
  var _pmx = __webpack_require__(52);
  
  var _pmx2 = _interopRequireDefault(_pmx);
  
  // require("http").globalAgent.maxSockets = Infinity;
  
  var app = global.server = (0, _express2['default'])();
  
  if (_config2['default'].env === 'logan-testing' || _config2['default'].env === 'logan-staging' || _config2['default'].env === 'logan-production') {
    _pmx2['default'].init({
      http: true, // HTTP routes logging (default: true)
      errors: true, // Exceptions loggin (default: true)
      custom_probes: true, // Auto expose JS Loop Latency and HTTP req/s as custom metrics
      network: true, // Network monitoring at the application level
      ports: true
    });
  }
  //function esReqTimeout(req, res, next){
  //  if (req.path.indexOf('/taskqueue') == -1){
  //    console.log("=============================>>> esReqTimeout 180000")
  //    let req_timeout_obj = req_timeout(180000);
  //    req_timeout_obj(req, res, next)
  //  }
  //  else{
  //    console.log("=============================>>> esReqTimeout 240000")
  //    let req_timeout_obj = req_timeout(240000);
  //    req_timeout_obj(req, res, next)
  //  }
  //};
  app.use((0, _connectTimeout2['default'])(_utilsServerConstants2['default'].defaultTimeoutSeconds * 1000));
  app.set('port', _config2['default'].port || 5000);
  // express configuration
  // -----------------------------------------------------------------------------
  __webpack_require__(144)(app);
  __webpack_require__(138)(app);
  //
  
  //https server setup for front end
  var server;
  
  if (_config2['default'].sslServer && _config2['default'].env === 'development') {
    var options = {
      key: _fs2['default'].readFileSync(__webpack_require__(20).normalize(__dirname + '/..') + '/private/key.pem', 'utf8'),
      cert: _fs2['default'].readFileSync(__webpack_require__(20).normalize(__dirname + '/..') + '/private/key-cert.pem', 'utf8')
    };
    server = __webpack_require__(180).createServer(options, app);
  } else {
    server = __webpack_require__(179).createServer(app);
  }
  
  if (!_process2['default'].env["backserver"]) {
    var socketio = __webpack_require__(149);
    socketio.initialize(server);
  }
  
  //var socketio = require('./socketio');
  //socketio.initialize(server);
  _mongoose2['default'].connect(_config2['default'].mongo.uri, _config2['default'].mongo.options);
  
  _mongoose2['default'].connection.on('connected', function () {
    _modulesLogger2['default'].info('MongoDB connected');
    _process2['default'].env['mongoUA'] = 'connected';
  });
  _mongoose2['default'].connection.on('error', function (err) {
    _modulesLogger2['default'].error('MongoDB connection error: ' + err);
    _mongoose2['default'].disconnect();
  });
  _mongoose2['default'].connection.on('disconnected', function () {
    _modulesLogger2['default'].warn('MongoDB disconnected! Reconnecting in 3 seconds');
    _process2['default'].env['mongoUA'] = 'disconnected';
    setTimeout(function () {
      _mongoose2['default'].connect(_config2['default'].mongo.uri, _config2['default'].mongo.options);
    }, 3000);
  });
  
  __webpack_require__(85)(app);
  // require('./seed').generateAdminList();
  //
  
  //
  //
  // Start server
  // -----------------------------------------------------------------------------
  // Not expire connection by http.server way
  server.timeout = 0;
  var listenIP = _config2['default'].ip || '0.0.0.0';
  server.listen(app.get('port'), listenIP, function () {
    /* eslint-disable no-console */
    if (_config2['default'].env === 'development') {
      _modulesLogger2['default'].info('The server is running at http://localhost:' + app.get('port') + ' under ' + app.get('env'));
      _modulesLogger2['default'].info('Version is ' + _config2['default'].version);
    } else {
      _modulesLogger2['default'].info('server start listening!  Environment: ' + app.get('env') + '  on Port: ' + _config2['default'].port);
      _modulesLogger2['default'].info('Version is ' + _config2['default'].version);
      if (_config2['default'].mongoLog) {
        _modulesLogger2['default'].info('Saving Logs');
      }
    }
  
    if (_process2['default'].send) {
      _process2['default'].send('online');
    }
  });
  
  // Expose app
  exports = module.exports = app;

/***/ },
/* 1 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var pmx = __webpack_require__(52),
      winston = __webpack_require__(195);
  //winstonMongoDB = require('winston-mongodb').MongoDB,
  
  //var helpers = require('./helper');
  
  var logger = new winston.Logger({
      levels: { error: 0, warn: 1, sync: 2, info: 3, verbose: 4, debug: 5, silly: 6 },
      level: _config2['default'].logLevel,
      colors: { sync: 'cyan' },
      exitOnError: false,
      transports: [new winston.transports.Console({
          timestamp: true,
          colorize: true,
          prettyPrint: true
      })]
  
  });
  
  var os = __webpack_require__(51);
  
  ['info', 'debug', 'warn', 'error', 'sync', 'verbose', 'silly'].forEach(function (method) {
      exports[method] = function () {
          var args = Array.prototype.slice.call(arguments, 0);
          args.unshift(method);
          //        var msg = args[0];
          //        args = Array.prototype.slice.call(args, 1);
          var newArgs = [];
          args.forEach(function (arg) {
              if (typeof arg === 'undefined') {
                  return;
              } else if (typeof arg === 'string') {
                  newArgs.push(arg);
              } else if (!!arg && !!arg.toJSON) {
                  newArgs.push(arg.toJSON());
              } else if (!!arg && !!arg.toString && arg.toString() !== '[object Object]') {
                  newArgs.push(arg);
              } else {
                  newArgs.push(arg);
              }
          });
          if (method === 'error' && !!_config2['default'].traceOnError) {
              var err = new Error();
              newArgs.push(err.stack);
              pmx.notify(newArgs);
          }
  
          logger.log.apply(logger, newArgs);
      };
  });
  
  var getLogglyCredential = function getLogglyCredential() {
      return {
          'token': _config2['default'].logglyToken,
          'subdomain': _config2['default'].logglySubdomain
      };
  };
  
  if (_config2['default'].env != 'development' && !!_config2['default'].mongoLog) {
      var hostname = os.hostname();
      console.log("Start writting logs to loggly now!");
      __webpack_require__(196);
      var tags = [os.hostname()];
  
      var addedtag = _config2['default'].env;
  
      if (hostname.indexOf('socket') > 0) {
          addedtag = addedtag + '-socket';
      }
      if (hostname.indexOf('task') > 0) {
          addedtag = addedtag + '-task';
      }
  
      if (hostname.indexOf('candidate') > 0) {
          addedtag = addedtag + '-candidate';
      }
      tags.push(addedtag);
      var cred = getLogglyCredential();
      /*  
      logger.add(winston.transports.Loggly, {
        token: cred.token,
        subdomain: cred.subdomain,
        tags: tags,
        json:true
      });*/
  }
  
  //if (!!config.mongoLog) {
  //    logger.add(winstonMongoDB, {
  //        db: config.logDB.uri,
  //        collection: 'logs',
  //        capped: true,
  //        storeHost: true,
  //        levels: { error: 0, warn: 1, sync: 2, info: 3, verbose: 4, debug: 5, silly: 6},
  //        level: config.logLevel,
  //        cappedSize: config.logDB.logSize         //1G for prod, 300M for rest
  //    });
  //}

/***/ },
/* 2 */
/***/ function(module, exports) {

  /**
   * http://usejsdoc.org/
   */
  
  'use strict';
  
  exports.HttpErrorStatus = 400;
  exports.HttpUnauthorizedAnonymousStatus = 4001;
  exports.HttpUnauthorizedStatus = 401;
  exports.HttpNotFoundStatus = 404;
  exports.HttpForbiddenStatus = 403;
  exports.HttpSuccessStatus = 200;
  exports.HttpCriticalErrorStatus = 500;
  exports.HttpRedirectStatus = 301;
  exports.HttpErrorTaskQueueNeverTry = 461;
  exports.HTTPSchema = 'http://';
  exports.HTTPSSchema = 'https://';
  
  exports.ES_PRODUCT_ONESNA = 'onesna';
  exports.OAuth2ScopeLogan = 'https://www.onesna.com/auth/logan';
  exports.OAuth2ScopeUserInfoEmail = 'https://www.onesna.com/auth/userinfo.email';
  exports.OAuth2ScopeUserInfoProfile = 'https://www.onesna.com/auth/userinfo.profile';
  exports.IncludeScope = 1;
  exports.NotIncludeScope = 0;
  exports.SyncOperateDelete = 2;
  
  exports.UrlApi = '/api';
  exports.UrlMessages = '/messages';
  exports.UrlMessagesFileRedirect = '/:id/files/:fileKey';
  exports.UrlMessagesFileRedirectFull = exports.UrlApi + exports.UrlMessages + exports.UrlMessagesFileRedirect;
  
  exports.StopFlag = 'Stop';
  exports.AuthenticateTypeJWT = 'jwt';
  exports.AuthenticateTypeOAuth2 = 'oauth2';
  exports.AuthenticateTypeAnonymous = 'anony';
  exports.AuthenticateTypeEsnaServer = 'esna_server';
  
  exports.MessageImageNativeLinkMimeHeader = 'image';
  exports.MessageProviderUrlLink = 'urllink';
  exports.MessageProviderNative = 'native';
  exports.TaskStatusDefault = 'pending';
  
  exports.DirectionAfter = 'after';
  exports.DirectionBefore = 'before';
  
  exports.TypeUser = 'user';
  exports.TypeAnonymous = 'anonymous';
  exports.TypeCompany = 'company';
  exports.TypeTopic = 'topic';
  exports.TypeMessage = 'message';
  exports.domainTagPrefix = String.fromCharCode(0xFE, 0xFF) + '@';
  exports.deferOutTimeout = 'timeout';
  exports.deferOutAgendaJob = 'agendaJob';
  
  exports.relationEmployee = 'employee';
  exports.relationAdmin = 'admin';
  exports.relationMember = 'member';
  exports.relationAny = 'any';
  exports.relationCreator = 'creator';
  exports.relationGuest = 'guest';
  exports.defaultTimeoutSeconds = 120;
  exports.taskRequestTimeoutSeconds = 600;
  
  exports.roleSiteAdmin = 'site_admin';
  exports.roleCustomerAdmin = 'customer_admin';
  exports.MigrateFailedStatus = 'failed';
  
  exports.JoinTopicOnlyMember = 1;
  exports.JoinTopicNoLimit = 0;
  exports.defaultRestrictValue = [];
  
  exports.ConvertStatusNotStart = 0;
  exports.ConvertStatusProgressing = 1;
  exports.ConvertStatusSuccess = 2;
  exports.ConvertStatusFailed = 3;
  exports.ConvertMemcacheKeyPrefix = 'fileViewConvrt_';
  exports.defaultMaxlistSize = 50;
  exports.userTagPrefix = 'u' + String.fromCharCode(0xFF, 0xFE) + ' ';
  exports.topicTagPrefix = 't' + String.fromCharCode(0xFF, 0xFE) + ' ';
  
  exports.previewProviderGCS = 'gcs';
  exports.storageProviderGCS = 'gcs';

/***/ },
/* 3 */
/***/ function(module, exports) {

  /**
   * Created by ericd on 26/11/2015.
   */
  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  var ESErrors = (function () {
    function ESErrors(code, message) {
      _classCallCheck(this, ESErrors);
  
      this.code = code || exports.SysUnkownError;
      this.message = message || getMessageByCode(this.code);
    }
  
    _createClass(ESErrors, [{
      key: 'toString',
      value: function toString() {
        return this.message;
      }
    }]);
  
    return ESErrors;
  })();
  
  exports.SysUnkownError = 'sys_unkown_error';
  exports.SysAlreadyRegisterDeferError = 'sys_dup_register_deffer';
  exports.SysNotExistedDeferError = 'sys_not_existed_deffer';
  exports.BadRequestError = 'api_bad_request_input';
  exports.ServerInternalError = 'sys_internal_error';
  exports.AuthenticateErrorJWT = 'authen_error.jwt_auth_failed';
  exports.AuthenticateErrorOauth2 = 'authen_error.oauth2_auth_failed';
  exports.AuthenticateErrorOauth = 'authen_error.oauth_auth_failed';
  exports.AuthenticateErrorEsnaServer = 'authen_error.esnaserver_auth_failed';
  exports.AuthenticateFailed = 'authen_error';
  exports.AuthenticateErrorAnonyJWT = 'authen_error.anonymouse_jwt_auth_failed';
  exports.AuthenticateErrorAnony4001JWT = 'authen_error.anonymouse_jwt_auth_4001_failed';
  exports.AuthenticateFailedOnesnaServer = 'authen_error.onesna_servercall_authentication_failed';
  exports.AuthorizeErrorOauth2 = 'authorize_error.oauth2';
  exports.AuthorizeErrorPermission = 'authorize_error.permission';
  exports.AuthorizeErrorDeveloperAdmin = 'authorize_error.developer_admin';
  // for pre-alpha-release
  exports.AuthorizeErrorNotOnApprovedList = 'authorize_error.not_on_approved_list';
  //
  exports.AuthorizeFailed = 'authorize_error';
  exports.SyncAddAccessTokenInvalidData = 'sync_add_accesstoekn_invalid_data';
  exports.SyncAddAccessTokenFailed = 'sync_add_accesstoekn_failed';
  exports.SyncDeleteAccessTokenInvalidData = 'sync_delete_accesstoekn_invalid_data';
  exports.SyncDeleteAccessTokenFailed = 'sync_delete_accesstoekn_failed';
  exports.SignJWTFailed = 'sign_jwt_failed';
  exports.VerifyJWTFailed = 'verify_jwt_failed';
  
  exports.UploadUrlCreateFailed = 'upload_url_create_failed';
  exports.DownloadUrlCreateFailed = 'download_url_create_failed';
  
  exports.DBError = 'db_error';
  exports.DBErrorDuplicateKey = 'db_error.duplicateKey';
  exports.NotExsistedError = 'not_existed_error';
  exports.NotCreatorError = 'not_exist_creator_error';
  exports.NotParentError = 'not_exist_parent_error';
  exports.UpdateRecordWithModifiedOutdate = 'update_outdated_record';
  
  exports.OAuth2AccessTokenNotExisted = 'access_token_not_existed_error';
  exports.AccessOnesnaHappenError = 'access_onesna_happen_error';
  exports.ViewNotImplement = 'view_not_implement';
  
  exports.SchemaInvalidHeader = 'schema_invalid.';
  exports.MessageInvalidProvider = 'message_invalid.content_data_provider';
  exports.MessageInvalidPath = 'message_invalid.content_data_path';
  exports.MessageInvalidPreviewFile = 'message_invalid.content_data_previewfile';
  exports.MessageInvalidFileId = 'message_invalid.content_data_fileid';
  exports.MessageInvalidFileSize = 'message_invalid.content_data_filesize';
  exports.MessageInvalidCategory = 'message_invalid.category';
  exports.MessageNotSupportSenderType = 'message_invalid.sender.type';
  exports.MessageUnexpectedCategory = 'message_unexpected.category';
  exports.ParentMessageNotExsistedError = 'parent_message_not_existed_error';
  exports.MessageInvalidDupLike = 'message_invalid.duplicate_like_comment';
  
  exports.TaskqueueInvalidUrl = 'taskqueue_invalid.url';
  exports.TaskqueueRetry = 'taskqueue.retry';
  exports.TaskqueueEndBeforeTimout = 'taskqueue.end_before_timeout';
  exports.TaskNoRetryError = 'taskqueue.no_retry';
  exports.RecordMigrageError = 'migrateAddRecord.failed';
  
  exports.MemcacheNotReady = 'memcache.not_ready';
  exports.NoValidateObjectType = 'relationPermission.objecttype_invalid';
  
  exports.FileCopyFailed = 'file.copy_failed';
  exports.FileCreateObjectFailed = 'file.create_fileobject_failed';
  exports.FileDeleteFailed = 'file.delete_files_failed';
  exports.NoSuchConverter = 'fileView.convert_not_implement';
  exports.AlreadyStartConvert = 'fileView.convert_already_start_convert';
  exports.SetConvertStatusFailed = 'fileView.set_convertstatus_failed';
  exports.SetPagesFailed = 'fileView.set_pages_failed';
  exports.SetPagingFailed = 'fileView.set_paging_failed';
  exports.SetProcessurlFailed = 'fileView.set_processurl_failed';
  exports.AsposeNoSIDOrKey = 'fileView.aspose_nosidorkey';
  exports.FileConvertFailed = 'fileView.convert_failed';
  exports.GetPreviewUrlFailed = 'fileView.get_previewurl_failed';
  exports.GetviewUrlsFailed = 'fileView.get_viewurls_failed';
  exports.ConvertFileCleanWorkFailed = 'fileView.convert_file_cleanwork_failed';
  exports.SyncMessageSenderFailed = 'sync_sender_msg.failed';
  exports.SyncParentMessageTitleFailed = 'sync_prt_msg_title.failed';
  
  var ErrorDescription = {};
  ErrorDescription[exports.SysUnkownError] = 'System Unkown Error';
  ErrorDescription[exports.SysAlreadyRegisterDeferError] = 'The deffer already registered';
  ErrorDescription[exports.SysNotExistedDeferError] = 'The deffer not existed';
  
  ErrorDescription[exports.ServerInternalError] = 'Server Internal Error';
  ErrorDescription[exports.DBError] = 'Database operation error';
  ErrorDescription[exports.DBErrorDuplicateKey] = 'Database operation duplicate key error:';
  ErrorDescription[exports.NotExsistedError] = 'Not exsist';
  ErrorDescription[exports.NotCreatorError] = 'Not exsist creator';
  ErrorDescription[exports.NotParentError] = 'Not exsist parent';
  ErrorDescription[exports.UpdateRecordWithModifiedOutdate] = 'Update outdated record';
  
  ErrorDescription[exports.OAuth2AccessTokenNotExisted] = 'Access_token not existed';
  ErrorDescription[exports.AccessOnesnaHappenError] = 'Access onesna happen error';
  ErrorDescription[exports.BadRequestError] = 'Api Bad Request Check Input';
  ErrorDescription[exports.AuthenticateErrorJWT] = 'Authenticate Jwt token failed';
  ErrorDescription[exports.AuthenticateErrorOauth2] = 'Authenticate oauth2 failed';
  ErrorDescription[exports.AuthenticateErrorAnonyJWT] = 'Authenticate anonymouse jwt failed';
  ErrorDescription[exports.AuthenticateErrorAnonyJWT] = 'Authenticate anonymouse jwt failed';
  ErrorDescription[exports.AuthenticateErrorEsnaServer] = 'Authenticate for esan server call failed';
  
  ErrorDescription[exports.AuthorizeErrorNotOnApprovedList] = 'Not on the approved list';
  ErrorDescription[exports.AuthorizeErrorOauth2] = 'Authorise oauth2 failed';
  ErrorDescription[exports.AuthorizeErrorPermission] = 'Authorise permission failed';
  
  ErrorDescription[exports.SyncAddAccessTokenInvalidData] = 'Invalid data for adding accesstoken by synchronizing way';
  ErrorDescription[exports.SyncAddAccessTokenFailed] = 'When adding access token by synchronizing way failed';
  ErrorDescription[exports.SyncDeleteAccessTokenInvalidData] = 'Invalid data for deleting accesstoken by synchronizing way';
  ErrorDescription[exports.SyncDeleteAccessTokenFailed] = 'When deleteing access token by synchronizing way failed';
  ErrorDescription[exports.SignJWTFailed] = 'Sign a jwt token failed';
  ErrorDescription[exports.VerifyJWTFailed] = 'Verify a jwt token failed';
  
  ErrorDescription[exports.UploadUrlCreateFailed] = 'Create upload url failed!';
  ErrorDescription[exports.DownloadUrlCreateFailed] = 'Create download url failed!';
  
  ErrorDescription[exports.ViewNotImplement] = 'View not implement';
  
  ErrorDescription[exports.MessageInvalidProvider] = 'Message object has invalid Provider in content.data';
  ErrorDescription[exports.MessageInvalidPath] = 'Message object has invalid path in content.data';
  ErrorDescription[exports.MessageInvalidPreviewFile] = 'Message object has invalid previewFile in content.data';
  ErrorDescription[exports.MessageInvalidFileId] = 'Message object has invalid FileId in content.data';
  ErrorDescription[exports.MessageInvalidFileSize] = 'Message object has invalid fileSize in content.data';
  ErrorDescription[exports.MessageInvalidCategory] = 'Message object has invalid category';
  ErrorDescription[exports.MessageNotSupportSenderType] = 'Message object has invalid sender type';
  ErrorDescription[exports.MessageUnexpectedCategory] = 'The category is not as expected';
  ErrorDescription[exports.ParentMessageNotExsistedError] = 'Parent message not existed';
  ErrorDescription[exports.MessageInvalidDupLike] = 'Duplicate like message from same user to same category';
  ErrorDescription[exports.TaskqueueInvalidUrl] = 'Taskqueue got a invalid url';
  ErrorDescription[exports.TaskqueueRetry] = 'Taskqueue need retry again';
  ErrorDescription[exports.TaskqueueEndBeforeTimout] = 'Taskqueue end before timeout';
  ErrorDescription[exports.TaskNoRetryError] = 'Taskqueue no retry although happen error';
  ErrorDescription[exports.RecordMigrageError] = 'Add record for migrate happen error';
  
  ErrorDescription[exports.MemcacheNotReady] = 'Memcahe not ready';
  ErrorDescription[exports.NoValidateObjectType] = 'Relation Permission must give valid object type';
  ErrorDescription[exports.NoSuchConverter] = 'There is no such converter';
  ErrorDescription[exports.AlreadyStartConvert] = 'The file already start convert';
  ErrorDescription[exports.FileCopyFailed] = 'Copy file failed';
  ErrorDescription[exports.FileCreateObjectFailed] = 'Create file object failed';
  ErrorDescription[exports.AsposeNoSIDOrKey] = 'There is no App SID or App Key of Aspose';
  ErrorDescription[exports.SetConvertStatusFailed] = 'Failed to set convert status of a file';
  ErrorDescription[exports.SetPagesFailed] = 'Failed to set pages of a file';
  ErrorDescription[exports.SetPagingFailed] = 'Failed to set paging number of a file';
  ErrorDescription[exports.SetProcessurlFailed] = 'Failed to set process url of a file';
  
  ErrorDescription[exports.FileConvertFailed] = 'Convert file failed';
  ErrorDescription[exports.FileDeleteFailed] = 'Delete files failed';
  ErrorDescription[exports.GetPreviewUrlFailed] = 'Get preview url failed';
  ErrorDescription[exports.GetviewUrlsFailed] = 'Get view urls failed';
  ErrorDescription[exports.ConvertFileCleanWorkFailed] = 'Convert file clean work failed';
  ErrorDescription[exports.SyncMessageSenderFailed] = 'Synchronize sender information failed';
  ErrorDescription[exports.SyncParentMessageTitleFailed] = 'Synchronize parent message title failed';
  
  var NoErrorMessage = 'No Error Message';
  
  function getMessageByCode(code) {
    return ErrorDescription[code] || NoErrorMessage;
  }
  
  exports.ESErrors = ESErrors;
  exports.getMessageByCode = getMessageByCode;

/***/ },
/* 4 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  module.exports = __webpack_require__(27);

/***/ },
/* 5 */
/***/ function(module, exports) {

  module.exports = require("mongoose");

/***/ },
/* 6 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Created by ericd on 02/12/2015.
   */
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _querystring = __webpack_require__(45);
  
  var _querystring2 = _interopRequireDefault(_querystring);
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var _fluxConstantsMeetingConstants = __webpack_require__(39);
  
  var _fluxConstantsMeetingConstants2 = _interopRequireDefault(_fluxConstantsMeetingConstants);
  
  var _serverConstants = __webpack_require__(2);
  
  var _serverConstants2 = _interopRequireDefault(_serverConstants);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _os = __webpack_require__(51);
  
  var _os2 = _interopRequireDefault(_os);
  
  var _url = __webpack_require__(194);
  
  var _url2 = _interopRequireDefault(_url);
  
  var _enrollAdminModelJs = __webpack_require__(80);
  
  var _enrollAdminModelJs2 = _interopRequireDefault(_enrollAdminModelJs);
  
  exports.getIssFromHostname = function (hostname) {
    var parts = hostname.split('.');
    if (parts.length >= 3) {
      return parts.slice(parts.length - 2).join('.');
    } else {
      return hostname;
    }
  };
  
  exports.paginationHelper = function (src, pagination, data, queryFunction, cb) {
    var search = data.search;
    var page = pagination.page;
    var size = pagination.size;
    var limit = pagination.size + 1;
    var apiRoute = pagination.apiRoute;
  
    queryFunction(pagination, data, function (err, result) {
      if (err) {
        return cb(err);
      }
  
      var returnData = {
        from: (page - 1) * size + 1,
        to: (page - 1) * size + result.data.length
      };
  
      if (result.length === limit) {
        returnData.data = result.slice(0, -1);
        returnData.nextPageUrl = apiRoute + '?page=' + (page + 1) + '&size=' + size;
      } else {
        returnData.data = result;
      }
  
      if (page > 1) {
        returnData.previousPageUrl = apiRoute + '?page=' + (page - 1) + '&size=' + size;
      }
      return cb(null, returnData);
    });
  };
  
  exports.checkZangUser = function (email) {
    return (/@esna.com\s*$/.test(email) || /@zang.io\s*$/.test(email)
    );
  };
  
  exports.checkItemInList = function (item, list) {
    return list.indexOf(item) > -1;
  };
  
  exports.getDeveloperAdmins = function (callback) {
    var logger = __webpack_require__(1);
    _enrollAdminModelJs2['default'].findOne({ group: "developers" }, function (err, admins) {
      if (err) {
        logger.error("failed to get developer admin list");
        return callback([]);
      }
      if (!admins) {
        return callback([]);
      }
      return callback(admins.emails);
    });
  };
  
  exports.getEnrollAdminEmails = function (callback) {
    var logger = __webpack_require__(1);
    _enrollAdminModelJs2['default'].findOne({ group: "enrollAdmins" }, function (err, admins) {
      if (err) {
        logger.error("failed to get enrollAdmins admin list");
        return callback([]);
      }
      if (!admins) {
        return callback([]);
      }
      return callback(admins.emails);
    });
  };
  
  exports.getFullUrlByType = function (src, inTypeVal) {
    var subdomaincfg = _config2['default'].SubDomains || { 'socket': '', 'task': '' };
    var candidateDomainCfg = subdomaincfg.candidate || { 'socket': '', 'task': '' };
    var hostname = src.hostname;
    var typeVal = subdomaincfg[inTypeVal] || '';
    var isCandidate = false;
    if (src.hostname.indexOf('candidate') > 0) {
      isCandidate = true;
      typeVal = candidateDomainCfg[inTypeVal] || '';
    }
  
    if (typeVal) {
      typeVal = '-' + typeVal;
    }
  
    if (typeVal) {
      if (hostname.indexOf(typeVal) == -1) {
        var hostnameparts = hostname.split('.');
        var cutpos = hostnameparts[0].indexOf('-');
        if (cutpos == -1) {
          hostnameparts[0] = hostnameparts[0] + typeVal;
        } else {
          hostnameparts[0] = hostnameparts[0].substring(0, cutpos) + typeVal;
        }
        if (isCandidate) {
          hostnameparts[0] = hostnameparts[0] + '-candidate';
        }
        hostname = hostnameparts.join('.');
      }
    } else {
      if (hostname.indexOf('-') > 0) {
        var hostnameparts = hostname.split('.');
        var cutpos = hostnameparts[0].indexOf('-');
        if (cutpos > 0) {
          hostnameparts[0] = hostnameparts[0].substring(0, cutpos);
        }
        if (isCandidate) {
          hostnameparts[0] = hostnameparts[0] + '-candidate';
        }
        hostname = hostnameparts.join('.');
      }
    }
    var port = src.port;
    var protocol = src.protocol;
    if (src.esDomain && src.esDomain.indexOf('local') == -1) {
      protocol = 'https';
    }
    if (port) {
      return protocol + '://' + hostname + ':' + port;
    } else {
      return protocol + '://' + hostname;
    }
  };
  
  exports.getSrcFromRequest = function (req) {
    function getPort() {
      if (req.port) {
        return req.port;
      }
      if (req.esDomain && req.esDomain.indexOf('local') >= 0) {
        return req.app.get('port');
      }
      return '';
    }
  
    function getFullUrl() {
      if (req.fullurl) {
        return req.fullurl;
      }
      var port = getPort();
      var protocol = req.protocol;
      if (req.esDomain && req.esDomain.indexOf('local') == -1) {
        protocol = 'https';
      }
      if (port) {
        return protocol + '://' + req.hostname + ':' + port;
      } else {
        return protocol + '://' + req.hostname;
      }
    }
    return {
      id: req.id,
      type: 'req',
      esDomain: req.esDomain,
      domain: req.esDomain,
      hostname: req.hostname,
      protocol: req.protocol,
      host: req.headers.host,
      fullurl: getFullUrl(),
      relPermChecker: req.relPermChecker,
      user: req.user,
      anonymousUser: req.anonymousUser,
      port: getPort()
    };
  };
  
  exports.getUserRole = function (user, topic, callback) {
    if (user.aType === '') var isMember = _lodash2['default'].find(topic.members, { member: user._id.toString() });
    if (isMember) {
      return callback(isMember.role);
    } else {
      return callback(_fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.GUEST.type);
    }
  };
  
  exports.getIssFromHostnameOld = function (hostname) {
    var parts = hostname.split('.');
    if (parts.length >= 1) {
      return parts.slice(1).join('.');
    } else {
      return hostname;
    }
  };
  
  exports.createPagination = function (req, data) {
    var queryData = data.queryData;
    var results = data.results;
    var nextPageUrl = '';
    var previousPageUrl = '';
    var oriurl = req.originalUrl;
    if (results.havingNextPage) {
      nextPageUrl = oriurl.replace(/\?.*/, '');
      var nextPageUrlQueryStringObj = _lodash2['default'].extend({}, queryData);
      nextPageUrlQueryStringObj.page = nextPageUrlQueryStringObj.page + 1;
      delete nextPageUrlQueryStringObj.prevRefObjId;
      nextPageUrlQueryStringObj.nextRefObjId = results.results[results.results.length - 1]._id.toString();
      nextPageUrl += '?' + _querystring2['default'].stringify(nextPageUrlQueryStringObj);
    }
    if (queryData.page > 1 && results.results.length > 0) {
      previousPageUrl = oriurl.replace(/\?.*/, '');
      var prevPageUrlQueryStringObj = _lodash2['default'].extend({}, queryData);
      prevPageUrlQueryStringObj.page = prevPageUrlQueryStringObj.page - 1;
      delete prevPageUrlQueryStringObj.nextRefObjId;
      prevPageUrlQueryStringObj.prevRefObjId = results.results[0]._id.toString();
      previousPageUrl += '?' + _querystring2['default'].stringify(prevPageUrlQueryStringObj);
    }
    return { data: results.results, nextPageUrl: nextPageUrl, previousPageUrl: previousPageUrl, total: results.results.length };
  };
  
  exports.createPaginationByPage = function (req, data) {
    var queryData = data.queryData;
    var results = data.results;
    var nextPageUrl = '';
    var previousPageUrl = '';
    var oriurl = req.originalUrl;
    if (results.havingNextPage) {
      nextPageUrl = oriurl.replace(/\?.*/, '');
      var nextPageUrlQueryStringObj = _lodash2['default'].extend({}, queryData);
      nextPageUrlQueryStringObj.page = nextPageUrlQueryStringObj.page + 1;
      nextPageUrlQueryStringObj.prev = false;
      nextPageUrl += '?' + _querystring2['default'].stringify(nextPageUrlQueryStringObj);
    }
    if (queryData.page > 1 && results.results.length > 0) {
      previousPageUrl = oriurl.replace(/\?.*/, '');
      var prevPageUrlQueryStringObj = _lodash2['default'].extend({}, queryData);
      prevPageUrlQueryStringObj.page = prevPageUrlQueryStringObj.page - 1;
      prevPageUrlQueryStringObj.prev = true;
      previousPageUrl += '?' + _querystring2['default'].stringify(prevPageUrlQueryStringObj);
    }
    return { data: results.results, nextPageUrl: nextPageUrl, previousPageUrl: previousPageUrl, total: results.results.length };
  };
  
  function getReqLogProperty(obj, outObj, stackdeep) {
    _lodash2['default'].forIn(obj, function (value, key) {
      if (key.startsWith('_') || key == 'domain' || key == 'socket' || key == 'connection') {
        null;
      } else if (typeof value == 'function') {
        null;
      } else if (typeof value == 'object') {
        var tempoutObj = {};
        var tempstackdeep = stackdeep;
        if (key == 'res') {
          null;
        } else if (++tempstackdeep < 3) {
          getReqLogProperty(value, tempoutObj, tempstackdeep);
          outObj[key] = tempoutObj;
        }
      } else {
        if (typeof value == 'string' && value.length > 100) {
          value = value.substring(0, 100) + '... length[' + value.length.toString() + ']';
        }
        outObj[key] = value;
      }
    });
  }
  exports.getReqLogProperty = getReqLogProperty;
  
  exports.requestWillEndSoon = function (req) {
    if (req.taskRequestTimeout) {
      var diffsecds = (req.taskRequestTimeout - Date.now()) / 1000;
      if (diffsecds < 30) {
        return true;
      }
    }
    return false;
  };
  
  exports.getListOfItemCaps = function (inSize, maxSize) {
    var maxsize = maxSize || _serverConstants2['default'].defaultMaxlistSize;
    inSize = parseInt(inSize);
    if (!inSize) {
      return maxsize;
    }
    return Math.min(inSize, maxsize);
  };
  
  exports.getSrcFromSocket = function (socket) {
    var functionName = '[getSrcFromSocket] ';
    var retData = {
      hostname: socket.request.headers.host,
      protocol: 'https'
    };
    if (socket.request.headers.referer) {
      var urlObj = _url2['default'].parse(socket.request.headers.referer);
      retData.hostname = urlObj.hostname;
      retData.protocol = urlObj.protocol.substring(0, urlObj.protocol.length - 1);
      retData.port = urlObj.port;
      return retData;
    } else {
      console.warn(functionName + "There is no referer in socket.request.headers");
      return retData;
    }
  };
  
  exports.getPicture_url = function (picturefile) {
    if (!picturefile) {
      return 'https://www.onesna.com/norevimages/noimage.jpg';
    }
    if (picturefile.indexOf('http://') > -1 || picturefile.indexOf('https://') > -1) {
      return picturefile;
    }
  
    return 'https://storage.googleapis.com/' + _config2['default'].bucket + '/' + picturefile;
  };
  
  exports.getTagsByType = function (obj, objType) {
    return [];
    function userTagGetter() {
      return (function () {
        var _ref = [];
        var _arr = [obj.username, obj.displayname];
  
        for (var _i = 0; _i < _arr.length; _i++) {
          var i = _arr[_i];
  
          if (i.length > 0) {
            _ref.push(_serverConstants2['default'].userTagPrefix + i);
          }
        }
  
        return _ref;
      })();
    }
    function topicTagGetter() {
      return (function () {
        var _ref2 = [];
        var _arr2 = [obj.title, obj.description];
  
        for (var _i2 = 0; _i2 < _arr2.length; _i2++) {
          var i = _arr2[_i2];
  
          if (i.length > 0) {
            _ref2.push(_serverConstants2['default'].topicTagPrefix + i);
          }
        }
  
        return _ref2;
      })();
    }
    var handles = {};
    handles[_serverConstants2['default'].TypeUser] = userTagGetter;
    handles[_serverConstants2['default'].TypeAnonymous] = userTagGetter;
    handles[_serverConstants2['default'].TypeTopic] = topicTagGetter;
    if (objType in handles) {
      return handles[objType]();
    } else {
      return [];
    }
  };

/***/ },
/* 7 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Created by ericd on 27/11/2015.
   */
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _authAuthService = __webpack_require__(15);
  
  var _authAuthService2 = _interopRequireDefault(_authAuthService);
  
  var _authAuthorizers = __webpack_require__(24);
  
  var _authAuthorizers2 = _interopRequireDefault(_authAuthorizers);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _authLru = __webpack_require__(77);
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var trycatch = null;
  /** The trycatch module will cause stack ouput from build folder.
   *  Only product enviroment will apply this module.
   */
  if (process.env.NODE_ENV === 'logan-production') {
    trycatch = __webpack_require__(193);
  }
  
  var getToken = function getToken(req, cb) {
    var header;
    if (req.headers && req.headers.authorization) {
      header = req.headers.authorization;
    }
    return header;
  };
  
  var ViewBase = (function () {
    _createClass(ViewBase, null, [{
      key: 'AUTHENTICATORS',
      value: [_authAuthService2['default'].JwtAuthenticator, _authAuthService2['default'].Oauth2Authenticator, _authAuthService2['default'].AnonymousAuthenticator],
      enumerable: true
    }, {
      key: 'AUTHORIZERS',
      value: [_authAuthorizers2['default'].OAuthAuthorizer],
      enumerable: true
    }, {
      key: 'OAUTHSCOPE',
      value: [_utilsServerConstants2['default'].OAuth2ScopeLogan],
      enumerable: true
    }, {
      key: 'USECACHE',
      value: true,
      enumerable: true
    }]);
  
    function ViewBase(ViewClass) {
      _classCallCheck(this, ViewBase);
  
      var authenticators = ViewClass.AUTHENTICATORS || [];
      this.authenticators = [];
      var _iteratorNormalCompletion = true;
      var _didIteratorError = false;
      var _iteratorError = undefined;
  
      try {
        for (var _iterator = authenticators[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
          var authenticatorItem = _step.value;
  
          this.authenticators.push(new authenticatorItem());
        }
      } catch (err) {
        _didIteratorError = true;
        _iteratorError = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion && _iterator['return']) {
            _iterator['return']();
          }
        } finally {
          if (_didIteratorError) {
            throw _iteratorError;
          }
        }
      }
  
      this.oauthscope = ViewClass.OAUTHSCOPE || [];
      this.useCache = ViewClass.USECACHE;
      var authorizers = ViewClass.AUTHORIZERS || [];
      this.authorizers = [];
      if (authorizers.indexOf(_authAuthorizers2['default'].OAuthAuthorizer) === -1) {
        this.authorizers.push(new _authAuthorizers2['default'].OAuthAuthorizer());
      }
      var _iteratorNormalCompletion2 = true;
      var _didIteratorError2 = false;
      var _iteratorError2 = undefined;
  
      try {
        for (var _iterator2 = authorizers[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
          var authorizerItem = _step2.value;
  
          if (authorizerItem instanceof _authAuthorizers2['default'].PermissionAuthorizer) {
            this.authorizers.push(authorizerItem);
          } else {
            this.authorizers.push(new authorizerItem());
          }
        }
      } catch (err) {
        _didIteratorError2 = true;
        _iteratorError2 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion2 && _iterator2['return']) {
            _iterator2['return']();
          }
        } finally {
          if (_didIteratorError2) {
            throw _iteratorError2;
          }
        }
      }
    }
  
    _createClass(ViewBase, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        _modulesLoggerIndex2['default'].error(req.id, _errorsErrors2['default'].getMessageByCode(_errorsErrors2['default'].ViewNotImplement));
        return res.status(500).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SysUnkownError));
      }
    }, {
      key: 'checkAuthentication',
      value: function checkAuthentication(req, res, cb) {
        var token, cachedApi, cachedUser;
        var self = this;
        if (this.authenticators.length === 0) {
          return cb(null);
        }
  
        token = getToken(req);
        cachedApi = _authLru.apiCache.get(token);
        if (cachedApi && cachedApi.cacheId) {
          cachedUser = _authLru.userCache.get(cachedApi.cacheId);
        }
        if (self.useCache && token && cachedApi && cachedUser) {
          _lodash2['default'].assign(req, cachedApi, cachedUser);
          _modulesLoggerIndex2['default'].info(req.id, 'Got user/anonymous from cache ' + cachedApi.cacheId);
          return cb(null);
        } else {
          _async2['default'].eachSeries(this.authenticators, function (authObj, callback) {
            _modulesLoggerIndex2['default'].info(req.id, 'Check authentication by ' + authObj.name);
            authObj.auth(req, res, function (err) {
              if (!err) {
                _modulesLoggerIndex2['default'].info(req.id, 'Pass authenticator ' + authObj.name);
                var cacheId = req.user ? 'user-' + req.user._id : 'anonymous-' + req.anonymousUser._id;
                var cacheReq = {
                  auth: req.auth,
                  cacheId: cacheId
                };
                var cacheUser = {
                  user: req.user,
                  anonymousUser: req.anonymousUser
                };
                _modulesLoggerIndex2['default'].info(req.id, 'Caching User with Id: ', cacheId);
                _authLru.apiCache.set(token, cacheReq);
                _authLru.userCache.set(cacheId, cacheUser);
                callback(_utilsServerConstants2['default'].StopFlag);
              } else {
                _modulesLoggerIndex2['default'].info(req.id, 'Failed pass authenticator ' + authObj.name + ' try next');
                self.es_error = err;
                callback(null);
              }
            });
          }, function (err) {
            if (err == _utilsServerConstants2['default'].StopFlag) {
              return cb(null);
            } else {
              return cb(self.es_error);
            }
          });
        }
      }
    }, {
      key: 'checkAuthorization',
      value: function checkAuthorization(req, res, cb) {
        var self = this;
        if (this.authorizers.length === 0) {
          return cb(null);
        }
  
        _async2['default'].eachSeries(this.authorizers, function (authObj, callback) {
          _modulesLoggerIndex2['default'].info(req.id, 'Check authorization by ' + authObj.name);
          authObj.check(req, res, self, function (err) {
            if (err) {
              _modulesLoggerIndex2['default'].info(req.id, 'Failed authorization ' + authObj.name);
              self.es_error = err;
              callback(_utilsServerConstants2['default'].StopFlag);
            } else {
              _modulesLoggerIndex2['default'].info(req.id, 'Pass authorization ' + authObj.name + ' check next');
              callback(null);
            }
          });
        }, function (err) {
          if (err == _utilsServerConstants2['default'].StopFlag) {
            return cb(self.es_error);
          } else {
            return cb(null);
          }
        });
      }
    }, {
      key: '_view_no_error_catch',
      value: function _view_no_error_catch(req, res, cb) {
        var self = this;
        _async2['default'].series([function (callback) {
          self.checkAuthentication(req, res, callback);
        }, function (callback) {
          self.checkAuthorization(req, res, callback);
        }, function (callback) {
          self.handle(req, res, callback);
        }], function (err, results) {
          if (err.code.indexOf(_errorsErrors2['default'].AuthenticateFailed) === 0) {
            _modulesLoggerIndex2['default'].info(req.id, 'Authenticate failed! with authorization ' + req.headers.authorization);
            if (err.code == _errorsErrors2['default'].anonymouse_jwt_auth_4001_failed) {
              return res.status(_utilsServerConstants2['default'].HttpUnauthorizedAnonymousStatus).json(err);
            }
            return res.status(_utilsServerConstants2['default'].HttpUnauthorizedStatus).json(err);
          } else if (err.code.indexOf(_errorsErrors2['default'].AuthorizeFailed) === 0) {
            _modulesLoggerIndex2['default'].info(req.id, 'Authorize failed! with authorization ' + req.headers.authorization);
            return res.status(_utilsServerConstants2['default'].HttpForbiddenStatus).json(err);
          }
          _modulesLoggerIndex2['default'].info(req.id, 'Happen unkown err', err);
          return res.status(_utilsServerConstants2['default'].HttpCriticalErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SysUnkownError));
        });
      }
    }, {
      key: 'view',
      value: function view(req, res, cb) {
        var self = this;
        if (trycatch) {
          trycatch(function () {
            self._view_no_error_catch(req, res, cb);
          }, function (err) {
            var reqVal = {};
            _utilsServerHelper2['default'].getReqLogProperty(req, reqVal, 0);
            _modulesLoggerIndex2['default'].info(req.id, 'Production is brought down', reqVal);
            _modulesLoggerIndex2['default'].error(req.id, 'Production is brought down', err);
            return res.status(_utilsServerConstants2['default'].HttpCriticalErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SysUnkownError));
          });
        } else {
          this._view_no_error_catch(req, res, cb);
        }
      }
    }]);
  
    return ViewBase;
  })();
  
  function asView(ViewClass) {
    var viewObj = new ViewClass(ViewClass);
    function wapper(req, res, cb) {
      viewObj.view(req, res, cb);
    }
    return wapper;
  }
  
  var serverCallView = (function (_ViewBase) {
    _inherits(serverCallView, _ViewBase);
  
    function serverCallView() {
      _classCallCheck(this, serverCallView);
  
      _get(Object.getPrototypeOf(serverCallView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(serverCallView, null, [{
      key: 'AUTHENTICATORS',
      value: [_authAuthService2['default'].EsnaServerAuthenticator],
      enumerable: true
    }]);
  
    return serverCallView;
  })(ViewBase);
  
  var regUserCallView = (function (_ViewBase2) {
    _inherits(regUserCallView, _ViewBase2);
  
    function regUserCallView() {
      _classCallCheck(this, regUserCallView);
  
      _get(Object.getPrototypeOf(regUserCallView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(regUserCallView, null, [{
      key: 'AUTHORISERS',
      value: [_authAuthorizers2['default'].OAuthAuthorizer, _authAuthorizers2['default'].regOnlyAuthorizer],
      enumerable: true
    }]);
  
    return regUserCallView;
  })(ViewBase);
  
  var anyCallView = (function (_ViewBase3) {
    _inherits(anyCallView, _ViewBase3);
  
    function anyCallView() {
      _classCallCheck(this, anyCallView);
  
      _get(Object.getPrototypeOf(anyCallView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(anyCallView, null, [{
      key: 'AUTHENTICATORS',
      value: [_authAuthService2['default'].JwtAuthenticator, _authAuthService2['default'].Oauth2Authenticator, _authAuthService2['default'].AnonymousAuthenticator],
      enumerable: true
    }]);
  
    return anyCallView;
  })(ViewBase);
  
  var anyCall4001View = (function (_ViewBase4) {
    _inherits(anyCall4001View, _ViewBase4);
  
    function anyCall4001View() {
      _classCallCheck(this, anyCall4001View);
  
      _get(Object.getPrototypeOf(anyCall4001View.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(anyCall4001View, null, [{
      key: 'AUTHENTICATORS',
      value: [_authAuthService2['default'].JwtAuthenticator, _authAuthService2['default'].Oauth2Authenticator, _authAuthService2['default'].AnonymousAuthenticator4001],
      enumerable: true
    }]);
  
    return anyCall4001View;
  })(ViewBase);
  
  var DeveloperAdminView = (function (_ViewBase5) {
    _inherits(DeveloperAdminView, _ViewBase5);
  
    function DeveloperAdminView() {
      _classCallCheck(this, DeveloperAdminView);
  
      _get(Object.getPrototypeOf(DeveloperAdminView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(DeveloperAdminView, null, [{
      key: 'AUTHORIZERS',
      value: [_authAuthorizers2['default'].DeveloperAdminAuthorizer],
      enumerable: true
    }]);
  
    return DeveloperAdminView;
  })(ViewBase);
  
  exports['default'] = {
    ViewBase: ViewBase,
    asView: asView,
    serverCallView: serverCallView,
    anyCallView: anyCallView,
    anyCall4001View: anyCall4001View,
    DeveloperAdminView: DeveloperAdminView,
    regUserCallView: regUserCallView
  };
  module.exports = exports['default'];

/***/ },
/* 8 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Created by ericd on 26/11/2015.
   */
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  exports.execute = function (scheme, schemeMethod, req_id) {
    var cb = arguments[arguments.length - 1];
    arguments[arguments.length - 1] = function (err, result) {
      if (err) {
        if (err.name == 'ValidationError') {
          for (var field in err.errors) {
            var errorItem = err.errors[field];
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SchemaInvalidHeader + scheme.modelName + '.' + errorItem.path, errorItem.message || 'Happen invalid error'));
          }
        }
        if (err.code == '11000') {
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].DBErrorDuplicateKey, err.errmsg));
        }
        _modulesLoggerIndex2['default'].error(req_id, 'failed', err);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].DBError));
      }
      return cb(null, result);
    };
  
    try {
      var args = Array.prototype.slice.call(arguments, 3);
      schemeMethod.apply(scheme, args);
    } catch (err) {
      _modulesLoggerIndex2['default'].error(req_id, 'call mongoose happen error ', err);
      cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].DBError));
    }
  };

/***/ },
/* 9 */
/***/ function(module, exports) {

  module.exports = require("async");

/***/ },
/* 10 */
/***/ function(module, exports) {

  module.exports = require("express");

/***/ },
/* 11 */
/***/ function(module, exports) {

  module.exports = require("lodash");

/***/ },
/* 12 */
/***/ function(module, exports) {

  module.exports = require("util");

/***/ },
/* 13 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5),
      Schema = mongoose.Schema;
  var integerValidator = __webpack_require__(185);
  var cst = __webpack_require__(2);
  var TopicMessageSchema = new Schema({
  		category: { type: String,
  				validate: [function (v) {
  						return v.length > 0;
  				}, 'category can not be null string']
  		},
  		topicId: { type: Schema.Types.ObjectId }, //The topic id
  		parentMsg: {
  				_id: { type: Schema.Types.ObjectId, index: true },
  				bodyText: { type: String },
  				category: { type: String }
  		}, //The message id
  		chatCount: { type: Number, 'default': 0 },
  		likeCount: { type: Number, 'default': 0 },
  		uniqueLikeId: { type: String, unique: true, sparse: true },
  		sender: {
  				_id: { type: Schema.Types.ObjectId, index: true },
  				type: { type: String }, //user, anonymous
  				username: { type: String },
  				displayname: { type: String },
  				picture_url: { type: String }
  		},
  		created: { type: Date, 'default': Date.now }, //UTC iso //new Date().toISOString()
  		modified: { type: Date }, //UTC iso //new Date().toISOString()	
  		content: {
  				bodyText: String, //optional: simple text typed as comment or message by the user
  				description: String, //optional: description for task objects
  				status: String, //optional: status for task objects
  				dueDate: { type: Date }, //optional UTC for tasks iso //new Date().toISOString()
  				assignees: [{
  						_id: { type: Schema.Types.ObjectId } //user ids withing members
  				}],
  				data: [{
  						_id: false,
  						provider: String,
  						providerFileType: String,
  						fileType: String,
  						name: String,
  						path: String,
  						icon: String,
  						thumbnail: String,
  						keywords: String,
  						description: String,
  						sitename: String,
  						videoProvider: String, //For fileType is video		 
  						fileId: String,
  						previewFile: String,
  						thumbnailFile: String,
  						fileSize: { type: Number, integer: true },
  						convertStatus: { type: Number, integer: true, 'default': cst.ConvertStatusNotStart },
  						pages: { type: Number, integer: true, 'default': 0 },
  						metaData: {
  								paging: { type: Number, integer: true, 'default': 0 },
  								prvwProvd: { type: String, 'default': cst.previewProviderGCS },
  								stgeProvd: { type: String, 'default': cst.storageProviderGCS }
  						}
  				}] //optional: array of possible objects provided by user input like files, images, links
  		}
  });
  
  TopicMessageSchema.plugin(integerValidator);
  /**
   * Virtuals
   */
  
  TopicMessageSchema.set('toJSON', {
  		virtuals: true
  });
  
  TopicMessageSchema.options.toJSON = {
  
  		transform: function transform(doc, ret, options) {
  				delete ret.__v;
  				delete ret.id;
  				delete ret.uniqueLikeId;
  				delete ret.creator;
  				delete ret.parent;
  				if (doc.category != 'task' || !doc.parentMsg) {
  						if (ret.content) {
  								delete ret.content.assignees;
  						}
  				}
  				return ret;
  		},
  		virtuals: true,
  		minimize: true
  };
  
  TopicMessageSchema.virtual('creator').get(function () {
  		return { _id: this.sender._id, aType: this.sender.type };
  });
  
  TopicMessageSchema.virtual('parent').get(function () {
  		return { _id: this.topicId, aType: cst.TypeTopic };
  });
  
  TopicMessageSchema.index({ topicId: 1, created: 1 });
  TopicMessageSchema.index({ topicId: 1, _id: 1 });
  TopicMessageSchema.index({ topicId: 1, category: 1, _id: 1 });
  TopicMessageSchema.index({ topicId: 1, category: 1, "content.dueDate": 1 });
  module.exports = mongoose.model('TopicMessage', TopicMessageSchema);

/***/ },
/* 14 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5);
  var Schema = mongoose.Schema;
  var crypto = __webpack_require__(35);
  var config = __webpack_require__(4);
  var cst = __webpack_require__(2);
  var _ = __webpack_require__(11);
  var isSiteAdmin = __webpack_require__(136);
  
  var UserSchema = new Schema({
    name: {
      familyname: String,
      formatted: String,
      givenname: String,
      honorific_prefix: String,
      honorific_suffix: String,
      middlename: String,
      pronunciation: String,
      pronunciation_url: String
    },
    ndbid: String,
    phone_numbers: [Number],
    addresses: [String],
    gender: String,
    displayname: String,
    lastupdatetime: Date,
    username: { type: String, lowercase: true },
    //
    aType: { type: String, 'default': 'user' }, //  user | anonymous
    hashedPassword: String,
    provider: String,
    salt: String,
    secret: String,
    user_action_required: Boolean,
    emails: [{
      _id: false,
      value: { type: String, lowercase: true },
      type: { type: String },
      primary: Boolean,
      label: String,
      relationdef_id: String,
      cid: { type: Schema.Types.ObjectId, ref: 'Company' }
    }],
    languages: [{
      _id: false,
      code: String,
      primary: Boolean
    }],
    timezone: String,
  
    // picture_url: String,
    picturefile: String,
    relation_graphs: [{
      _id: false,
      relationdef_id: String,
      initiator_id: { type: String, index: true },
      initiator_type: String,
      relation_type: String
    }],
    permissions: [{ type: String }]
  });
  
  /**
   * Indexes
   */
  UserSchema.index({ ndbid: 1 }, { unique: true });
  UserSchema.index({ username: 1 }, { unique: true });
  
  /**
   * Virtuals
   */
  UserSchema.set('toJSON', {
    virtuals: true
  });
  
  UserSchema.options.toJSON = {
  
    transform: function transform(doc, ret, options) {
      delete ret.__v;
      delete ret.id;
      return ret;
    },
    virtuals: true
  };
  
  UserSchema.virtual('password').set(function (password) {
    this._password = password;
    this.salt = this.makeSalt();
    this.hashedPassword = this.encryptPassword(password);
  }).get(function () {
    return this._password;
  });
  
  UserSchema.path('lastupdatetime').set(function (lastupdatetime) {
    this.lastupdatetime = lastupdatetime.toUTCString();
  });
  
  UserSchema.virtual('picture_url').get(function () {
    if (!this.picturefile) {
      return 'https://www.onesna.com/norevimages/noimage.jpg';
    }
    if (this.picturefile.indexOf('http://') > -1 || this.picturefile.indexOf('https://') > -1) {
      return this.picturefile;
    }
    return 'https://storage.googleapis.com/' + config.bucket + '/' + this.picturefile;
  });
  
  // Public profile information
  UserSchema.virtual('profile').get(function () {
    return {
      'name': this.name,
      'displayname': this.displayname,
      'username': this.username,
      'phone_numbers': this.phone_numbers,
      'picture_url': this.picture_url,
      'addresses': this.addresses,
      'gender': this.gender
    };
  });
  
  // Non-sensitive info we'll be putting in the token
  UserSchema.virtual('token').get(function () {
    return {
      '_id': this._id,
      'role': this.role
    };
  });
  
  /**
   * Validations
   */
  
  // Validate empty email
  UserSchema.path('username').validate(function (username) {
    return username.length;
  }, 'Email cannot be blank');
  
  // Validate empty password
  UserSchema.path('hashedPassword').validate(function (hashedPassword) {
    return hashedPassword.length;
  }, 'Password cannot be blank');
  
  // Validate email is not taken
  UserSchema.path('username').validate(function (value, respond) {
    var self = this;
    this.constructor.findOne({ username: value, role: 'user' }, function (err, user) {
      if (err) throw err;
      if (user) {
        if (self.id === user.id) return respond(true);
        return respond(false);
      }
      respond(true);
    });
  }, 'The specified email address is already in use.');
  
  var validatePresenceOf = function validatePresenceOf(value) {
    return value && value.length;
  };
  
  /**
   * Methods
   */
  UserSchema.methods = {
    /**
     * Authenticate - check if the passwords are the same
     *
     * @param {String} plainText
     * @return {Boolean}
     * @api public
     */
    authenticate: function authenticate(plainText) {
      return this.encryptPassword(plainText) === this.hashedPassword;
    },
  
    /**
     * Make salt
     *
     * @return {String}
     * @api public
     */
    makeSalt: function makeSalt() {
      return crypto.randomBytes(16).toString('base64');
    },
  
    /**
     * Encrypt password
     *
     * @param {String} password
     * @return {String}
     * @api public
     */
    encryptPassword: function encryptPassword(password) {
      if (!password || !this.salt) return '';
      var salt = new Buffer(this.salt, 'base64');
      return crypto.pbkdf2Sync(password, salt, 10000, 64).toString('base64');
    }
  };
  
  module.exports = mongoose.model('User', UserSchema);

/***/ },
/* 15 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  //Version 1.0
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _passport = __webpack_require__(25);
  
  var _passport2 = _interopRequireDefault(_passport);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _jsonwebtoken = __webpack_require__(29);
  
  var _jsonwebtoken2 = _interopRequireDefault(_jsonwebtoken);
  
  var _expressJwt = __webpack_require__(173);
  
  var _expressJwt2 = _interopRequireDefault(_expressJwt);
  
  var _composableMiddleware = __webpack_require__(165);
  
  var _composableMiddleware2 = _interopRequireDefault(_composableMiddleware);
  
  var _apiUserUserModel = __webpack_require__(14);
  
  var _apiUserUserModel2 = _interopRequireDefault(_apiUserUserModel);
  
  var _apiAnonymousAnonymousModel = __webpack_require__(30);
  
  var _apiAnonymousAnonymousModel2 = _interopRequireDefault(_apiAnonymousAnonymousModel);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _request = __webpack_require__(19);
  
  var _request2 = _interopRequireDefault(_request);
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _fs = __webpack_require__(43);
  
  var _fs2 = _interopRequireDefault(_fs);
  
  var _oauthAccessTokenAccessTokenModel = __webpack_require__(59);
  
  var _oauthAccessTokenAccessTokenModel2 = _interopRequireDefault(_oauthAccessTokenAccessTokenModel);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _apiUserUserEvent = __webpack_require__(31);
  
  var _apiUserUserEvent2 = _interopRequireDefault(_apiUserUserEvent);
  
  var _apiSyncSyncBackend = __webpack_require__(73);
  
  var _apiSyncSyncBackend2 = _interopRequireDefault(_apiSyncSyncBackend);
  
  var _apiUserUserBackend = __webpack_require__(23);
  
  var _apiUserUserBackend2 = _interopRequireDefault(_apiUserUserBackend);
  
  /**
   * Checks if the user role meets the minimum requirements of the route
   */
  function hasRole(roleRequired) {
    if (!roleRequired) throw new Error('Required role needs to be set');
  
    return (0, _composableMiddleware2['default'])().use(isAuthenticated()).use(function meetsRequirements(req, res, next) {
      if (_config2['default'].userRoles.indexOf(req.user.role) >= _config2['default'].userRoles.indexOf(roleRequired)) {
        next();
      } else {
        res.status(403).send('Forbidden');
      }
    });
  }
  
  /**
   * Returns a jwt token signed by the app secret
   */
  function signToken(id) {
    return _jsonwebtoken2['default'].sign({ _id: id }, _config2['default'].secrets.session, { expiresInMinutes: 60 * 5 });
  }
  
  /**
   * Set token cookie directly for oAuth strategies
   */
  function setTokenCookie(req, res) {
    if (!req.user) return res.status(404).json({ message: 'Something went wrong, please try again.' });
    var token = signToken(req.user._id, req.user.role);
    res.cookie('token', JSON.stringify(token));
    // res.redirect('/');
    return res.status(_utilsServerConstants2['default'].HttpSuccessStatus);
  }
  
  var JwtAuthenticator = (function () {
    function JwtAuthenticator() {
      _classCallCheck(this, JwtAuthenticator);
  
      this.name = 'JwtAuthenticator';
    }
  
    _createClass(JwtAuthenticator, [{
      key: 'getJwtToken',
      value: function getJwtToken(req, cb) {
        var token;
        if (req.headers && req.headers.authorization) {
          var parts = req.headers.authorization.split(' ');
          if (parts.length == 2) {
            var scheme = parts[0].toLowerCase();
            var credentials = parts[1];
  
            if (/^jwt$/i.test(scheme)) {
              token = credentials;
            } else {
              return null;
            }
          } else {
            return null;
          }
        }
        return token;
      }
    }, {
      key: 'getUserOnesna',
      value: function getUserOnesna(cb) {
        var functionName = '[JwtAuthenticator.getUserOnesna] ';
        var url = _config2['default'].getEsnaLink(this.request.esDomain) + '/api/1.0/users/self/logan';
        var token = this.token;
        var options = {
          url: url,
          headers: {
            'Authorization': 'jwt ' + token
          },
          accept: '*/*'
        };
        var self = this;
        _modulesLogger2['default'].info(self.reqId, functionName + 'Access esna by url ' + url);
        _request2['default'].get(options, function (err, response) {
          if (err || response.statusCode !== 200) {
            _modulesLogger2['default'].error(self.reqId, functionName + 'Wrong response!: ');
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AccessOnesnaHappenError));
          }
          return cb(null, response.body);
        });
      }
    }, {
      key: 'get_secret_token_user',
      value: function get_secret_token_user(userid, cb) {
        var functionName = '[JwtAuthenticator.get_secret_token_user] ';
        var self = this;
        var reqid = this.reqId;
        var oldUser = null;
  
        _async2['default'].waterfall([function (callback) {
          var exeobj = _apiUserUserModel2['default'].findOne({ ndbid: userid }, { displayname: 1, lastupdatetime: 1, username: 1, picturefile: 1, permissions: 1, secret: 1, relation_graphs: 1, emails: 1 }).lean();
          _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, reqid, callback);
        }, function (user, callback) {
          if (user) {
            user.aType = _utilsServerConstants2['default'].TypeUser;
            oldUser = user;
          }
          if (!user || user.lastupdatetime.getTime() < new Date(self.payload.lastupdatetime).getTime()) {
            _modulesLogger2['default'].info(reqid, functionName + 'No user found, lets go to onesna');
            self.getUserOnesna(callback);
          } else {
            return cb(null, user);
          }
        }, function (newUser, callback) {
          var loganUser = JSON.parse(newUser);
          loganUser.ndbid = loganUser.id;
          loganUser.secret = loganUser.security_token;
          delete loganUser.id;
          _utilsDbwrapper2['default'].execute(_apiUserUserModel2['default'], _apiUserUserModel2['default'].findOneAndUpdate, reqid, { ndbid: loganUser.ndbid }, loganUser, { upsert: true, 'new': true }, function (err, savedUser) {
            if (!err) {
              return callback(null, savedUser);
            } else if (err.code == _errorsErrors2['default'].DBErrorDuplicateKey) {
              //Under ndbid unique and username unique condition, happen such error only possible be username duplicate
              //To avoid problem of endless loop, get user by username and replace secret in memory to make verify pass
              _modulesLogger2['default'].info(reqid, functionName + 'Happen duplicate username ' + loganUser.username + '. Get user by same username from db!');
              _utilsDbwrapper2['default'].execute(_apiUserUserModel2['default'], _apiUserUserModel2['default'].findOne, reqid, { username: loganUser.username }, function (err, savedUser) {
                if (err || !savedUser) {
                  _modulesLogger2['default'].error(reqid, functionName + 'Failed to get user by username ' + loganUser.username);
                  return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorJWT));
                }
                savedUser.fakeSecret = loganUser.secret;
                return callback(null, savedUser);
              });
            } else {
              return callback(err, savedUser);
            }
          });
        }, function (savedUser, callback) {
          if (!savedUser) {
            _modulesLogger2['default'].error(reqid, functionName + 'Error while save/update Logan user');
            return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].DBError));
          }
          _apiUserUserEvent2['default'].emitUserUpdated({ id: reqid, domain: self.request.esDomain, type: 'req', fn: '[JwtAuthenticator]' }, savedUser, oldUser);
          _modulesLogger2['default'].info(reqid, functionName + 'Logan user saved/updated!');
          return callback(null, savedUser);
        }], function (err, result) {
          if (err) {
            _modulesLogger2['default'].error(reqid, functionName + ' happen error!', err.message);
          }
          return cb(err, result);
        });
      }
    }, {
      key: 'verifyToken',
      value: function verifyToken(secret, token, req, res, cb) {
        var functionName = '[JwtAuthenticator.verifyToken] ';
        var self = this;
        var verify = (0, _expressJwt2['default'])({
          secret: secret + _config2['default'].commonSecretJwt,
          getToken: function getToken() {
            return token;
          }
        });
        verify(req, res, function (err, result) {
          if (err) {
            _modulesLogger2['default'].info(req.id, functionName + 'Verify failed for token ' + token);
            return cb(err);
          } else {
            //verify domain of jwt
            if (_utilsServerHelper2['default'].getIssFromHostname(req.hostname) != self.payload.iss && _utilsServerHelper2['default'].getIssFromHostnameOld(req.hostname) != self.payload.iss) {
              _modulesLogger2['default'].info(req.id, functionName + 'Issure is not correct with value ' + self.payload.iss);
              return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorJWT));
            } else {
              return cb(null);
            }
          }
        });
      }
    }, {
      key: 'auth',
      value: function auth(req, res, cb) {
        var functionName = '[JwtAuthenticator.auth] ';
        var token = this.getJwtToken(req);
        this.reqId = req.id;
  
        if (!token) {
          _modulesLogger2['default'].info(req.id, functionName + 'No jwt token in header');
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorJWT));
        }
        this.token = token;
        var payload = _jsonwebtoken2['default'].decode(token);
        if (!payload) {
          _modulesLogger2['default'].warn(req.id, functionName + 'Payload is undefined in token' + token);
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorJWT));
        }
        if (!payload.user_id) {
          _modulesLogger2['default'].warn(req.id, functionName + 'user_id is undefined in Payload of token' + token);
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorJWT));
        }
        var uid = payload.user_id;
        var self = this;
        var userObj = null;
        this.payload = payload;
        this.request = req;
        _async2['default'].waterfall([function (callback) {
          self.get_secret_token_user(uid, callback);
        }, function (userObj, callback) {
          self.userObj = userObj;
          if (userObj.ndbid == uid) {
            self.verifyToken(userObj.secret, token, req, res, callback);
          } else {
            if (userObj.fakeSecret) {
              self.verifyToken(userObj.fakeSecret, token, req, res, function (err) {
                if (err) {
                  return self.verifyToken(userObj.secret, token, req, res, callback);
                } else {
                  return callback(null);
                }
              });
            } else {
              self.verifyToken(userObj.secret, token, req, res, callback);
            }
          }
        }], function (err, result) {
          if (err) {
            _modulesLogger2['default'].warn(req.id, functionName + 'Verify Token :' + token + ' has Error: ', err);
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorJWT));
          } else {
            if (self.userObj.fakeSecret) {
              delete self.userObj.fakeSecret;
            }
            req.user = self.userObj;
            req.auth = payload;
            req.auth.authenType = _utilsServerConstants2['default'].AuthenticateTypeJWT;
            _apiUserUserBackend2['default'].getUserPermissions(req, req.user, function (err, result) {
              req.user.extendPermissions = result;
              return cb();
            });
          }
        });
      }
    }]);
  
    return JwtAuthenticator;
  })();
  
  var Oauth2Authenticator = (function () {
    function Oauth2Authenticator() {
      _classCallCheck(this, Oauth2Authenticator);
  
      this.name = 'Oauth2Authenticator';
    }
  
    _createClass(Oauth2Authenticator, [{
      key: 'getBearerToken',
      value: function getBearerToken(req) {
        var token;
        if (req.headers && req.headers.authorization) {
          var parts = req.headers.authorization.split(' ');
          if (parts.length == 2) {
            var scheme = parts[0].toLowerCase();
            var credentials = parts[1];
  
            if (/^bearer$/i.test(scheme)) {
              token = credentials;
            } else {
              return null;
            }
          } else {
            return null;
          }
        }
        return token;
      }
    }, {
      key: 'verify',
      value: function verify(token, cb) {
        var functionName = '[Oauth2Authenticator.verify] ';
        var reqid = this.reqId;
        var self = this;
        _async2['default'].waterfall([function (callback) {
          //Get token information from table accesstoken
          _utilsDbwrapper2['default'].execute(_oauthAccessTokenAccessTokenModel2['default'], _oauthAccessTokenAccessTokenModel2['default'].findOne, reqid, { accessToken: token }, callback);
        }, function (accessToken, callback) {
          if (!accessToken) {
            _modulesLogger2['default'].warn(reqid, functionName + "Can't get access token " + token + " from db");
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].OAuth2AccessTokenNotExisted));
          }
          //Check the user is existed in system
          if (new Date(accessToken.expires).getTime() < Date.now()) {
            //Expired
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorOauth2));
          }
          self.accessToken = accessToken;
          var exeobj = _apiUserUserModel2['default'].findOne({ _id: accessToken.userId }, { displayname: 1, lastupdatetime: 1, username: 1, picturefile: 1, permissions: 1, secret: 1, aType: 1, relation_graphs: 1, emails: 1 }).lean();
          _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, reqid, callback);
        }, function (user, callback) {
          //Not exist throw error
          if (!user) {
            _modulesLogger2['default'].warn(reqid, functionName + "Can't get user object by id " + accessToken.userId + " from db");
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorOauth2));
          } else {
            user.aType = _utilsServerConstants2['default'].TypeUser;
            return cb(null, user);
          }
        }], function (err, result) {
          if (err) {
            _modulesLogger2['default'].error(reqid, functionName + 'Happen error!', err);
          }
          return cb(err, result);
        });
      }
    }, {
      key: 'auth',
      value: function auth(req, res, cb) {
        var functionName = '[Oauth2Authenticator.auth] ';
        var token = this.getBearerToken(req);
        if (!token) {
          _modulesLogger2['default'].info(req.id, functionName + 'No oauth2 access token in header');
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorOauth2));
        }
        this.reqId = req.id;
        var self = this;
        this.verify(token, function (err, result) {
          if (err) {
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorOauth2));
          } else {
            req.user = result;
            req.auth = self.accessToken;
            req.auth.authenType = _utilsServerConstants2['default'].AuthenticateTypeOAuth2;
            _apiUserUserBackend2['default'].getUserPermissions(req, req.user, function (err, result) {
              req.user.extendPermissions = result;
              return cb();
            });
          }
        });
      }
    }]);
  
    return Oauth2Authenticator;
  })();
  
  var OnesnaServerAuthenticator = (function () {
    function OnesnaServerAuthenticator() {
      _classCallCheck(this, OnesnaServerAuthenticator);
  
      this.name = 'OnesnaServerAuthenticator';
    }
  
    _createClass(OnesnaServerAuthenticator, [{
      key: 'auth',
      value: function auth(req, res, cb) {
        var functionName = '[OnesnaServerAuthenticator.auth] ';
        if (!req.headers || !req.headers.authorization || req.headers.authorization !== 'API_KEY ' + _config2['default'].ESNA_API_KEY) {
          _modulesLogger2['default'].info(req.id, functionName + 'No api key in header');
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateFailedOnesnaServer));
        }
        return cb();
      }
    }]);
  
    return OnesnaServerAuthenticator;
  })();
  
  var AnonymousAuthenticator = (function () {
    function AnonymousAuthenticator() {
      _classCallCheck(this, AnonymousAuthenticator);
  
      this.name = 'AnonymousAuthenticator';
    }
  
    _createClass(AnonymousAuthenticator, [{
      key: 'getJwtToken',
      value: function getJwtToken(req, cb) {
        var functionName = '[AnonymousAuthenticator.getJwtToken] ';
        var token;
        if (req.headers && req.headers.authorization) {
          var parts = req.headers.authorization.split(' ');
          if (parts.length == 2) {
            var scheme = parts[0].toLowerCase();
            var credentials = parts[1];
  
            if (/^jwt$/i.test(scheme)) {
              token = credentials;
            } else {
              return null;
            }
          } else {
            return null;
          }
        }
        return token;
      }
    }, {
      key: 'getAnonymousUser',
      value: function getAnonymousUser(src, id, callback) {
        var functionName = '[AnonymousAuthenticator.getAnonymousUser] ';
        _utilsDbwrapper2['default'].execute(_apiAnonymousAnonymousModel2['default'], _apiAnonymousAnonymousModel2['default'].findById, null, id, function (err, anonymousUser) {
          if (err || !anonymousUser) {
            _modulesLogger2['default'].error(src.id, functionName + 'Can not get anonymous user from jwt ID ' + id);
            return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorAnonyJWT));
          }
          _modulesLogger2['default'].info(src.id, functionName + 'Get anonymousUser from JWT');
          return callback(null, anonymousUser);
        });
      }
    }, {
      key: 'auth',
      value: function auth(req, res, cb) {
        var functionName = '[AnonymousAuthenticator.auth] ';
        var token = this.getJwtToken(req);
        this.reqId = req.id;
        if (!token) {
          _modulesLogger2['default'].info(req.id, functionName + 'No jwt token in header');
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorAnonyJWT));
        }
        this.token = token;
        var payload = _jsonwebtoken2['default'].decode(token);
        if (!payload) {
          _modulesLogger2['default'].warn(req.id, functionName + 'Payload is undefined in token' + token);
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorAnonyJWT));
        }
        if (payload.anonymous_id) {
          this.getAnonymousUser({ id: req.id }, payload.anonymous_id, function (err, anonymous) {
            if (err) {
              return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorAnonyJWT));
            }
            var verify = (0, _expressJwt2['default'])({
              secret: anonymous.secret,
              getToken: function getToken() {
                return token;
              }
            });
            verify(req, res, function (err, result) {
              if (err) {
                _modulesLogger2['default'].warn(req.id, functionName + 'Verify toekn [' + token + '] failed!');
                return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorAnonyJWT));
              } else {
                req.user = undefined;
                req.anonymousUser = anonymous;
                req.auth = payload;
                req.auth.authenType = _utilsServerConstants2['default'].AuthenticateTypeAnonymous;
                return cb();
              }
            });
          });
        } else {
          _modulesLogger2['default'].warn(req.id, functionName + 'There is no anonymous_id in toekn ' + token);
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorAnonyJWT));
        }
      }
    }]);
  
    return AnonymousAuthenticator;
  })();
  
  var AnonymousAuthenticator4001 = (function (_AnonymousAuthenticator) {
    _inherits(AnonymousAuthenticator4001, _AnonymousAuthenticator);
  
    function AnonymousAuthenticator4001() {
      _classCallCheck(this, AnonymousAuthenticator4001);
  
      _get(Object.getPrototypeOf(AnonymousAuthenticator4001.prototype), 'constructor', this).call(this);
      this.name = 'AnonymousAuthenticator4001';
    }
  
    _createClass(AnonymousAuthenticator4001, [{
      key: 'auth',
      value: function auth(req, res, cb) {
        var functionName = '[AnonymousAuthenticator4001.auth] ';
        return _get(Object.getPrototypeOf(AnonymousAuthenticator4001.prototype), 'auth', this).call(this, req, res, function (err) {
          if (err) {
            _modulesLogger2['default'].error(req.id, functionName + 'Happen error!', err);
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorAnony4001JWT));
          } else {
            return cb();
          }
        });
      }
    }]);
  
    return AnonymousAuthenticator4001;
  })(AnonymousAuthenticator);
  
  var EsnaServerAuthenticator = (function () {
    function EsnaServerAuthenticator() {
      _classCallCheck(this, EsnaServerAuthenticator);
  
      this.name = 'EsnaServerAuthenticator';
    }
  
    _createClass(EsnaServerAuthenticator, [{
      key: 'getApiKey',
      value: function getApiKey(req) {
        var token;
        if (req.headers && req.headers.authorization) {
          var parts = req.headers.authorization.split(' ');
          if (parts.length == 2) {
            var scheme = parts[0].toLowerCase();
            var credentials = parts[1];
            if (/^API_KEY$/i.test(scheme)) {
              token = credentials;
            } else {
              return null;
            }
          } else {
            return null;
          }
        }
        return token;
      }
    }, {
      key: 'auth',
      value: function auth(req, res, cb) {
        var functionName = '[EsnaServerAuthenticator.auth] ';
        var api_key = this.getApiKey(req);
        if (api_key === _config2['default'].ESNA_API_KEY) {
          req.user = {
            _id: '__virtual_id',
            username: 'ServerSuperUser',
            aType: _utilsServerConstants2['default'].TypeUser,
            permissions: ['SITE_ADMIN_PERMISSION_GROUP']
          };
          req.auth = { authenType: _utilsServerConstants2['default'].AuthenticateTypeEsnaServer };
          _apiUserUserBackend2['default'].getUserPermissions(req, req.user, function (err, result) {
            req.user.extendPermissions = result;
            return cb();
          });
        } else {
          _modulesLogger2['default'].info(req.id, functionName + 'api key ' + api_key + ' is not avaliable');
          cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorEsnaServer));
        }
      }
    }]);
  
    return EsnaServerAuthenticator;
  })();
  
  exports['default'] = {
    hasRole: hasRole,
    signToken: signToken,
    setTokenCookie: setTokenCookie,
    JwtAuthenticator: JwtAuthenticator,
    Oauth2Authenticator: Oauth2Authenticator,
    AnonymousAuthenticator: AnonymousAuthenticator,
    AnonymousAuthenticator4001: AnonymousAuthenticator4001,
    EsnaServerAuthenticator: EsnaServerAuthenticator
  };
  module.exports = exports['default'];

/***/ },
/* 16 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var util = __webpack_require__(12),
      EventEmitter = process.EventEmitter,
      instance;
  
  function MessageEvent() {
      EventEmitter.call(this);
  }
  
  util.inherits(MessageEvent, EventEmitter);
  
  MessageEvent.prototype.emitMessageUpdated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('messageUpdated');
      this.emit.apply(this, args);
  };
  
  MessageEvent.prototype.onMessageUpdated = function (callback) {
      this.on('messageUpdated', callback);
  };
  
  MessageEvent.prototype.emitMessageCreated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('messageCreated');
      this.emit.apply(this, args);
  };
  
  MessageEvent.prototype.onMessageCreated = function (callback) {
      this.on('messageCreated', callback);
  };
  
  MessageEvent.prototype.emitMessageDeleted = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('messageDeleted');
      this.emit.apply(this, args);
  };
  
  MessageEvent.prototype.onMessageDeleted = function (callback) {
      this.on('messageDeleted', callback);
  };
  
  MessageEvent.prototype.emitMessageInvited = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('messageInvited');
      this.emit.apply(this, args);
  };
  
  MessageEvent.prototype.onMessageInvited = function (callback) {
      this.on('messageInvited', callback);
  };
  
  MessageEvent.prototype.emitCardDeleted = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('cardDeleted');
      this.emit.apply(this, args);
  };
  
  MessageEvent.prototype.onCardDeleted = function (callback) {
      this.on('cardDeleted', callback);
  };
  
  MessageEvent.prototype.emitUpdateModifyTime = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('updateModifyTime');
      this.emit.apply(this, args);
  };
  
  MessageEvent.prototype.onUpdateModifyTime = function (callback) {
      this.on('updateModifyTime', callback);
  };
  
  MessageEvent.prototype.emitFileConverted = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('fileConverted');
      this.emit.apply(this, args);
  };
  
  MessageEvent.prototype.onFileConverted = function (callback) {
      this.on('fileConverted', callback);
  };
  
  var exportMe = {
      getInstance: function getInstance() {
          return instance || (instance = new MessageEvent());
      }
  };
  
  module.exports = exportMe.getInstance();

/***/ },
/* 17 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
  	value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror = __webpack_require__(41);
  
  var _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror2 = _interopRequireDefault(_node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror);
  
  var _componentsTranslate = __webpack_require__(47);
  
  var _componentsTranslate2 = _interopRequireDefault(_componentsTranslate);
  
  var _TaskConstants = __webpack_require__(81);
  
  var _TaskConstants2 = _interopRequireDefault(_TaskConstants);
  
  var _utilsIs = __webpack_require__(62);
  
  var _utilsIs2 = _interopRequireDefault(_utilsIs);
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var _ZSLogger = __webpack_require__(49);
  
  var _ZSLogger2 = _interopRequireDefault(_ZSLogger);
  
  var ns = '[MessageConstants]';
  var MessageConstants = {};
  MessageConstants.DEFAULT_MESSAGES_PERPAGE = 30;
  MessageConstants.MAX_LONG_TEXT_LENGTH = 500;
  MessageConstants.API = {
  	userChatSearch: '/api/users/{userid}/chat/search/',
  	TOPIC_MESSAGES_BYREF_URL: '/api/topics/{topicid}/messages/byref',
  	TOPIC_MEMBERS_URL: '/api/topics/:topicId/members',
  	TOPIC_TASKS_URL: '/api/topics/:topicId/tasks',
  	TOPIC_IDEAS_URL: '/api/topics/:topicId/ideas',
  	USER_TASKS_URL: '/api/users/:userId/tasks',
  	USER_POSTS_URL: '/api/users/:userId/ideas',
  	USER_NATIVE_FILES_URL: '/api/users/:userId/attachments/natives',
  	roomMessagesRead: '/api/meetings/{roomid}/messagesread',
  	FILE_GET_UPLOAD_URL: '/api/files/getuploadurl',
  	FILE_GET_PUBLIC_UPLOAD_URL: '/api/files/getProfileImageUploadUrl',
  	FILE_GET_DOWNLOAD_URL: '/api/files/getdownloadurl',
  	PARSE_LINK_URL: '/api/messages/parselink',
  	FILE_GET_MESSAGE_FILE_VIEWER_URL: '/api/messages/:msgId/files/:fileId/viewerUrl'
  };
  
  MessageConstants.ACTIONS = (0, _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror2['default'])({
  	SEND_MESSAGE: null,
  	SAVE_QUED_MESSAGE: null,
  	RENDER_MESSAGE: null,
  	ARRIVED_MESSAGE: null,
  	UPDATED_MESSAGE: null,
  	MESSAGE_UPDATED: null,
  	USER_TOPIC_PRESENCE: null,
  	GET_DOWNLOAD_URL: null
  });
  
  MessageConstants.AUDIO_NOTIFICATION_TYPES = {
  	NEW_CHAT: 'new_chat'
  };
  
  MessageConstants.ROOM_PARTY_TYPES = {
  	SE_ROOM_PARTICIPANT_PARTY: 'party',
  	SE_ROOM_PARTICIPANT_ADMIN: 'admin',
  	SE_ROOM_PARTICIPANT_OBSERVER: 'observer'
  };
  
  MessageConstants.DATA_PROVIDER_TYPES = {
  	NATIVE: 'native',
  	URLLINK: 'urllink'
  };
  
  //in seconds
  MessageConstants.MAX_CONVERSION_TIME = 3 * 60;
  MessageConstants.MIN_CONVERSION_TIME = 30;
  MessageConstants.MAX_CONVERSION_TIME_PER_PAGE = 10;
  MessageConstants.MIN_CONVERSION_TIME_PER_PAGE = 2;
  
  MessageConstants.CONVERT_STATUS = {
  	NOT_STARTED: 0,
  	IN_PROGRESS: 1,
  	FINISHED: 2,
  	FAILED: 3
  };
  
  MessageConstants.VIDEO_PROVIDERS = {
  	NATIVE: 'native',
  	YOUTUBE: 'youtube'
  };
  
  MessageConstants.ACTIVITY_CATEGORY_TYPES = {
  	CHAT: 'chat',
  	TASK: 'task',
  	IDEA: 'idea',
  	LIKE: 'like',
  
  	VIDEO_EVENT_TYPE: 'video.event',
  	APP_EVENTS: {
  		TASK_UPDATED: 'app.event.task.updated',
  		IDEA_UPDATED: 'app.event.idea.updated',
  		MESSAGE_UPDATED: 'app.event.message.updated',
  
  		RequestPartiesPresence: 'app.event.presence.request.parties', //'check.parties.presence',
  		PartyEnters: 'app.event.presence.party.enters',
  		PartyOnline: 'app.event.presence.party.online',
  		PartyIdle: 'app.event.presence.party.idle',
  		PartyLeaves: 'app.event.presence.party.leaves',
  
  		VIDEO: {
  			READY: 'video.ready',
  			REQUEST: 'video.request',
  			ACCEPT: 'video.accept',
  			StartScreenShare: 'video.startscreenshare',
  			StopScreenShare: 'video.stopscreenshare',
  			ScreenShareData: 'video.screensharedata',
  			ScreenShareUploadUrl: 'video.screenshare.uploadurl',
  			ScreenShareDownloadUrl: 'video.screenshare.downloadurl',
  
  			EndVideoChat: 'video.end',
  			TracksStatus: 'tracksstatus',
  			RequestAttendeeTracksStatusChange: 'requestattendeetracksstatuschange',
  			AudioTrackStatus: 'audiotrack.status',
  			PartyStatusChanged: 'party.status.changed',
  			PartyTyping: 10,
  			PartySpeaking: 'speaking',
  			PartyStoppedSpeaking: 'speaking.stopped',
  			WebRTCEvents: 'video.webrtc.events',
  
  			StartMediaSession: 'media.session.start',
  			MediaSessionReady: 'media.session.ready',
  			MediaSessionStarted: 'media.session.started',
  			InvalidMediaSession: 'media.session.invalid'
  
  		},
  
  		//topic related events
  		AddedNewParty: 'added.new.party',
  		RemovedParty: 'removed.party',
  		RequestToJoinRoom: 'request.join.room',
  		TopicSettingsUpdated: 'settings.updated'
  	}
  };
  
  function getAllValues(obj, resultList) {
  	_lodash2['default'].forIn(obj, function (value, key) {
  		if (typeof value == 'string') {
  			resultList.push(value);
  		} else if (typeof value == 'object') {
  			getAllValues(value, resultList);
  		}
  	});
  }
  
  var AllCategories = [];
  var AllVideoCategories = [];
  var AllEventCategories = [];
  setTimeout(function () {
  	getAllValues(MessageConstants.ACTIVITY_CATEGORY_TYPES, AllCategories);
  	getAllValues(MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO, AllVideoCategories);
  	getAllValues(MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS, AllEventCategories);
  });
  
  MessageConstants.MSG_TYPES = {
  	TEXT_TYPE: 'text',
  	TASK_TYPE: 'task',
  	IDEA_TYPE: 'idea',
  
  	LINK_TYPE: 'link',
  	LINK_VIDEO_YOUTUBE_TYPE: 'link.video.youtube',
  
  	IMAGE_TYPE: 'image',
  
  	FILE_NATIVE_TYPE: 'file.native',
  	FILE_NATIVE_IMAGE_TYPE: 'file.native.image',
  	FILE_NATIVE_PDF_TYPE: 'file.native.pdf',
  
  	FILE_GOOGLE_TYPE: 'file.google',
  	FILE_GOOGLE_DOC_TYPE: 'file.google.doc',
  	FILE_GOOGLE_SHEET_TYPE: 'file.google.sheet',
  	FILE_GOOGLE_PRESENTATION_TYPE: 'file.google.presentation',
  
  	//legacy events kept for reference.
  	AppEnters: 1,
  	AppLeaves: 2,
  	//Receive: 'event.received',
  
  	ReceiveWhisper: 6,
  	ExistingParties: 7, //indicates existing parties
  	Invite: 8,
  
  	ListOfJoinedPartiesIsAvailable: 13,
  	AppConnectedSuccessfully: 14, //Parameters: RoomData
  	AppUnbleToConnect: 15,
  	IsRoomConnected: 16, //Parameter: ulong RoomID
  	MakeCall: 17,
  	CallFailed: 18,
  	CallCompleted: 19,
  	CallDisconnected: 20,
  	AnnouncementText: 21,
  	AnnouncementVoice: 22,
  
  	InitVideoChat: 25,
  	PartyActivity: 26,
  	PartyTypingStopped: 27,
  	VideoEvent: 'video.event',
  
  	CheckConnection: 'check.connection'
  };
  
  //      CheckVideoSession: 'check.video.session',
  //      VideoInProgress: 'video.in.progress',
  
  MessageConstants.APP_EVENTS = {};
  
  MessageConstants.MAX_IMAGE_SIZE_TO_DISPLAY = 1048576; //2MB
  MessageConstants.THUMBNAIL_SIZE = 480;
  
  //    PRESENCE_TYPES: {
  //      PRESENCE_CHECK_PARITES_PRESENCE: 'check.parties.presence',
  //      PRESENCE_ONLINE: 'online',
  //      PRESENCE_JOINED: 'joined',
  //      PRESENCE_IDLE: 'idle'
  //    },
  MessageConstants.FILE_TYPES = {
  	GOOGLE_DRIVE: 'gdrive'
  };
  
  MessageConstants.LINK_TYPES = {
  	DEFAULT: 'default',
  	GOOGLE_DRIVE_OTHER: 'g-other',
  	GOOGLE_DRIVE_DOC: 'g-doc',
  	GOOGLE_DRIVE_SPREADSHEET: 'g-xls',
  	GOOGLE_DRIVE_PRESENTATION: 'g-ppt',
  	GOOGLE_DRIVE_FORMS: 'g-frm',
  	GOOGLE_DRIVE_DRAW: 'g-drw',
  	YOUTUBE: 'youtube'
  };
  
  MessageConstants.DEFAULT_DATA = {
  	TOPIC_MESSAGES: {
  		BASE_DATA: {
  			id: '',
  			type: '',
  			client_msg_uid: '', //set by client for client reference
  			parents: [{
  				type: 'topic',
  				id: '' //collectionid
  			}, {
  				type: 'message', //for replies or
  				id: '' //collection id
  			}],
  			sender: {
  				id: '',
  				type: 'user' //could by any other sub system
  			},
  			created: '', //UTC iso //new Date().toISOString()
  			content: {
  				body_text: '',
  				data: []
  			}
  		},
  
  		LINK_DATA: {
  			provider: 'link', //required: link, google, native, Dropbox, OneDrive...
  			providerFileType: '', //optional: blank, not applicable
  			filetype: '', //optional: exe, video, pdf,
  
  			path: '', //required: url
  			name: '', //optional: the link title
  			icon: '', //optional: a link to icon
  
  			thumbnail: '', //optional: link to a thumbnail
  			keywords: '', //optional: list of keywords comma delimited from META_DATA
  			description: '', //optional: page description from META_DATA
  			sitename: '' },
  
  		//optional: human
  		SE_CHAT_MESSAGE_TASK_DATA: {
  			bodyText: '',
  			description: '',
  			data: [],
  			assignees: [],
  			status: _TaskConstants2['default'].TASK_STATUS_TYPES.PENDING.status,
  			dueDate: new Date().toISOString()
  		},
  
  		SE_CHAT_MESSAGE_IDEA_DATA: {
  			type: MessageConstants.ACTIVITY_CATEGORY_TYPES.TEXT_TYPE,
  			text: ''
  		},
  
  		SE_CHAT_MESSAGE_IMAGE_DATA: {}
  	}
  };
  
  MessageConstants.generateUUID = function () {
  	var d = new Date().getTime();
  	var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
  		var r = (d + Math.random() * 16) % 16 | 0;
  		d = Math.floor(d / 16);
  		return (c == 'x' ? r : r & 0x7 | 0x8).toString(16);
  	});
  	return uuid;
  };
  
  MessageConstants.isInteractiveDataEvent = function (message) {
  	var func = ns + "[isInteractiveDataEvent] ";
  	try {
  		_ZSLogger2['default'].log(func + "begin: ");
  		if (message.category == MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.RequestToJoinRoom) {
  			return true;
  		}
  	} catch (e) {
  		_ZSLogger2['default'].error(func, e);
  	}
  	return false;
  };
  
  MessageConstants.isMessageEventType = function (message_type) {
  	if (AllEventCategories.length == 0) {
  		getAllValues(MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS, AllEventCategories);
  	}
  	if (AllEventCategories.indexOf(message_type) >= 0) {
  		return true;
  	}
  	return false;
  
  	if (message_type == MessageConstants.ACTIVITY_CATEGORY_TYPES.VIDEO_EVENT_TYPE || message_type in MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS) {
  		return true;
  	}
  	return false;
  };
  
  MessageConstants.isInteractiveEvent = function (messageObj) {
  	if (MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS && (messageObj.category == MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.RequestToJoinRoom || messageObj.category == MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.AddedNewParty || messageObj.category == MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.RemovedParty))
  		//        || (messageObj.message_type == MeetingConstants.MSG_TYPES.VIDEO_EVENT_TYPE
  		//         && (messageObj.message_text.category == MeetingConstants.APP_EVENTS.RequestVideoChat)
  		//        )
  		{
  			return true;
  		}
  	return false;
  };
  
  MessageConstants.isPresenceMessageType = function (messageObj) {
  	if (messageObj.category == MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS || messageObj.category == MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.RequestPartiesPresence || messageObj.category == MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.PartyOnline || messageObj.category == MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.PartyLeaves) {
  		return true;
  	}
  	return false;
  };
  
  MessageConstants.isValidCategory = function (messageObj) {
  	if (AllCategories.length == 0) {
  		getAllValues(MessageConstants.ACTIVITY_CATEGORY_TYPES, AllCategories);
  	}
  	if (AllCategories.indexOf(messageObj.category) >= 0) {
  		return true;
  	}
  	return false;
  };
  
  MessageConstants.isVideoEvent = function (messageObj) {
  	if (AllVideoCategories.length == 0) {
  		getAllValues(MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO, AllVideoCategories);
  	}
  	if (AllVideoCategories.indexOf(messageObj.category) >= 0) {
  		return true;
  	}
  	return false;
  };
  MessageConstants.isViewerMediaSessionEvents = function (messageObj) {
  	var allCats = [MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO.MediaSessionReady];
  	if (allCats.indexOf(messageObj.category) >= 0) {
  		return true;
  	}
  	return false;
  };
  
  MessageConstants.isStorableEventType = function (messageObj) {
  	if (messageObj.category == MessageConstants.ACTIVITY_CATEGORY_TYPES.CHAT || messageObj.category == MessageConstants.ACTIVITY_CATEGORY_TYPES.IDEA || messageObj.category == MessageConstants.ACTIVITY_CATEGORY_TYPES.TASK || messageObj.category == MessageConstants.ACTIVITY_CATEGORY_TYPES.LIKE || MessageConstants.isInteractiveEvent(messageObj)) {
  		return true;
  	}
  	return false;
  };
  
  MessageConstants.isNotifiableMessageType = function (messageObj) {
  	return !MessageConstants.isMessageEventType(messageObj.category);
  };
  
  /*MessageConstants.convertChatMessageTypesToEvents = function (messageObj) {
  	var eventType = '';//MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.Receive;
  	switch (messageObj.message_type) {
  		case MessageConstants.ACTIVITY_CATEGORY_TYPES.VIDEO_EVENT_TYPE:
  			eventType = MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VideoEvent;
  			break;
  		case MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS:
  			eventType = messageObj.message_text.category;
  			break;
  	}
  	return eventType;
  };*/
  
  MessageConstants.stringifyMessage = function (message_text, message_type) {
  	var func = ns + "[stringifyMessage] ";
  	try {
  		if (message_type != MessageConstants.ACTIVITY_CATEGORY_TYPES.TEXT_TYPE) {
  			message_text = JSON.stringify(message_text);
  		}
  	} catch (e) {
  		_ZSLogger2['default'].error(func, e);
  	}
  	return message_text;
  };
  
  MessageConstants.jsonifyMessage = function (message_text, message_type) {
  	var func = ns + "[jsonifyMessage] ";
  	try {
  		if (message_type != MessageConstants.ACTIVITY_CATEGORY_TYPES.TEXT_TYPE) {
  			message_text = JSON.parse(message_text);
  		}
  	} catch (e) {
  		_ZSLogger2['default'].error(func, e);
  	}
  	return message_text;
  };
  
  MessageConstants.isMobileBrowser = function () {
  	var func = ns + '[isMobileBrowser]';
  	var bIsMobile = false;
  	try {
  		if (/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)) {
  			bIsMobile = true;
  			_ZSLogger2['default'].error(ns, 'this is is MOBILE APP');
  		}
  		if ($(window).width() < 760) {
  			bIsMobile = true;
  			//          Log.error(ns, 'SMALL Screen < 760px is DETECTED');
  		} else {
  				//          Log.error(ns, 'Large Screen > 760px is DETECTED');
  			}
  	} catch (e) {
  		_ZSLogger2['default'].error(func, e);
  	}
  	return bIsMobile;
  };
  
  MessageConstants.MSG_FILE_TYPES = {
  	IMAGE: 'image',
  	DOCUMENT: 'document',
  	VIDEO: 'video',
  	AUDIO: 'audio',
  	SPREADSHEET: 'spreadsheet',
  	PRESENTATION: 'presentation',
  	WEBSITE: 'website',
  	MAP: 'map'
  };
  
  MessageConstants.MIME_TYPES = {
  	DOCUMENT: ['application/msword', 'application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.openxmlformats-officedocument.wordprocessingml.template'],
  	SPREADSHEET: ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.openxmlformats-officedocument.spreadsheetml.template'],
  	PRESENTATION: ['application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/vnd.openxmlformats-officedocument.presentationml.template', 'application/vnd.openxmlformats-officedocument.presentationml.slideshow']
  };
  
  MessageConstants.getMessageFileTypeByMime = function (mimeType) {
  	if (!mimeType) {
  		return '';
  	}
  	if (_utilsIs2['default'].$imageMime(mimeType)) {
  		//return (mime=='image/jpeg' || mime=='image/png');
  		return MessageConstants.MSG_FILE_TYPES.IMAGE;
  	}
  	if (_utilsIs2['default'].$videoMime(mimeType)) {
  		//return (mime=='image/jpeg' || mime=='image/png');
  		return MessageConstants.MSG_FILE_TYPES.VIDEO;
  	}
  	if (MessageConstants.MIME_TYPES.DOCUMENT.indexOf(mimeType) > -1) {
  		//return (mime=='image/jpeg' || mime=='image/png');
  		return MessageConstants.MSG_FILE_TYPES.DOCUMENT;
  	}
  	if (MessageConstants.MIME_TYPES.SPREADSHEET.indexOf(mimeType) > -1) {
  		//return (mime=='image/jpeg' || mime=='image/png');
  		return MessageConstants.MSG_FILE_TYPES.SPREADSHEET;
  	}
  	if (MessageConstants.MIME_TYPES.PRESENTATION.indexOf(mimeType) > -1) {
  		//return (mime=='image/jpeg' || mime=='image/png');
  		return MessageConstants.MSG_FILE_TYPES.PRESENTATION;
  	}
  	return '';
  };
  
  MessageConstants.fileIconsClassNames = {
  	'pdf': 'fa fa-file-pdf-o fa-6 preview-file-icon',
  	'doc': 'fa fa-file-word-o fa-6 preview-file-icon',
  	'docx': 'fa fa-file-word-o fa-6 preview-file-icon',
  	'xls': 'fa fa-file-excel-o fa-6 preview-file-icon',
  	'xlsx': 'fa fa-file-excel-o fa-6 preview-file-icon',
  	'generic': 'fa fa-file-o fa-6 preview-file-icon'
  };
  
  MessageConstants.getYouTubeThumbnail = function (vid) {
  	var turl = 'http://img.youtube.com/vi/video_id/hqdefault.jpg';
  	return turl.replace('video_id', vid);
  };
  
  MessageConstants.getYoutubeIDFrom = function (url) {
  	if (_utilsIs2['default'].$array(url)) {
  		url = url[0];
  	}
  	var video_id = url.split('v=')[1];
  	var ampersandPosition = video_id.indexOf('&');
  	if (ampersandPosition != -1) {
  		video_id = video_id.substring(0, ampersandPosition);
  	}
  	return video_id;
  };
  
  MessageConstants.isYouTubeUrl = function (url) {
  	if (_utilsIs2['default'].$array(url)) {
  		url = url[0];
  	}
  	if (url.indexOf('www.youtube.com/') < 0) {
  		return false;
  	}
  	return true;
  };
  
  MessageConstants.getIconClassName = function getIconClassName(name) {
  	var ext = name.split(".").pop();
  	var cls = MessageConstants.fileIconsClassNames[ext];
  	var generic = MessageConstants.fileIconsClassNames['generic'];
  	return cls ? cls : generic;
  };
  
  MessageConstants.getFirstItemWithPreview = function (dataList) {
  	var func = ns + "[getFirstItemWithPreview] ";
  
  	//Log.log(func, 'begin');
  	for (var i in dataList) {
  		if (MessageConstants.getMessageFileTypeByMime(dataList[i].providerFileType) == MessageConstants.MSG_FILE_TYPES.DOCUMENT) {
  			_ZSLogger2['default'].debug(func, 'this is doc', dataList[i]);
  			dataList[i].fileType = MessageConstants.MSG_FILE_TYPES.DOCUMENT;
  		}
  		//if(dataList[i].thumbnailUrl) {
  		//	return dataList[i];
  		//}
  		if (
  		//dataList[i].fileType == MessageConstants.MSG_FILE_TYPES.IMAGE
  		dataList[i].fileType == MessageConstants.MSG_FILE_TYPES.VIDEO || dataList[i].fileType == MessageConstants.MSG_FILE_TYPES.WEBSITE) {
  			var dataItem = dataList[i];
  			//dataList.splice(i, 1);
  			return dataItem;
  		}
  	}
  	//if(dataList.length>0){
  	//	let dataItem = dataList[0];
  	//	//dataList.splice(0, 1);
  	//	//return dataItem;
  	//}
  	return null;
  };
  
  MessageConstants.getRootUrl = function (url) {
  	return url.toString().replace(/^(.*\/\/[^\/?#]*).*$/, "$1");
  };
  MessageConstants.sanitizeMessageObject = function (messageObj) {
  	var func = ns + "[sanitizeMessageObject] ";
  	//validate object
  	messageObj = _lodash2['default'].assign({ content: { data: [] } }, messageObj);
  	if (messageObj.content && !messageObj.content.data) {
  		messageObj.content.data = [];
  	}
  	return messageObj;
  };
  
  MessageConstants.updateChangedProps = function (obj1, changes) {
  	var exceptionKeys = arguments.length <= 2 || arguments[2] === undefined ? [] : arguments[2];
  
  	obj1 = obj1 || {};
  	if (!changes) {
  		return obj1;
  	}
  
  	for (var prop in changes) {
  		if (exceptionKeys.indexOf(prop) < 0) {
  			obj1[prop] = changes[prop];
  		}
  	}
  	return obj1;
  };
  
  MessageConstants.updateAttachmentByFile = function (orgMsgData, file) {
  	var exceptionKeys = arguments.length <= 2 || arguments[2] === undefined ? [] : arguments[2];
  
  	orgMsgData = orgMsgData || [];
  
  	if (!file) {
  		return orgMsgData;
  	}
  
  	for (var i in orgMsgData) {
  		if (orgMsgData[i].fileId && orgMsgData[i].fileId == file.fileId) {
  			orgMsgData[i] = MessageConstants.updateChangedProps(orgMsgData[i], file, exceptionKeys);
  		}
  	}
  	return orgMsgData;
  };
  
  MessageConstants.updateMessageContentDataChanges = function (orgMsgData, changedData) {
  	var exceptionKeys = arguments.length <= 2 || arguments[2] === undefined ? [] : arguments[2];
  
  	orgMsgData = orgMsgData || [];
  
  	if (!changedData) {
  		return orgMsgData;
  	}
  
  	for (var i in changedData) {
  		var file = changedData[i];
  		MessageConstants.updateAttachmentByFile(orgMsgData, file, exceptionKeys);
  	}
  	return orgMsgData;
  };
  
  MessageConstants.updateMessageChanges = function (orgMsgData, changes) {
  	orgMsgData = orgMsgData || {};
  	orgMsgData = MessageConstants.updateChangedProps(orgMsgData, changes, ['sender', 'messageId', 'content', 'category']);
  	orgMsgData.content = MessageConstants.updateChangedProps(orgMsgData.content, changes.content, ['data']);
  	if (orgMsgData.content) {
  		orgMsgData.content.data = MessageConstants.updateMessageContentDataChanges(orgMsgData.content.data, changes.content.data);
  	}
  	orgMsgData._clientChanged = Date.now();
  	return orgMsgData;
  };
  
  exports['default'] = MessageConstants;
  module.exports = exports['default'];

/***/ },
/* 18 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5),
      cst = __webpack_require__(2),
      Schema = mongoose.Schema;
  
  var TopicSchema = new Schema({
      cid: { type: Schema.Types.ObjectId, ref: 'User' }, //creator Id
      created: { type: Date, 'default': Date.now },
      title: String,
      description: String,
      settings: {
          mdSvr: { type: String, "enum": ['p2p', 'ams'], 'default': 'ams' }
      },
      parents: [
      //In most cases they are companies, but in the future maybe other group type?
      { _id: false,
          parentid: { type: Schema.Types.ObjectId },
          parent_type: String
      }],
      members: [{ _id: false,
          member: { type: String, index: true },
          memberType: { type: String, "enum": ['userId', 'email'] }, //  userId
          role: String, //admin | member
          joinTime: Date,
          username: { type: String },
          displayname: { type: String },
          picture_url: { type: String }
      }],
      status: { type: Number, 'default': 0 }, // 0 means normal, 1 means hide,
      restrict: { type: Array, 'default': [] } //deny_guest_read_idea, deny_guest_read_task
  });
  
  /**
   * Virtuals
   */
  TopicSchema.set('toJSON', {
      virtuals: true
  });
  
  TopicSchema.path('restrict').set(function (restrict) {
      if (restrict.length != cst.defaultRestrictValue.length) {
          return restrict;
      }
      for (var retrictIdx in restrict) {
          var retrictItem = restrict[retrictIdx];
          var defaultRestrictValueItem = cst.defaultRestrictValue[retrictIdx];
          if (retrictItem != defaultRestrictValueItem) {
              return restrict;
          }
      }
      //Default value will always transfer to empty array.
      return [];
  });
  
  TopicSchema.options.toJSON = {
  
      transform: function transform(doc, ret, options) {
          delete ret.__v;
          delete ret.id;
          return ret;
      },
      virtuals: true,
      minimize: true
  };
  
  var paginationPlugin = function paginationPlugin(schema) {
      schema.statics.paginate = mongoosePagination;
  };
  
  var mongoosePagination = function mongoosePagination(query, options, callback) {
  
      /**
      * @param {Object}              [query={}]
      * @param {Object}              [options={}]
      * @param {Object|String}       [options.sort]
      * @param {Number}              [options.limit=10]
      * @param {Function}            [callback]
      *
      * @returns {Promise}
      */
  
      var sort = options.sort,
          limit = options.limit || 0;
      // queryString,
      // next,
      // previous,
  
      return this.find(query).sort(sort).limit(limit).exec(callback);
  };
  
  // TopicSchema.static.paginate = mongoosePagination;
  TopicSchema.plugin(paginationPlugin);
  
  module.exports = mongoose.model('Topic', TopicSchema);

/***/ },
/* 19 */
/***/ function(module, exports) {

  module.exports = require("request");

/***/ },
/* 20 */
/***/ function(module, exports) {

  module.exports = require("path");

/***/ },
/* 21 */
/***/ function(module, exports) {

  module.exports = require("process");

/***/ },
/* 22 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * author: Eric Ding
   */
  
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _agenda = __webpack_require__(157);
  
  var _agenda2 = _interopRequireDefault(_agenda);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _process = __webpack_require__(21);
  
  var _process2 = _interopRequireDefault(_process);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  global.deferHandleDict = {};
  
  exports.registerDeferHandle = function (keyString, funcObj) {
    setTimeout(function () {
      if (keyString in global.deferHandleDict) {
        _modulesLogger2['default'].warn('sysloading', 'registerDeferHandle happen already registered error for keyString=' + keyString);
      } else {
        _modulesLogger2['default'].info('sysloading', 'registerDeferHandle load defer with keyString=' + keyString + ' successfully!');
        global.deferHandleDict[keyString] = funcObj;
      }
    });
  };
  
  exports.getDeferHandleByKeyString = function (keyString) {
    if (keyString in global.deferHandleDict) {
      return global.deferHandleDict[keyString];
    }
    _modulesLogger2['default'].warn('sysloading', 'registerDeferHandle not existed');
    throw new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SysAlreadyRegisterDeferError);
  };
  
  exports.TimerWayLauchDefer = function (src, keyString) {
    var _this = this,
        _arguments = arguments;
  
    try {
      var tempoptions;
      var parametersFuncObj;
      var options;
  
      (function () {
        _modulesLogger2['default'].info('Begin starting defer with keyString = ' + keyString);
        var funcObj = _this.getDeferHandleByKeyString(keyString);
        tempoptions = _arguments[_arguments.length - 1];
        parametersFuncObj = Array.prototype.splice.call(_arguments, 2);
        options = { delay: 0,
          attempts: 0,
          backoff_seconds: 0,
          callback: null };
  
        if (Object.prototype.toString.call(tempoptions) == '[object Object]' && tempoptions.defferOption) {
          //Remove the last element from parameterFuncObj
          parametersFuncObj = Array.prototype.splice.call(parametersFuncObj, 0, parametersFuncObj.length - 1);
          options = {
            delay: tempoptions.delay || options.delay,
            attempts: tempoptions.attempts || options.attempts,
            backoff_seconds: tempoptions.backoff_seconds || options.backoff_seconds,
            callback: tempoptions.callback || options.callback
          };
        }
        parametersFuncObj[0]._taskoptions = { attempts: 0, attempt_times: 0 };
        Array.prototype.splice.call(parametersFuncObj, 0, 0, src);
  
        var tmoutObj = setTimeout(function (inParametersFuncObj) {
          var parametersFuncObjTemp = JSON.parse(inParametersFuncObj);
          parametersFuncObjTemp.push(function () {});
          funcObj.apply(funcObj, parametersFuncObjTemp);
        }, options.delay * 1000, JSON.stringify(parametersFuncObj));
  
        var deferOut = {
          deferOutObj: tmoutObj,
          aType: _utilsServerConstants2['default'].deferOutTimeout
        };
        if (options.callback) {
          options.callback(null, tmoutObj);
        }
      })();
    } catch (err) {
      _modulesLogger2['default'].warn(src.id, 'Start defer with keyString = ' + keyString + ' failed!');
    }
  };
  
  var agenda = null;
  function getAgenda(cb) {
    var mongoConnectionString = _config2['default'].mongo.uri;
    if (!agenda) {
      (function () {
        var tempagenda = new _agenda2['default']({ mongo: _mongoose2['default'].connection,
          db: { collection: 'jobCollectionName' }
        });
        tempagenda.on('ready', function () {
          _modulesLogger2['default'].info('Agenda is ready');
          agenda = tempagenda;
        });
      })();
    }
    if (cb) {
      cb(agenda);
    }
  }
  
  setTimeout(getAgenda, 0);
  
  exports.agendaLauchDefer = function (src, keyString) {
    var _arguments2 = arguments;
  
    getAgenda(function (agenda) {
      var url = _utilsServerHelper2['default'].getFullUrlByType(src, 'task') + '/api/taskqueue/runner';
      var tempoptions = _arguments2[_arguments2.length - 1];
      var parametersFuncObj = Array.prototype.splice.call(_arguments2, 2);
      var options = { delay: 0,
        attempts: 0,
        backoff_seconds: 0,
        callback: null };
      if (Object.prototype.toString.call(tempoptions) == '[object Object]' && tempoptions.defferOption) {
        //Remove the last element from parameterFuncObj
        parametersFuncObj = Array.prototype.splice.call(parametersFuncObj, 0, parametersFuncObj.length - 1);
        options = {
          delay: tempoptions.delay || options.delay,
          attempts: tempoptions.attempts || options.attempts,
          backoff_seconds: tempoptions.backoff_seconds || options.backoff_seconds,
          callback: tempoptions.callback || options.callback
        };
      }
  
      options.url = url;
      options.keyString = keyString;
      options.attempt_times = 0;
      options.args = JSON.stringify(parametersFuncObj);
      var callback = options.callback;
      delete options.callbac;
      var job = agenda.schedule(options.delay.toString() + ' seconds', 'defer task', options, function (err, result) {
        if (err) {
          _modulesLogger2['default'].error(src.id, 'Dispatch task happen error', err);
        }
        if (callback) {
          var deferOut = {
            deferOutObj: result,
            aType: _utilsServerConstants2['default'].deferOutAgendaJob
          };
          callback(err, result);
        }
      });
    });
  };
  
  exports.launchDefer = function (src, keyString) {
    if (_process2['default'].env.DeferType && _process2['default'].env.DeferType === 'timeout') {
      exports.TimerWayLauchDefer.apply(this, arguments);
    } else {
      exports.agendaLauchDefer.apply(this, arguments);
    }
  };
  
  exports.runner = function (src, options, cb) {
    _modulesLogger2['default'].info(src.id, 'Try to call function ' + options.keyString);
    try {
      var funcObj = this.getDeferHandleByKeyString(options.keyString);
      //Push callback function to the end of args
      var args = JSON.parse(options.args);
      args[0]._taskoptions = { attempts: options.attempts, attempt_times: options.attempt_times };
      args.unshift(src);
      args.push(cb);
      funcObj.apply(funcObj, args);
    } catch (err) {
      _modulesLogger2['default'].warn(src.id, 'Start defer with keyString = ' + options.keyString + ' failed!');
      cb(err);
    }
  };

/***/ },
/* 23 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Backend non api functions
   */
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var _userModel = __webpack_require__(14);
  
  var _userModel2 = _interopRequireDefault(_userModel);
  
  var _topicTopicModel = __webpack_require__(18);
  
  var _topicTopicModel2 = _interopRequireDefault(_topicTopicModel);
  
  var _modulesUtils = __webpack_require__(40);
  
  var _modulesUtils2 = _interopRequireDefault(_modulesUtils);
  
  var _inviteInviteBackend = __webpack_require__(55);
  
  var _inviteInviteBackend2 = _interopRequireDefault(_inviteInviteBackend);
  
  var _userEvent = __webpack_require__(31);
  
  var _userEvent2 = _interopRequireDefault(_userEvent);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  var _escapeStringRegexp = __webpack_require__(42);
  
  var _escapeStringRegexp2 = _interopRequireDefault(_escapeStringRegexp);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _relationRelationgraphModel = __webpack_require__(72);
  
  var _relationRelationgraphModel2 = _interopRequireDefault(_relationRelationgraphModel);
  
  var _relationRelationModel = __webpack_require__(71);
  
  var _relationRelationModel2 = _interopRequireDefault(_relationRelationModel);
  
  var _notifyTopicuserModel = __webpack_require__(46);
  
  var _notifyTopicuserModel2 = _interopRequireDefault(_notifyTopicuserModel);
  
  var _fluxConstantsMeetingConstants = __webpack_require__(39);
  
  var _fluxConstantsMeetingConstants2 = _interopRequireDefault(_fluxConstantsMeetingConstants);
  
  var _relationRelationBackend = __webpack_require__(57);
  
  var _relationRelationBackend2 = _interopRequireDefault(_relationRelationBackend);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _authPermissiongroupModel = __webpack_require__(79);
  
  var _authPermissiongroupModel2 = _interopRequireDefault(_authPermissiongroupModel);
  
  var _taskqueueTaskqueueBackend = __webpack_require__(22);
  
  var _taskqueueTaskqueueBackend2 = _interopRequireDefault(_taskqueueTaskqueueBackend);
  
  var _util = __webpack_require__(12);
  
  var _util2 = _interopRequireDefault(_util);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _fluxConstantsMessageConstants = __webpack_require__(17);
  
  var _fluxConstantsMessageConstants2 = _interopRequireDefault(_fluxConstantsMessageConstants);
  
  var ObjectId = _mongoose2['default'].Schema.Types.ObjectId;
  // Only test git operation
  
  /**
   * CRUD
   */
  exports.create = function (user, cb) {
    _userModel2['default'].create(topic, function (err, data) {
      if (err) {
        return cb(err);
      }
  
      if (!data) {
        return cb('not retrieving created user');
      } else {
        data.id = data._id;
        delete data._id;
      }
  
      return cb(null, data);
    });
  };
  
  /**
   * First Layer
   */
  
  var cleanUserForTopicInvite = function cleanUserForTopicInvite(invitee, cb) {
    if (invitee.inviteeType === 'email') {
      return cb(null, { email: invitee.invitee, emailType: 'external' });
    } else if (invitee.inviteeType === 'userId') {
      _utilsDbwrapper2['default'].execute(_userModel2['default'], _userModel2['default'].findById, null, invitee.invitee, function (err, user) {
        if (err || !user) {
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
        } else {
          return cb(null, { email: user.username, name: user.displayname, emailType: 'internal' });
        }
      });
    } else {
      return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
    };
  };
  
  exports.inviteUsers = function (src, data, cb) {
    var processUsers = function processUsers(index, ul, callback) {
      if (!ul) {
        return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
      }
  
      var cur_user = ul[index];
      if (!cur_user) {
        return callback(null);
      } else {
        cleanUserForTopicInvite(cur_user, function (err, result) {
          if (err) {
            _modulesLoggerIndex2['default'].error(src.id, 'Error cleaning user object for topicInvite with user', err, cur_user);
            return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
          } else {
            _modulesLoggerIndex2['default'].info(src.id, 'sending invitation email to  ' + result.email);
            _userEvent2['default'].emitUserInvited(src, {
              title: data.topic.title,
              user: result,
              sender: data.creator,
              invite: data.topicInvite
            });
            return processUsers(index + 1, ul, callback);
          }
        });
      }
    };
  
    processUsers(0, data.invitees, function (err) {
      if (err) {
        _modulesLoggerIndex2['default'].error(src.id, err);
        return cb(err);
      }
  
      return cb(null);
    });
  };
  //future change
  exports.listTopicsForMePlugin = function (src, data, cb) {
    var query = {};
    var options = {
      sort: {
        created: 1
      },
      limit: 20
    };
    _utilsDbwrapper2['default'].execute(_topicTopicModel2['default'], _topicTopicModel2['default'].paginate, src.id, query, options, function (err, topics) {
      if (err) {
        _modulesLoggerIndex2['default'].error('there is an error', err);
        return cb(err);
      }
      return cb(null, topics);
    });
  };
  
  exports.listUsersById = function (src, data, cb) {
    src.fn += '[listUsersById]';
    var userList = data.userIds;
    var skip = data.pagination.skip,
        limit = data.pagination.limit + 1;
    var query = {
      $and: [{ '_id': { $in: userList } }]
    };
  
    if (data.search) {
      var str = (0, _escapeStringRegexp2['default'])(data.search);
      query.$and.push({
        $or: [{ 'name.familyname': { $regex: str, $options: 'i' } }, { 'name.formatted': { $regex: str, $options: 'i' } }, { 'name.givenname': { $regex: str, $options: 'i' } }, { 'name.honorific_prefix': { $regex: str, $options: 'i' } }, { 'name.honorific_suffix': { $regex: str, $options: 'i' } }, { 'name.middlename': { $regex: str, $options: 'i' } }, { 'name.pronunciation': { $regex: str, $options: 'i' } }, { displayname: { $regex: str, $options: 'i' } }, { username: { $regex: str, $options: 'i' } }]
      });
    };
    _utilsDbwrapper2['default'].execute(_userModel2['default'], _userModel2['default'].find, src.id, query, {}, { skip: skip, limit: limit }, function (err, users) {
      if (err) {
        _modulesLoggerIndex2['default'].error(src.id, src.fn + 'Error runs query on User table', err);
        return cb(err);
      }
      if (users.length === limit) {
        return cb(null, { data: users.slice(0, -1), hasNext: true });
      }
      return cb(null, { data: users, hasNext: false });
    });
  };
  exports.listRecentAccessedTopicsForUser = function (src, data, cb) {
    listRecentAccessedTopicsByUserId(src, data, cb);
  };
  
  exports.listRecentAccessedTopicsForMe = function (src, data, cb) {
    listRecentAccessedTopicsByUserId(src, data, cb);
  };
  
  function getTopicListFromTopicUserList(src, topicUserOjbs, cb) {
    var functionName = '[getTopicListFromTopicUserList] ';
    if (topicUserOjbs.length == 0) {
      return cb(null, []);
    }
  
    var inList = (function () {
      var _inList = [];
      var _iteratorNormalCompletion = true;
      var _didIteratorError = false;
      var _iteratorError = undefined;
  
      try {
        for (var _iterator = topicUserOjbs[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
          var item = _step.value;
  
          _inList.push(item.targetId);
        }
      } catch (err) {
        _didIteratorError = true;
        _iteratorError = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion && _iterator['return']) {
            _iterator['return']();
          }
        } finally {
          if (_didIteratorError) {
            throw _iteratorError;
          }
        }
      }
  
      return _inList;
    })();
    var stack = [];
    var roles = [];
    var lastaccesstms = [];
    for (var i = inList.length - 1; i >= 0; i--) {
      var rec = {
        "$cond": [{ "$eq": ["$_id", inList[i]] }, i]
      };
      var rolerec = {
        "$cond": [{ "$eq": ["$_id", inList[i]] }, topicUserOjbs[i].role]
      };
  
      var lastaccesstmrec = {
        "$cond": [{ "$eq": ["$_id", inList[i]] }, topicUserOjbs[i].lastAccess]
      };
  
      if (stack.length == 0) {
        rec["$cond"].push(i + 1);
      } else {
        var lval = stack.pop();
        rec["$cond"].push(lval);
      }
      stack.push(rec);
  
      if (roles.length == 0) {
        rolerec["$cond"].push('');
      } else {
        var lval = roles.pop();
        rolerec["$cond"].push(lval);
      }
      roles.push(rolerec);
  
      if (lastaccesstms.length == 0) {
        lastaccesstmrec["$cond"].push(null);
      } else {
        var lval = lastaccesstms.pop();
        lastaccesstmrec["$cond"].push(lval);
      }
      lastaccesstms.push(lastaccesstmrec);
    }
  
    var pipeline = [{ "$match": { "_id": { "$in": inList } } }, { "$project": { "weight": stack[0], "title": 1, "description": 1, "members": 1, "status": 1, "created": 1, "settings": 1, "role": roles[0], "lastAccess": lastaccesstms[0] } }, { "$sort": { "weight": 1 } }, { "$project": { "title": 1, "description": 1, "members": 1, "status": 1, "created": 1, "settings": 1, "role": 1, "lastAccess": 1 } }];
    _topicTopicModel2['default'].aggregate(pipeline, function (err, topicObjs) {
      if (err) {
        _modulesLoggerIndex2['default'].error(src.id, "Topic query by aggregate happen error", err);
        return cb(null, []);
      }
      return cb(null, topicObjs);
    });
  }
  
  var listRecentAccessedTopicsByUserId = function listRecentAccessedTopicsByUserId(src, data, cb) {
    src.fn += '[listRecentAccessedTopicsByUserId]';
    var skip = data.pagination.skip,
        limit = data.pagination.limit + 1,
        ret = {};
    var queryCondition = {
      userId: data.user._id,
      userType: data.user.aType
    };
    var filterType = data.filterType || 'all';
    if (filterType == 'member') {
      queryCondition.role = { '$in': [_fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.ADMIN.type, _fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.MEMBER.type] };
    } else if (filterType == 'guest') {
      queryCondition.role = _fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.GUEST.type;
    }
  
    // TopicUser.find({userId: data.user._id, userType: data.user.aType}).skip(skip).limit(limit).sort({lastAccess: -1}).exec(function (err, results) {
    _notifyTopicuserModel2['default'].find(queryCondition).skip(skip).limit(limit).sort({ lastAccess: -1 }).exec(function (err, results) {
      if (err) {
        _modulesLoggerIndex2['default'].error(src.id, src.fn + 'Error runs query on TopicUser table', err);
        return cb(err);
      }
      //   
      getTopicListFromTopicUserList(src, results, function (err, topicObjs) {
        if (topicObjs.length === limit) {
          ret.hasNext = true;
          topicObjs = topicObjs.slice(0, -1);
        } else {
          ret.hasNext = false;
        }
        ret.data = topicObjs;
        return cb(null, ret);
      });
    });
  };
  //
  exports.listTopicsForUser = function (src, data, cb) {
    data.objId = data.user;
    listTopicsForUserId(src, data, cb);
  };
  
  exports.listTopicsForMe = function (src, data, cb) {
    data.objId = data.user;
    listTopicsForUserId(src, data, cb);
  };
  
  var listTopicsForUserId = function listTopicsForUserId(src, data, cb) {
    src.fn += '[listTopicsForUserId]';
    var ret = {};
    var skip = data.pagination.skip,
        limit = data.pagination.limit + 1,
        query = {
      userId: data.user._id,
      userType: data.user.aType
    };
  
    if (data.search) {
      var str = (0, _escapeStringRegexp2['default'])(data.search);
      //    query.$and.push(
      //        { title: {$regex: str, $options: 'i'} }     
      //    );
      query.title = { $regex: str, $options: 'i' };
    }
  
    _notifyTopicuserModel2['default'].find(query).skip(skip).limit(limit).sort({ title: 1 }).exec(function (err, topicUserObjs) {
      if (err) {
        _modulesLoggerIndex2['default'].error(src.id, src.fn + 'Error runs query on Topic user table', err);
        return cb(err);
      }
      getTopicListFromTopicUserList(src, topicUserObjs, function (err, topicObjs) {
        if (topicObjs.length === limit) {
          ret.hasNext = true;
          topicObjs = topicObjs.slice(0, -1);
        } else {
          ret.hasNext = false;
        }
        ret.data = topicObjs;
        return cb(null, ret);
      });
    });
  };
  
  exports.searchColleagues = function (src, data, cb) {
    src.fn += '[searchColleagues]';
    var query = [];
    var match = {
      $match: {
        $and: []
      }
    };
  
    var userId = data.user._id;
    /*let tempQuery = {
      target_id: data.user._id,
      target_type: cst.TypeUser,
      initiator_type: cst.TypeCompany,
      relation_type: cst.relationEmployee
    };*/
    _utilsDbwrapper2['default'].execute(_userModel2['default'], _userModel2['default'].findById, src.id, userId, 'relation_graphs', function (err, userObj) {
      if (err || !userObj) {
        return cb(null, []);
      }
  
      var rels = (function () {
        var _rels = [];
        var _iteratorNormalCompletion2 = true;
        var _didIteratorError2 = false;
        var _iteratorError2 = undefined;
  
        try {
          for (var _iterator2 = userObj.relation_graphs[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
            var relationItem = _step2.value;
  
            if (relationItem.initiator_type == _utilsServerConstants2['default'].TypeCompany && relationItem.relation_type == _utilsServerConstants2['default'].relationEmployee) {
              _rels.push(relationItem.initiator_id);
            }
          }
        } catch (err) {
          _didIteratorError2 = true;
          _iteratorError2 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion2 && _iterator2['return']) {
              _iterator2['return']();
            }
          } finally {
            if (_didIteratorError2) {
              throw _iteratorError2;
            }
          }
        }
  
        return _rels;
      })();
      match.$match.$and.push({
        'relation_graphs.initiator_id': { $in: rels }
      });
  
      if (data.search) {
        var str = data.search;
        match.$match.$and.push({
          $or: [
          /*{ 'name.familyname': {$regex: str, $options: 'i'} },
          { 'name.formatted': {$regex: str, $options: 'i'} },
          { 'name.givenname': {$regex: str, $options: 'i'} },
          { 'name.honorific_prefix': {$regex: str, $options: 'i'} },
          { 'name.honorific_suffix': {$regex: str, $options: 'i'} },
          { 'name.middlename': {$regex: str, $options: 'i'} },
          { 'name.pronunciation': {$regex: str, $options: 'i'} },*/
          { displayname: { $regex: str, $options: 'i' } }, { username: { $regex: str, $options: 'i' } }]
        });
      }
      query.push(match);
      query.push({ $limit: 5 });
      query.push({
        $project: {
          _id: 1,
          name: 1,
          username: 1,
          picture_url: 1,
          displayname: 1,
          givenname: 1
        }
      });
      _modulesLoggerIndex2['default'].info(src.id, '[searchColleagues] Search user by aggregate condition', query);
      _utilsDbwrapper2['default'].execute(_userModel2['default'], _userModel2['default'].aggregate, src.id, query, function (err, users) {
        if (err) {
          _modulesLoggerIndex2['default'].error(reqid, src.fn + 'Query User happen error', err);
          return cb(null, []);
        } else {
          return cb(null, users);
        }
      });
    });
  };
  
  var listMsgsByUserId = function listMsgsByUserId(src, data, cb) {
    var functionName = '[listMsgsByUserId] ';
    var matchCondition = data.matchCondition;
    var sort = data.sort || { _id: -1 };
  
    if (data.page <= 1) {
      delete data.nextRefObjId;
      delete data.prevRefObjId;
      data.page = 1;
    }
    var includeEqual = data.includeEqual || false;
    delete data.includeEqual;
    if (data.nextRefObjId) {
      if (includeEqual) {
        matchCondition._id = { $lte: _mongoose2['default'].Types.ObjectId(data.nextRefObjId) };
      } else {
        matchCondition._id = { $lt: _mongoose2['default'].Types.ObjectId(data.nextRefObjId) };
      }
      sort = { _id: -1 };
    } else if (data.prevRefObjId) {
      if (includeEqual) {
        matchCondition._id = { $gte: _mongoose2['default'].Types.ObjectId(data.prevRefObjId) };
      } else {
        matchCondition._id = { $gt: _mongoose2['default'].Types.ObjectId(data.prevRefObjId) };
      }
      sort = { _id: 1 };
    }
  
    _modulesLoggerIndex2['default'].info(src.id, functionName + ' Query topic message by following matchCondition, sort, size', matchCondition, sort, data.size + 1);
    var exeobj = _messageMessageModel2['default'].find(matchCondition).sort(sort).limit(data.size + 1).lean();
    _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, results) {
      if (err) {
        _modulesLoggerIndex2['default'].error(src.id, functionName + ' Happen error', err.message);
        return cb(null, { results: [] });
      }
      if (results.length > data.size) {
        if (data.prevRefObjId) {
          results = results.reverse();
          return cb(null, { results: results.slice(1, data.size + 1), havingNextPage: true });
        }
        return cb(null, { results: results.slice(0, data.size), havingNextPage: true });
      } else {
        if (data.prevRefObjId) {
          results = results.reverse();
        }
        return cb(null, { results: results, havingNextPage: false });
      }
    });
  };
  
  exports.listTasksByUserId = function (src, data, cb) {
    var functionName = '[listTasksByUserId] ';
    _modulesLoggerIndex2['default'].info(src.id, functionName + 'Query tasks by userId =' + data.sender.toString());
    data.matchCondition = {
      '$or': [{ "sender._id": data.sender, "sender.type": _utilsServerConstants2['default'].TypeUser }, { 'content.assignees._id': data.sender }],
      category: data.category
    };
    return listMsgsByUserId(src, data, cb);
  };
  
  exports.listIdeasByUserId = function (src, data, cb) {
    var functionName = '[listIdeasByUserId] ';
    _modulesLoggerIndex2['default'].info(src.id, functionName + 'Query ideas by userId =' + data.sender.toString());
    data.matchCondition = {
      "sender._id": data.sender,
      "sender.type": _utilsServerConstants2['default'].TypeUser,
      category: data.category
    };
  
    return listMsgsByUserId(src, data, cb);
  };
  
  exports.listNativesByUserId = function (src, data, cb) {
    var functionName = '[listNativesByUserId] ';
    _modulesLoggerIndex2['default'].info(src.id, functionName + 'Query natives by userId =' + data.sender.toString());
    data.matchCondition = {
      "sender._id": data.sender._id,
      "sender.type": data.sender.aType,
      "content.data.provider": _fluxConstantsMessageConstants2['default'].DATA_PROVIDER_TYPES.NATIVE
    };
  
    return listMsgsByUserId(src, data, cb);
  };
  
  exports.listAssignedTaskByTopic = function (src, data, cb) {
    var matchCondition = {
      "content.assignees._id": data.assignee,
      category: data.category
    };
  
    var sort = { _id: -1 };
    if (data.page <= 1) {
      delete data.nextRefObjId;
      delete data.prevRefObjId;
      data.page = 1;
    }
    var includeEqual = data.includeEqual || false;
    delete data.includeEqual;
    if (data.nextRefObjId) {
      if (includeEqual) {
        matchCondition._id = { $lte: _mongoose2['default'].Types.ObjectId(data.nextRefObjId) };
      } else {
        matchCondition._id = { $lt: _mongoose2['default'].Types.ObjectId(data.nextRefObjId) };
      }
      sort = { _id: -1 };
    } else if (data.prevRefObjId) {
      if (includeEqual) {
        matchCondition._id = { $gte: _mongoose2['default'].Types.ObjectId(data.prevRefObjId) };
      } else {
        matchCondition._id = { $gt: _mongoose2['default'].Types.ObjectId(data.prevRefObjId) };
      }
      sort = { _id: 1 };
    }
    var exeobj = _messageMessageModel2['default'].find(matchCondition).sort(sort).limit(data.size + 1);
    _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, results) {
      if (err) {
        _modulesLoggerIndex2['default'].error(src.id, 'listCategoryByTopic happen error', err.message);
        return cb(null, { results: [] });
      }
      if (results.length > data.size) {
        if (data.prevRefObjId) {
          results = results.reverse();
          return cb(null, { results: results.slice(1, data.size + 1), havingNextPage: true });
        }
        return cb(null, { results: results.slice(0, data.size), havingNextPage: true });
      } else {
        if (data.prevRefObjId) {
          results = results.reverse();
        }
        return cb(null, { results: results, havingNextPage: false });
      }
    });
  };
  
  exports.getUserPermissions = function (src, userObj, cb) {
    var query = {
      $or: []
    };
    var _iteratorNormalCompletion3 = true;
    var _didIteratorError3 = false;
    var _iteratorError3 = undefined;
  
    try {
      for (var _iterator3 = userObj.permissions[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
        var permItem = _step3.value;
  
        query.$or.push({ "permission_name": permItem });
      }
    } catch (err) {
      _didIteratorError3 = true;
      _iteratorError3 = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion3 && _iterator3['return']) {
          _iterator3['return']();
        }
      } finally {
        if (_didIteratorError3) {
          throw _iteratorError3;
        }
      }
    }
  
    if (query.$or.length > 0) {
      var execObj = _authPermissiongroupModel2['default'].find(query).lean();
      _utilsDbwrapper2['default'].execute(execObj, execObj.exec, src, function (err, result) {
        if (err) {
          _modulesLoggerIndex2['default'].warn(src, 'getUserPermissions happes error', err);
          return cb(null, []);
        }
        var retArray = [];
        var _iteratorNormalCompletion4 = true;
        var _didIteratorError4 = false;
        var _iteratorError4 = undefined;
  
        try {
          for (var _iterator4 = result[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
            var permgp = _step4.value;
  
            //retArray = _.concat(retArray, permgp.permissions);
            var _iteratorNormalCompletion5 = true;
            var _didIteratorError5 = false;
            var _iteratorError5 = undefined;
  
            try {
              for (var _iterator5 = permgp.permissions[Symbol.iterator](), _step5; !(_iteratorNormalCompletion5 = (_step5 = _iterator5.next()).done); _iteratorNormalCompletion5 = true) {
                var permItm = _step5.value;
  
                retArray.push(permItm);
              }
            } catch (err) {
              _didIteratorError5 = true;
              _iteratorError5 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion5 && _iterator5['return']) {
                  _iterator5['return']();
                }
              } finally {
                if (_didIteratorError5) {
                  throw _iteratorError5;
                }
              }
            }
          }
        } catch (err) {
          _didIteratorError4 = true;
          _iteratorError4 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion4 && _iterator4['return']) {
              _iterator4['return']();
            }
          } finally {
            if (_didIteratorError4) {
              throw _iteratorError4;
            }
          }
        }
  
        return cb(null, retArray);
      });
    } else {
      return cb(null, []);
    }
  };
  
  var afterInsertUpdateUser = function afterInsertUpdateUser(src, userObj, cb) {
    _modulesLoggerIndex2['default'].info(src.id, "begin call function afterInsertUpdateUser");
    var tagList = [userObj.username];
    var data = { username: userObj.username,
      displayname: userObj.displayname };
  
    var _iteratorNormalCompletion6 = true;
    var _didIteratorError6 = false;
    var _iteratorError6 = undefined;
  
    try {
      for (var _iterator6 = userObj.emails[Symbol.iterator](), _step6; !(_iteratorNormalCompletion6 = (_step6 = _iterator6.next()).done); _iteratorNormalCompletion6 = true) {
        var emailItem = _step6.value;
  
        tagList.push(emailItem.value);
        var emailParts = emailItem.value.split('@');
        if (emailParts.length > 1) {
          tagList.push(_utilsServerConstants2['default'].domainTagPrefix + emailParts[0]);
        }
      }
    } catch (err) {
      _didIteratorError6 = true;
      _iteratorError6 = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion6 && _iterator6['return']) {
          _iterator6['return']();
        }
      } finally {
        if (_didIteratorError6) {
          throw _iteratorError6;
        }
      }
    }
  
    tagList = Array.from(new Set(tagList));
  
    var savedData = {
      destinationId: userObj._id,
      destinationType: _utilsServerConstants2['default'].TypeUser,
      tags: tagList,
      data: data
    };
  
    _async2['default'].waterfall([function (interCallback) {
      var queryCondition = { target_id: userObj._id,
        target_type: _utilsServerConstants2['default'].TypeUser,
        initiator_type: _utilsServerConstants2['default'].TypeCompany };
      var project = 'relationdef_id initiator_id initiator_type relation_type';
      _utilsDbwrapper2['default'].execute(_relationRelationModel2['default'], _relationRelationModel2['default'].find, src.id, queryCondition, project, function (err, relations) {
        if (err) {
          _modulesLoggerIndex2['default'].warn(src.id, 'Get list of relation of user happen error, keep orignial relation');
          savedData.relation_graphs = userObj.relation_graphs;
          relations = [];
        }
        var add_relations = _lodash2['default'].differenceWith(userObj.relation_graphs, relations, function (lRelVal, rRelVal) {
          return lRelVal.relationdef_id == rRelVal.relationdef_id;
        });
        var remove_relations = _lodash2['default'].differenceWith(relations, userObj.relation_graphs, function (lRelVal, rRelVal) {
          return lRelVal.relationdef_id == rRelVal.relationdef_id;
        });
        interCallback(null, userObj, add_relations, remove_relations);
      });
    }, function (userObj, add_relations, remove_relations, interCallback) {
      _async2['default'].parallel([function (interCallback) {
        var updateCondition = { destinationId: userObj._id,
          destinationType: _utilsServerConstants2['default'].TypeUser };
        _utilsDbwrapper2['default'].execute(_relationRelationgraphModel2['default'], _relationRelationgraphModel2['default'].update, src.id, updateCondition, savedData, { upsert: true }, interCallback);
      }, function (interCallback) {
        var added_rels = [];
        var _iteratorNormalCompletion7 = true;
        var _didIteratorError7 = false;
        var _iteratorError7 = undefined;
  
        try {
          for (var _iterator7 = add_relations[Symbol.iterator](), _step7; !(_iteratorNormalCompletion7 = (_step7 = _iterator7.next()).done); _iteratorNormalCompletion7 = true) {
            var add_rel_item = _step7.value;
  
            var added_rel = {
              target_id: userObj._id,
              target_type: _utilsServerConstants2['default'].TypeUser,
              initiator_id: add_rel_item.initiator_id,
              initiator_type: add_rel_item.initiator_type,
              relation_type: add_rel_item.relation_type,
              relationdef_id: add_rel_item.relationdef_id
            };
            added_rels.push(added_rel);
          }
        } catch (err) {
          _didIteratorError7 = true;
          _iteratorError7 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion7 && _iterator7['return']) {
              _iterator7['return']();
            }
          } finally {
            if (_didIteratorError7) {
              throw _iteratorError7;
            }
          }
        }
  
        _relationRelationBackend2['default'].addRelations(src, added_rels, interCallback);
      }, function (interCallback) {
        _relationRelationBackend2['default'].delRelations(src, remove_relations, interCallback);
      }], function (err, results) {
        if (err) {
          _modulesLoggerIndex2['default'].warn(src.id, "happen some error when save data about relation and relationGraph");
        }
        return interCallback(err, results);
      });
    }], function (err, results) {
      if (err) {
        _modulesLoggerIndex2['default'].warn(src.id, "afterInsertUpdateUser happen some error");
      }
      _modulesLoggerIndex2['default'].info(src.id, "End call function afterInsertUpdateUser");
      return cb(err, results);
    });
  };
  
  exports.afterInsertUpdateUser = afterInsertUpdateUser;
  
  //userEvent.onUserCreated((src, newUser) => {
  //  afterInsertUpdateUser(src, newUser, (err, result) => {});
  //});
  //
  _userEvent2['default'].onUserUpdated(function (src, newUser, oldUser) {
    var functionName = '[userEvent.onUserUpdated]';
    if (oldUser) {
      (function () {
        //If username, picturefile and displayname is changed, update all cached sender info in topic message
        var updateFields = {};
        if (oldUser.username != newUser.username) {
          updateFields['sender.username'] = newUser.username;
        }
        if (oldUser.pictureurl != newUser.pictureurl) {
          updateFields['sender.picture_url'] = newUser.picture_url;
        }
        if (oldUser.displayname != newUser.displayname) {
          updateFields['sender.displayname'] = newUser.displayname;
        }
        var data = {};
        data.senderId = newUser._id.toString();
        data.senderType = _utilsServerConstants2['default'].TypeUser;
        data.senderData = updateFields;
        _taskqueueTaskqueueBackend2['default'].launchDefer(src, 'syncMessageSenderDefer', data, { defferOption: true,
          backoff_seconds: 300,
          attempts: 3,
          callback: function callback(err, result) {
            if (!err) {
              _modulesLoggerIndex2['default'].info(src.id, _util2['default'].format('%s Trigger a task to sync topicmessage sender successfully', functionName), data);
            } else {
              _modulesLoggerIndex2['default'].info(src.id, _util2['default'].format('%s Trigger a task to sync topicmessage sender failed', functionName), data);
            }
          }
        });
      })();
    }
  });
  //
  //userEvent.onUserDeleted((src, deletedUser) => {
  //  relationBk.deleteTargetObj(src, deletedUser, cst.TypeUser, (err, result) => {});
  //});
  
  _userEvent2['default'].onUserUpdated(function (src, newUser, oldUser) {
    return;
    var functionName = '[userEvent.onUserUpdated]  ';
    if (oldUser) {
      if (oldUser.username == newUser.username && oldUser.displayname == newUser.displayname) {
        return;
      } else {
        var updateData = {
          cachedObjId: newUser._id.toString(),
          cachedObjType: _utilsServerConstants2['default'].TypeUser,
          cachedObjCompareData: newUser.username + newUser.displayname
        };
        _taskqueueTaskqueueBackend2['default'].launchDefer(src, 'cacheUserToTopicUserDefer', data, { defferOption: true,
          backoff_seconds: 300,
          attempts: 3,
          //Delay 10s to execute the task, let different task with same topic can end itself. 
          delay: 10,
          callback: function callback(err, result) {
            if (!err) {
              _modulesLoggerIndex2['default'].info(src.id, _util2['default'].format('%s Trigger a task to cache user information to topicUser successfully', functionName), data);
            } else {
              _modulesLoggerIndex2['default'].info(src.id, _util2['default'].format('%s Trigger a task to cache user information to topicUser failed', functionName), data);
            }
          }
        });
      }
    }
  });

/***/ },
/* 24 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * http://usejsdoc.org/
   * All authroiser will have unite interface
   * check(req, res, subject, cb)
   */
  
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
      value: true
  });
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _apiTopicTopicModel = __webpack_require__(18);
  
  var _apiTopicTopicModel2 = _interopRequireDefault(_apiTopicTopicModel);
  
  var _apiTopicTopicInviteModel = __webpack_require__(58);
  
  var _apiTopicTopicInviteModel2 = _interopRequireDefault(_apiTopicTopicInviteModel);
  
  var _apiMessageMessageModel = __webpack_require__(13);
  
  var _apiMessageMessageModel2 = _interopRequireDefault(_apiMessageMessageModel);
  
  var _permissionConfig = __webpack_require__(78);
  
  var _permissionConfig2 = _interopRequireDefault(_permissionConfig);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _apiEnrollEnrollModel = __webpack_require__(69);
  
  var _apiEnrollEnrollModel2 = _interopRequireDefault(_apiEnrollEnrollModel);
  
  var logger = __webpack_require__(1);
  
  var OAuthAuthorizer = (function () {
      function OAuthAuthorizer() {
          _classCallCheck(this, OAuthAuthorizer);
  
          this.name = 'OAuthAutherizer';
      }
  
      _createClass(OAuthAuthorizer, [{
          key: 'scopesCompareOtherScopes',
          value: function scopesCompareOtherScopes(userScopes, requiredScopes) {
              if (requiredScopes === undefined || requiredScopes === null) {
                  return _utilsServerConstants2['default'].IncludeScope;
              }
              if (requiredScopes && requiredScopes.length === 0) {
                  return _utilsServerConstants2['default'].NotIncludeScope;
              } else {
                  var _iteratorNormalCompletion = true;
                  var _didIteratorError = false;
                  var _iteratorError = undefined;
  
                  try {
                      for (var _iterator = requiredScopes[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
                          var scope = _step.value;
  
                          if (userScopes.indexOf(scope) < 0) {
                              logger.warn("scope required not matching", scope);
                              return _utilsServerConstants2['default'].NotIncludeScope;
                          }
                      }
                  } catch (err) {
                      _didIteratorError = true;
                      _iteratorError = err;
                  } finally {
                      try {
                          if (!_iteratorNormalCompletion && _iterator['return']) {
                              _iterator['return']();
                          }
                      } finally {
                          if (_didIteratorError) {
                              throw _iteratorError;
                          }
                      }
                  }
  
                  return _utilsServerConstants2['default'].IncludeScope;
              }
          }
      }, {
          key: 'check',
          value: function check(req, res, view, cb) {
              if (req.auth && req.auth.authenType === _utilsServerConstants2['default'].AuthenticateTypeOAuth2) {
                  if (this.scopesCompareOtherScopes(req.auth.scope, view.oauthscope) == _utilsServerConstants2['default'].IncludeScope) {
                      return cb();
                  }
                  return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorOauth2));
              }
              return cb();
          }
      }]);
  
      return OAuthAuthorizer;
  })();
  
  var verifyTopicCreator = function verifyTopicCreator(user, topic, cb) {
      if (!user || !topic) {
          return cb('No user or No topic');
      };
      if (topic.cid.toString() === user._id.toString()) {
  
          return cb();
      }
  
      return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeFailed));
  };
  
  var verifyMessageCreator = function verifyMessageCreator(user, message, cb) {
      if (!user || !message) {
          return cb('No user or No message');
      };
      if (message.sender && message.sender._id && message.sender._id.toString() === user._id.toString()) {
          return cb();
      }
  
      return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeFailed));
  };
  
  var isIdeaCreatorByParams = (function () {
      function isIdeaCreatorByParams() {
          _classCallCheck(this, isIdeaCreatorByParams);
      }
  
      _createClass(isIdeaCreatorByParams, [{
          key: 'check',
          value: function check(req, res, view, cb) {
              if (!req.params || !req.params.ideaId) {
                  return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
              }
              var me = req.anonymousUser || req.user;
  
              _apiMessageMessageModel2['default'].findById(req.params.ideaId, function (err, message) {
                  if (err) {
                      logger.warn(req.id, 'Error find message :' + req.params.ideaId, err);
                      return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
                  }
                  if (!message) {
                      logger.warn(req.id, 'Message not found : ' + req.params.ideaId);
                      return res.status(_utilsServerConstants2['default'].HttpNotFoundStatus).json(_errorsErrors2['default'].NotExsistedError);
                  }
                  verifyMessageCreator(me, message, function (err, result) {
                      if (err) {
                          logger.warn(req.id, 'Fail to authorize user to this message' + req.params.ideaId, err);
                          return cb(err);
                      } else {
                          req.message = message;
                          req.me = me;
                          return cb();
                      }
                  });
              });
          }
      }]);
  
      return isIdeaCreatorByParams;
  })();
  
  var isTaskCreatorByParams = (function () {
      function isTaskCreatorByParams() {
          _classCallCheck(this, isTaskCreatorByParams);
      }
  
      _createClass(isTaskCreatorByParams, [{
          key: 'check',
          value: function check(req, res, view, cb) {
              if (!req.params || !req.params.taskId) {
                  return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
              }
              var me = req.anonymousUser || req.user;
  
              _apiMessageMessageModel2['default'].findById(req.params.taskId, function (err, message) {
                  if (err) {
                      logger.warn(req.id, 'Error find message :' + req.params.taskId, err);
                      return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
                  }
                  if (!message) {
                      logger.warn(req.id, 'Message not found : ' + req.params.taskId);
                      return res.status(_utilsServerConstants2['default'].HttpNotFoundStatus).json(_errorsErrors2['default'].NotExsistedError);
                  }
                  verifyMessageCreator(me, message, function (err, result) {
                      if (err) {
                          logger.warn(req.id, 'Fail to authorize user to this message' + req.params.taskId, err);
                          return cb(err);
                      } else {
                          req.message = message;
                          req.me = me;
                          return cb();
                      }
                  });
              });
          }
      }]);
  
      return isTaskCreatorByParams;
  })();
  
  var isTopicCreatorByParams = (function () {
      function isTopicCreatorByParams() {
          _classCallCheck(this, isTopicCreatorByParams);
      }
  
      _createClass(isTopicCreatorByParams, [{
          key: 'check',
          value: function check(req, res, view, cb) {
              if (!req.params || !req.params.topicId) {
                  return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
              }
              var me = req.anonymousUser || req.user;
  
              _apiTopicTopicModel2['default'].findById(req.params.topicId, function (err, topic) {
                  if (err) {
                      logger.warn(req.id, 'Error find topic :' + req.params.topicId, err);
                      return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
                  }
                  if (!topic) {
                      logger.warn(req.id, 'Topic not found : ' + req.params.topicId);
                      return res.status(_utilsServerConstants2['default'].HttpNotFoundStatus).json(_errorsErrors2['default'].NotExsistedError);
                  }
                  verifyTopicCreator(me, topic, function (err, result) {
                      if (err) {
                          logger.warn(req.id, 'Fail to authorize user to this topic' + req.params.topicId, err);
                          return cb(err);
                      } else {
                          req.topic = topic;
                          req.me = me;
                          return cb();
                      }
                  });
              });
          }
      }]);
  
      return isTopicCreatorByParams;
  })();
  
  var isInviteCreatorByParams = (function () {
      function isInviteCreatorByParams() {
          _classCallCheck(this, isInviteCreatorByParams);
      }
  
      _createClass(isInviteCreatorByParams, [{
          key: 'check',
          value: function check(req, res, view, cb) {
              if (!req.params || !req.params.inviteId) {
                  return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
              }
              var me = req.anonymousUser || req.user;
  
              _apiTopicTopicInviteModel2['default'].findById(req.params.inviteId, function (err, invite) {
                  if (err) {
                      logger.warn(req.id, 'Error find invite :' + req.params.inviteId, err);
                      return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
                  }
                  if (!invite) {
                      logger.warn(req.id, 'Invite not found : ' + req.params.inviteId);
                      return res.status(_utilsServerConstants2['default'].HttpNotFoundStatus).json(_errorsErrors2['default'].NotExsistedError);
                  }
  
                  _apiTopicTopicModel2['default'].findById(invite.topicId, function (err, topic) {
                      verifyTopicCreator(me, topic, function (err, result) {
                          if (err) {
                              logger.warn(req.id, 'Fail to authorize user to this invite' + req.params.inviteId, err);
                              return cb(err);
                          } else {
                              req.topic = topic;
                              req.invite = invite;
                              req.me = me;
                              return cb();
                          }
                      });
                  });
              });
          }
      }]);
  
      return isInviteCreatorByParams;
  })();
  
  var isEnrollAdmin = (function () {
      function isEnrollAdmin() {
          _classCallCheck(this, isEnrollAdmin);
      }
  
      _createClass(isEnrollAdmin, [{
          key: 'check',
          value: function check(req, res, view, cb) {
              var user = req.user;
              if (!user) {
                  return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorDeveloperAdmin));
              }
              if (developerAdmins.indexOf(user.username) > -1) {
                  return cb();
              }
  
              return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorDeveloperAdmin));
          }
      }]);
  
      return isEnrollAdmin;
  })();
  
  var isApprovedAuthorizer = (function () {
      function isApprovedAuthorizer() {
          _classCallCheck(this, isApprovedAuthorizer);
      }
  
      _createClass(isApprovedAuthorizer, [{
          key: 'check',
          value: function check(req, res, view, cb) {
              var user = req.user;
              if (!user) {
                  return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorDeveloperAdmin));
              }
              var emails = user.emails.map(function (email) {
                  return email.value;
              });
              _async2['default'].series([function (callback) {
                  _utilsServerHelper2['default'].getDeveloperAdmins(function (admins) {
                      if (admins.length > 0) {
                          _async2['default'].eachSeries(emails, function (email, callback) {
                              if (_utilsServerHelper2['default'].checkItemInList(email, admins)) {
                                  return cb();
                              }
                              return callback();
                          }, function (err, result) {
                              return callback();
                          });
                      } else {
                          return callback();
                      }
                  });
              }, function (callback) {
                  _utilsServerHelper2['default'].getEnrollAdminEmails(function (enrollAdmins) {
                      if (enrollAdmins.length > 0) {
                          _async2['default'].eachSeries(emails, function (email, callback) {
                              if (_utilsServerHelper2['default'].checkItemInList(email, enrollAdmins)) {
                                  return cb();
                              }
                              return callback();
                          }, function (err, result) {
                              return callback();
                          });
                      } else {
                          return callback();
                      }
                  });
              }, function (callback) {
                  _async2['default'].eachSeries(emails, function (email, callback) {
                      if (_utilsServerHelper2['default'].checkZangUser(email)) {
                          return cb();
                      }
                      return callback();
                  }, function (err) {
                      return callback();
                  });
              }, function (callback) {
                  _apiEnrollEnrollModel2['default'].findOne({ email: { $in: emails } }, function (err, enroll) {
                      if (err) {
                          return cb(err);
                      }
                      if (!enroll || enroll.status !== "approved") {
                          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorNotOnApprovedList));
                      }
                      return cb();
                  });
              }], function (err, results) {
                  if (err) {
                      return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorNotOnApprovedList));
                  }
                  return cb();
              });
          }
      }]);
  
      return isApprovedAuthorizer;
  })();
  
  var DeveloperAdminAuthorizer = (function () {
      function DeveloperAdminAuthorizer() {
          _classCallCheck(this, DeveloperAdminAuthorizer);
      }
  
      _createClass(DeveloperAdminAuthorizer, [{
          key: 'check',
          value: function check(req, res, view, cb) {
              var user = req.user;
              if (!user) {
                  return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
              }
              var emails = user.emails.map(function (email) {
                  return email.value;
              });
              _utilsServerHelper2['default'].getDeveloperAdmins(function (admins) {
                  if (admins.length > 0) {
                      _async2['default'].eachSeries(emails, function (email, callback) {
                          if (_utilsServerHelper2['default'].checkItemInList(email, admins)) {
                              return cb();
                          }
                          return callback();
                      }, function (err, result) {
                          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorNotOnApprovedList));
                      });
                  } else {
                      return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorNotOnApprovedList));
                  }
              });
          }
      }]);
  
      return DeveloperAdminAuthorizer;
  })();
  
  var EnrollAdminAuthorizer = (function () {
      function EnrollAdminAuthorizer() {
          _classCallCheck(this, EnrollAdminAuthorizer);
      }
  
      _createClass(EnrollAdminAuthorizer, [{
          key: 'check',
          value: function check(req, res, view, cb) {
              var user = req.user;
              if (!user) {
                  return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
              }
              var emails = user.emails.map(function (email) {
                  return email.value;
              });
              _async2['default'].series([function (callback) {
                  _utilsServerHelper2['default'].getDeveloperAdmins(function (admins) {
                      if (admins.length > 0) {
                          _async2['default'].eachSeries(emails, function (email, callback) {
                              if (_utilsServerHelper2['default'].checkItemInList(email, admins)) {
                                  return cb();
                              }
                              return callback();
                          }, function (err, result) {
                              return callback();
                          });
                      } else {
                          return callback();
                      }
                  });
              }, function (callback) {
                  _utilsServerHelper2['default'].getEnrollAdminEmails(function (enrollAdmins) {
                      if (enrollAdmins.length > 0) {
                          _async2['default'].eachSeries(emails, function (email, callback) {
                              if (_utilsServerHelper2['default'].checkItemInList(email, enrollAdmins)) {
                                  return cb();
                              }
                              return callback();
                          }, function (err, result) {
                              return callback();
                          });
                      } else {
                          return callback();
                      }
                  });
              }], function (err, results) {
                  return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorNotOnApprovedList));
              });
          }
      }]);
  
      return EnrollAdminAuthorizer;
  })();
  
  var regOnlyAuthorizer = (function () {
      function regOnlyAuthorizer() {
          _classCallCheck(this, regOnlyAuthorizer);
      }
  
      _createClass(regOnlyAuthorizer, [{
          key: 'check',
          value: function check(req, res, view, cb) {
              var user = req.user;
              if (!user) {
                  return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorPermission));
              } else {
                  return cb();
              }
          }
      }]);
  
      return regOnlyAuthorizer;
  })();
  
  var PermissionAuthorizer = (function () {
      function PermissionAuthorizer(askPermission) {
          _classCallCheck(this, PermissionAuthorizer);
  
          this.name = 'PermissionAuthorizer';
          this.askPermission = askPermission;
      }
  
      _createClass(PermissionAuthorizer, [{
          key: 'check',
          value: function check(req, res, view, cb) {
              var user = req.anonymousUser || req.user;
              var self = this;
              _permissionConfig2['default'].hasPerm(req, this.askPermission, user, null, null, function (err, result) {
                  if (err || !result) {
                      return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorPermission));
                  }
                  req.relPermChecker = self;
                  return cb();
              });
          }
      }, {
          key: 'checkRelation',
          value: function checkRelation(req, object, objectType, cb) {
              var user = req.anonymousUser || req.user;
              _permissionConfig2['default'].hasPerm(req, this.askPermission, user, object, objectType, function (err, result) {
                  if (err || !result) {
                      return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorPermission));
                  }
                  return cb();
              });
          }
      }]);
  
      return PermissionAuthorizer;
  })();
  
  exports['default'] = {
      OAuthAuthorizer: OAuthAuthorizer,
      isInviteCreatorByParams: isInviteCreatorByParams,
      isTopicCreatorByParams: isTopicCreatorByParams,
      isTaskCreatorByParams: isTaskCreatorByParams,
      isIdeaCreatorByParams: isIdeaCreatorByParams,
      DeveloperAdminAuthorizer: DeveloperAdminAuthorizer,
      PermissionAuthorizer: PermissionAuthorizer,
      isApprovedAuthorizer: isApprovedAuthorizer,
      EnrollAdminAuthorizer: EnrollAdminAuthorizer,
      regOnlyAuthorizer: regOnlyAuthorizer,
      pm: _permissionConfig2['default'].pm
  };
  module.exports = exports['default'];

/***/ },
/* 25 */
/***/ function(module, exports) {

  module.exports = require("passport");

/***/ },
/* 26 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var _querystring = __webpack_require__(45);
  
  var _querystring2 = _interopRequireDefault(_querystring);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _messageModel = __webpack_require__(13);
  
  var _messageModel2 = _interopRequireDefault(_messageModel);
  
  var _userUserModel = __webpack_require__(14);
  
  var _userUserModel2 = _interopRequireDefault(_userUserModel);
  
  var _anonymousAnonymousModel = __webpack_require__(30);
  
  var _anonymousAnonymousModel2 = _interopRequireDefault(_anonymousAnonymousModel);
  
  var _modulesFile = __webpack_require__(28);
  
  var _modulesFile2 = _interopRequireDefault(_modulesFile);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _fluxConstantsMessageConstants = __webpack_require__(17);
  
  var _fluxConstantsMessageConstants2 = _interopRequireDefault(_fluxConstantsMessageConstants);
  
  var _fluxConstantsTaskConstants = __webpack_require__(81);
  
  var _fluxConstantsTaskConstants2 = _interopRequireDefault(_fluxConstantsTaskConstants);
  
  var _messageEvent = __webpack_require__(16);
  
  var _messageEvent2 = _interopRequireDefault(_messageEvent);
  
  var _fileviewerFileviewBackend = __webpack_require__(105);
  
  var _fileviewerFileviewBackend2 = _interopRequireDefault(_fileviewerFileviewBackend);
  
  var _jsonwebtoken = __webpack_require__(29);
  
  var _jsonwebtoken2 = _interopRequireDefault(_jsonwebtoken);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _util = __webpack_require__(12);
  
  var _util2 = _interopRequireDefault(_util);
  
  var _taskqueueTaskqueueBackend = __webpack_require__(22);
  
  var _taskqueueTaskqueueBackend2 = _interopRequireDefault(_taskqueueTaskqueueBackend);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _topicTopicModel = __webpack_require__(18);
  
  var _topicTopicModel2 = _interopRequireDefault(_topicTopicModel);
  
  function TransferUrlLink(src, inData) {
    var transferedObj = {
      provider: _fluxConstantsMessageConstants2['default'].DATA_PROVIDER_TYPES.URLLINK,
      providerFileType: inData.providerFileType || '',
      fileType: inData.fileType || '',
      name: inData.name || undefined,
      path: inData.path || '',
      icon: inData.icon || '',
      thumbnail: inData.thumbnail || '',
      keywords: inData.keywords || [],
      description: inData.description || '',
      sitename: inData.sitename || '',
      previewFile: inData.previewFile || '',
      thumbnailFile: inData.thumbnailFile || ''
    };
    if (!transferedObj.path) {
      _modulesLogger2['default'].error(src.id, 'The path in ' + _fluxConstantsMessageConstants2['default'].DATA_PROVIDER_TYPES.URLLINK + ' Can not be null');
      throw new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MessageInvalidPath);
    }
    return transferedObj;
  }
  
  function TransferNativeLink(src, inData) {
    var transferedObj = {
      provider: _fluxConstantsMessageConstants2['default'].DATA_PROVIDER_TYPES.NATIVE,
      providerFileType: inData.providerFileType || '',
      fileType: inData.fileType || '',
      name: inData.name || '',
      fileId: inData.fileId || '',
      icon: inData.icon || '',
      thumbnail: inData.thumbnail || '',
      keywords: inData.keywords || [],
      description: inData.description || '',
      previewFile: inData.previewFile || '',
      fileSize: inData.fileSize || 0,
      thumbnailFile: inData.thumbnailFile || '',
      metaData: inData.metaData,
      pages: inData.pages,
      convertStatus: inData.convertStatus
    };
  
    if (!transferedObj.fileId) {
      _modulesLogger2['default'].error(src.id, 'The fileId not existed');
      throw new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MessageInvalidFileId);
    }
    if (!transferedObj.fileSize) {
      _modulesLogger2['default'].error(src.id, 'The fileSize must be integer larger than zero');
      throw new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MessageInvalidFileSize);
    }
    return transferedObj;
  }
  
  var transferProviderMap = {};
  transferProviderMap[_fluxConstantsMessageConstants2['default'].DATA_PROVIDER_TYPES.NATIVE] = TransferNativeLink;
  transferProviderMap[_fluxConstantsMessageConstants2['default'].DATA_PROVIDER_TYPES.URLLINK] = TransferUrlLink;
  
  function isValidSenderType(senderType) {
    var senderTypeEnum = [_utilsServerConstants2['default'].TypeUser, _utilsServerConstants2['default'].TypeAnonymous];
    if (senderTypeEnum.indexOf(senderType) < 0) {
      return false;
    }
    return true;
  }
  
  function fillContentByCategory(src, data) {
    if (data.parentMsg) {
      if (!data.parentMsg || !data.parentMsg._id) {
        delete data.parentMsg;
      }
    }
    if ((data.category == _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA || data.category == _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.TASK) && !data.parentMsg && data.content) {
      data.content.description = data.content.description || '';
      if (_fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.TASK) {
        data.content.status = data.content.status || _fluxConstantsTaskConstants2['default'].TASK_STATUS_TYPES.PENDING.status;
        data.content.dueDate = data.content.dueDate || Date.now();
        data.content.assignees = data.content.assignees || [];
      } else {
        delete data.content.status;
        delete data.content.dueDate;
        delete data.content.assignees;
      }
    } else {
      delete data.content.description;
      delete data.content.status;
      delete data.content.dueDate;
      delete data.content.assignees;
    }
  }
  
  function addUniqueLikeId(src, data, cb) {
    if (data.category === _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.LIKE && data.parentMsg && data.parentMsg._id) {
      var queryCondition = {
        'category': _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.LIKE,
        'parentMsg._id': data.parentMsg._id,
        'sender._id': data.sender._id,
        'sender.type': data.sender.type
      };
      data.uniqueLikeId = _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.LIKE + data.parentMsg._id.toString() + data.sender._id.toString() + data.sender.type;
    }
    cb(null, data);
  }
  
  function beforeAddMessageHandle(src, data, cb) {
    var reqId = src.id || '';
    if (!_fluxConstantsMessageConstants2['default'].isValidCategory(data)) {
      _modulesLogger2['default'].error(src.id, 'The category is not valid');
      return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MessageInvalidCategory));
    }
    if (!isValidSenderType(data.sender.type)) {
      _modulesLogger2['default'].error(src.id, 'The sender type is invalid');
      return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MessageNotSupportSenderType));
    }
    fillContentByCategory(src, data);
    var transferdObjs = [];
    if (data.content.data && data.content.data.length > 0) {
      var _iteratorNormalCompletion = true;
      var _didIteratorError = false;
      var _iteratorError = undefined;
  
      try {
        for (var _iterator = data.content.data[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
          var dataItem = _step.value;
  
          if (!dataItem.provider) {
            _modulesLogger2['default'].error(src.id, 'The provider in content.data can not be null');
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MessageInvalidProvider));
          }
          if (dataItem.provider in transferProviderMap) {
            var transferFun = transferProviderMap[dataItem.provider];
            try {
              var transferObj = transferFun(src, dataItem);
              transferdObjs.push(transferObj);
            } catch (err) {
              _modulesLogger2['default'].error(src.id, err);
              return cb(err);
            }
          } else {
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MessageInvalidProvider));
          }
        }
      } catch (err) {
        _didIteratorError = true;
        _iteratorError = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion && _iterator['return']) {
            _iterator['return']();
          }
        } finally {
          if (_didIteratorError) {
            throw _iteratorError;
          }
        }
      }
  
      data.content.data = transferdObjs;
    }
    return cb(null, data);
  }
  
  exports.addMessage = function (src, data, cb) {
    if (!_fluxConstantsMessageConstants2['default'].isStorableEventType(data)) {
      return cb(null, data);
    }
    var reqId = src.id || '';
    delete data._id;
    data.created = data.created || Date.now();
    data.modified = null;
    if (data.category === _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA) {
      data.modified = data.created;
    }
  
    _async2['default'].waterfall([function (interCallback) {
      beforeAddMessageHandle(src, data, interCallback);
    }, function (msgObj, interCallback) {
      addUniqueLikeId(src, data, interCallback);
    }, function (msgObj, interCallback) {
      _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].create, reqId, msgObj, function (err, createdMessage) {
        if (err) {
          _modulesLogger2['default'].warn(src.id, err.message);
        }
        return interCallback(err, createdMessage);
      });
    }], function (err, result) {
      if (err) {
        _modulesLogger2['default'].warn(src.id, err.message);
      } else {
        _messageEvent2['default'].emitMessageCreated(src, result);
      }
      return cb(err, result);
    });
  };
  
  function mergeMessage(src, oriMessage, newMessage) {
    var functionName = '[mergeMessage] ';
    oriMessage.modified = Date.now();
    oriMessage.content = newMessage.content;
  }
  
  exports.updateMessage = function (src, data, cb) {
    var functionName = '[message.backend.updateMessage]';
    if (!_fluxConstantsMessageConstants2['default'].isStorableEventType(data)) {
      return cb(null, data);
    }
    var reqId = src.id || '';
    data.created = data.created || Date.now();
  
    _async2['default'].waterfall([function (interCallback) {
      _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].findById, reqId, data._id, function (err, oriMessage) {
        if (data.modified && Math.floor(new Date(data.modified).getTime() / 1000) < Math.floor(oriMessage.modified.getTime() / 1000)) {
          _modulesLogger2['default'].warn(src.id, functionName + 'Outdated message update for updated modified ' + Math.floor(new Date(data.modified).getTime() / 1000) + ' old modified ' + Math.floor(oriMessage.modified.getTime() / 1000));
          return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].UpdateRecordWithModifiedOutdate));
        } else {
          data.modified = Date.now();
          return interCallback(null, oriMessage);
        }
      });
    }, function (oriMessage, interCallback) {
      mergeMessage(src, oriMessage, data);
      beforeAddMessageHandle(src, oriMessage, interCallback);
    }, function (msgObj, interCallback) {
      _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].findOneAndUpdate, reqId, { _id: data._id }, msgObj, { 'new': true }, function (err, updatedMessage) {
        if (err) {
          _modulesLogger2['default'].warn(src.id, err.message);
        }
        return interCallback(err, updatedMessage);
      });
    }], function (err, result) {
      if (err) {
        _modulesLogger2['default'].warn(src.id, err.message);
      } else {
        _messageEvent2['default'].emitMessageUpdated(src, result);
      }
      return cb(err, result);
    });
  };
  
  exports.addMessageWhenNoId = function (src, data, cb) {
    //If the message has _id do different business process,
    //Or else addMessage
    _modulesLogger2['default'].debug(src.id, 'addMessageWhenNoId try to save data');
    if (data._id) {
      beforeAddMessageHandle(src, data, function (err, msgObj) {
        if (err) {
          return cb(err);
        }
        cb(null, msgObj);
      });
    } else {
      exports.addMessage(src, data, function (err, msgObj) {
        if (err) {
          return cb(err);
        }
        cb(null, msgObj);
      });
    }
  };
  
  function toDownloadableDataItem(src, dataItem, cb) {
    var promiseArray = [];
    if (dataItem.provider == _fluxConstantsMessageConstants2['default'].DATA_PROVIDER_TYPES.NATIVE) {
      if (dataItem.fileId) {
        (function () {
          var inData = { key: dataItem.fileId, name: dataItem.name };
          var aPromise = new Promise(function (resolve, reject) {
            _modulesFile2['default'].getDownloadSignedUrl(src, inData, function (err, url) {
              if (err) {
                _modulesLogger2['default'].error(src.id, 'Get download signed url happen error');
                reject(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].DownloadUrlCreateFailed));
              } else {
                dataItem.path = url;
                resolve(url);
              }
            });
          });
          promiseArray.push(aPromise);
        })();
      }
      var thumbnailFile = dataItem.thumbnailFile;
      if (thumbnailFile) {
        (function () {
          var inData = { key: thumbnailFile, name: dataItem.name };
          var aPromise = new Promise(function (resolve, reject) {
            _modulesFile2['default'].getDownloadSignedUrl(src, inData, function (err, url) {
              if (err) {
                _modulesLogger2['default'].error(src.id, 'Get download signed url happen error');
                reject(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].DownloadUrlCreateFailed));
              } else {
                dataItem.previewUrl = url;
                dataItem.thumbnailUrl = url;
                resolve(url);
              }
            });
          });
          promiseArray.push(aPromise);
        })();
      } else if (dataItem.previewFile) {
        (function () {
          var inData = { key: dataItem.previewFile, name: dataItem.name };
          var aPromise = new Promise(function (resolve, reject) {
            _modulesFile2['default'].getDownloadSignedUrl(src, inData, function (err, url) {
              if (err) {
                _modulesLogger2['default'].error(src.id, 'Get download signed url happen error');
                reject(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].DownloadUrlCreateFailed));
              } else {
                dataItem.previewUrl = url;
                resolve(url);
              }
            });
          });
          promiseArray.push(aPromise);
        })();
      }
    } else if (dataItem.provider == _fluxConstantsMessageConstants2['default'].DATA_PROVIDER_TYPES.URLLINK) {
      var thumbnailFile = dataItem.thumbnailFile;
      if (thumbnailFile) {
        if (thumbnailFile.startsWith(_utilsServerConstants2['default'].HTTPSchema) || thumbnailFile.startsWith(_utilsServerConstants2['default'].HTTPSSchema)) {
          dataItem.previewUrl = thumbnailFile;
          dataItem.thumbnailUrl = thumbnailFile;
        } else {
          (function () {
            var inData = { key: thumbnailFile, name: dataItem.name };
            var aPromise = new Promise(function (resolve, reject) {
              _modulesFile2['default'].getDownloadSignedUrl(src, inData, function (err, url) {
                if (err) {
                  _modulesLogger2['default'].error(src.id, 'Get download signed url happen error');
                  reject(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].DownloadUrlCreateFailed));
                } else {
                  dataItem.previewUrl = url;
                  dataItem.thumbnailUrl = url;
                  resolve(url);
                }
              });
            });
            promiseArray.push(aPromise);
          })();
        }
      } else if (dataItem.previewFile) {
        if (dataItem.previewFile.startsWith(_utilsServerConstants2['default'].HTTPSchema) || dataItem.previewFile.startsWith(_utilsServerConstants2['default'].HTTPSSchema)) {
          dataItem.previewUrl = thumbnailFile;
        } else {
          (function () {
            var inData = { key: dataItem.previewFile, name: dataItem.name };
            var aPromise = new Promise(function (resolve, reject) {
              _modulesFile2['default'].getDownloadSignedUrl(src, inData, function (err, url) {
                if (err) {
                  _modulesLogger2['default'].error(src.id, 'Get download signed url happen error');
                  reject(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].DownloadUrlCreateFailed));
                } else {
                  dataItem.previewUrl = url;
                  resolve(url);
                }
              });
            });
            promiseArray.push(aPromise);
          })();
        }
      }
    }
    if (promiseArray.length) {
      Promise.all(promiseArray).then(function () {
        return cb(null, dataItem);
      })['catch'](function () {
        return cb(null, dataItem);
      });
    } else {
      return cb(null, dataItem);
    }
    //  if (shouldReturn){
    //    return cb(null, dataItem);
    //  }
    //  else{
    //    setTimeout(function(){
    //      return cb(null, dataItem);
    //    }, 1000);
    //  }
  }
  
  exports.toDownloadableMessage = function (src, data, cb) {
    //This function will fill download url for each message native attachment
    var reqId = src.id || '';
    if (data.content.data && data.content.data.length > 0) {
      _async2['default'].forEach(data.content.data, function (dataItem, callback) {
        toDownloadableDataItem(src, dataItem, function (err, dataItem) {
          if (dataItem.previewUrl) {
            dataItem.previewUrl = dataItem.previewUrl.replace(':id', data._id);
          }
          callback(err, dataItem);
        });
      }, function (err) {
        return cb(err);
      });
    } else {
      return cb(null, data);
    }
  };
  
  exports.toClientFormatMessage = function (src, data, cb) {
    //This function will remove _id from content.data
    if (data.content.data && data.content.data.length > 0) {
      for (var dataItem in data.content.data) {
        dataItem._id = undefined;
      }
    }
    return cb(null, data.toJSON());
  };
  
  function covertTOIsostring(data) {
    if (data.created && typeof data.created != 'string') {
      data.created = data.created.toISOString();
    }
    if (data.modified && typeof data.modified != 'string') {
      data.modified = data.modified.toISOString();
    }
    if (data.content && data.content.dueDate && typeof data.content.dueDate != 'string') {
      data.content.dueDate = data.content.dueDate.toISOString();
    }
  }
  
  exports.toDownloadableClientFormatMessage = function (src, data, cb) {
    //This function will remove _id from content.data and fill download url
    var reqId = src.id || '';
    if ('toJSON' in data && typeof data.toJSON == 'function') {
      data = data.toJSON();
    }
    //covertTOIsostring(data);
    if (data.content.data && data.content.data.length > 0) {
      _async2['default'].forEach(data.content.data, function (dataItem, callback) {
        toDownloadableDataItem(src, dataItem, function (err, dataItem) {
          if (dataItem) {
            dataItem._id = undefined;
            if (dataItem.previewUrl) {
              dataItem.previewUrl = dataItem.previewUrl.replace(':id', data._id);
            }
          } else {
            _modulesLogger2['default'].warn(src.id, 'toDownloadableDataItem happen error', err);
          }
          return callback(err, dataItem);
        });
      }, function (err) {
        if (err) {
          return cb(err);
        }
        return cb(null, data);
      });
    } else {
      return cb(null, data);
    }
  };
  
  function addChatCount(src, msgObj, addedVal) {
    var functionName = '[addChatCount]';
    _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].update, src.id, { _id: msgObj._id }, { $inc: { 'chatCount': addedVal } }, function (err, result) {
      if (err) {
        _modulesLogger2['default'].error(src.id, _util2['default'].format("%s Add count %d to topic message %s failed", functionName, addedVal, msgObj._id.toString()), err);
      } else {
        _modulesLogger2['default'].info(src.id, _util2['default'].format("%s Add count %d to topic message %s successfully", functionName, addedVal, msgObj._id.toString()), err);
      }
    });
  }
  
  function addLikeCount(src, msgObj, addedVal) {
    var functionName = '[addLikeCount]';
    _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].update, src.id, { _id: msgObj._id }, { $inc: { 'likeCount': addedVal } }, function (err, result) {
      if (err) {
        _modulesLogger2['default'].error(src.id, _util2['default'].format("%s Add like %d to topic message %s failed", functionName, addedVal, msgObj._id.toString()), err);
      } else {
        _modulesLogger2['default'].info(src.id, _util2['default'].format("%s Add like %d to topic message %s successfully", functionName, addedVal, msgObj._id.toString()), err);
      }
    });
  }
  
  function fillParentMsgInformation(src, data, cb) {
    var functionName = '[fillParentMsgInformation]';
    if (data.parentMsg && data.parentMsg._id) {
      var execobj = _messageModel2['default'].findById(data.parentMsg._id, { 'category': 1, 'content.bodyText': 1, 'chatCount': 1, 'likeCount': 1 });
      _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Get title of message=%s', functionName, data.parentMsg._id.toString()));
      _utilsDbwrapper2['default'].execute(execobj, execobj.exec, src.id, function (err, parentMsg) {
        if (err) {
          _modulesLogger2['default'].error(src.id, _util2['default'].format('%s Get title of message failed', functionName), err);
          return cb(null, data);
        } else {
          _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Get title of message successfully', functionName));
          data.parentMsg.bodyText = parentMsg.content.bodyText;
          data.parentMsg.category = parentMsg.category;
  
          if (parentMsg.category == _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA) {
            setTimeout(function () {
              addChatCount(src, parentMsg, 1);
            }, 1000);
          }
          if (data.category === _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.LIKE) {
            setTimeout(function () {
              addLikeCount(src, parentMsg, 1);
            }, 1000);
          }
          return cb(null, data);
        }
      });
    } else {
      return cb(null, data);
    }
  }
  
  exports.addMessagetoNoSenderPublicInfo = function (src, data, cb) {
    _async2['default'].waterfall([function (InternalCallback) {
      fillParentMsgInformation(src, data, InternalCallback);
    }, function (createdMessage, InternalCallback) {
      exports.addMessage(src, createdMessage, InternalCallback);
    }, function (createdMessage, InternalCallback) {
      exports.toDownloadableClientFormatMessages(src, [createdMessage], InternalCallback);
    }, function (results, InternalCallback) {
      var result = results[0];
      //Throw event to update parentMessage if it is idea
      if (result.parentMsg && result.parentMsg.category === _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA) {
        _messageEvent2['default'].emitUpdateModifyTime(src.id, result.parentMsg._id);
      }
      return cb(null, result);
    }], function (err) {
      if (err) {
        return cb(err);
      }
    });
  };
  
  exports.updateMessagetoNoSenderPublicInfo = function (src, data, cb) {
    _async2['default'].waterfall([function (InternalCallback) {
      exports.updateMessage(src, data, InternalCallback);
    }, function (createdMessage, InternalCallback) {
      exports.toDownloadableClientFormatMessages(src, [createdMessage], InternalCallback);
    }, function (results, InternalCallback) {
      var result = results[0];
      //Throw event to update parentMessage if it is idea
      if (result.parentMsg && result.parentMsg.category === _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA) {
        _messageEvent2['default'].emitUpdateModifyTime(src.id, result.parentMsg._id);
      }
      return cb(null, result);
    }], function (err) {
      if (err) {
        return cb(err);
      }
    });
  };
  
  exports.addMessageWhenNoIdtoNoSenderPublicInfo = function (src, data, cb) {
    _async2['default'].waterfall([function (InternalCallback) {
      fillParentMsgInformation(src, data, InternalCallback);
    }, function (createdMessage, InternalCallback) {
      exports.addMessageWhenNoId(src, createdMessage, InternalCallback);
    }, function (createdMessage, InternalCallback) {
      exports.toDownloadableClientFormatMessages(src, [createdMessage], InternalCallback);
    }, function (results, InternalCallback) {
      var result = results[0];
      //Throw event to update parentMessage if it is idea and data._id not existed
      if (!data._id && result.parentMsg && result.parentMsg.category === _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA) {
        _messageEvent2['default'].emitUpdateModifyTime(src.id, result.parentMsg._id);
      }
      return cb(null, result);
    }], function (err) {
      if (err) {
        return cb(err);
      }
    });
  };
  
  function getSenderPublicInfo(src, data, callback) {
    if (data.sender.type == _utilsServerConstants2['default'].TypeUser) {
      (function () {
        var userId = data.sender._id;
        _utilsDbwrapper2['default'].execute(_userUserModel2['default'], _userUserModel2['default'].findById, src.id, userId, function (err, user) {
          if (err || !user) {
            _modulesLogger2['default'].error(src.id, 'getSenderPublicInfo in addMessagetoDownloadableClientFormatMessage failed with userid=' + userId);
            return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          }
          data.sender.username = user.username;
          data.sender.picture_url = user.picture_url;
          data.sender.displayname = user.displayname;
          return callback(null);
        });
      })();
    } else if (data.sender.type == _utilsServerConstants2['default'].TypeAnonymous) {
      (function () {
        var anonymousId = data.sender._id;
        _utilsDbwrapper2['default'].execute(_anonymousAnonymousModel2['default'], _anonymousAnonymousModel2['default'].findById, src.id, anonymousId, function (err, anonymous) {
          if (err || !anonymous) {
            _modulesLogger2['default'].error(src.id, 'getSenderPublicInfo in addMessagetoDownloadableClientFormatMessage failed with anonymousid=' + anonymousId);
            return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          }
          //anonymous = anonymous.toJSON();
          data.sender.username = anonymous.username;
          data.sender.picture_url = anonymous.picture_url;
          data.sender.displayname = anonymous.displayname;
          return callback(null);
        });
      })();
    } else {
      return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MessageNotSupportSenderType));
    }
  }
  
  function getParentMsgInfo(src, data, callback) {
    if (data.parentMsg) {
      if (data.parentMsg._id == data._id) {
        _modulesLogger2['default'].error('The parent message is the message self. It is impossilbe');
        callback(null, null);
      } else {
        _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].findById, src.id, data.parentMsg, function (err, parentMsg) {
          if (err) {
            _modulesLogger2['default'].warn(src.id, 'getParentMsgInfo happen error', err);
            return callback(err);
          }
          if (!parentMsg) {
            _modulesLogger2['default'].warn(src.id, 'There is no message with with _id =' + data.parentMsg._id.toString());
            return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ParentMessageNotExsistedError));
          }
          exports.toDownloadableClientFormatMessages(src, [parentMsg], callback);
        });
      }
    } else {
      callback(null, null);
    }
  }
  
  exports.addMessagetoDownloadableClientFormatMessage = function (src, data, cb) {
    _async2['default'].parallel([function (InternalCallback) {
      getSenderPublicInfo(src, data, InternalCallback);
    }, function (InternalCallback) {
      exports.addMessagetoNoSenderPublicInfo(src, data, InternalCallback);
    }, function (InternalCallback) {
      getParentMsgInfo(src, data, InternalCallback);
    }], function (err, results) {
      if (!err) {
        var sender = results[0];
        var message = results[1];
        var parentMsg = null;
        if (results[2]) {
          parentMsg = results[2][0];
        }
        message.sender = _lodash2['default'].extend(message.sender, sender);
        if (parentMsg) {
          message.parentMsg = parentMsg;
        }
        //Throw event to update parentMessage if it is idea
        if (message.parentMsg && message.parentMsg.category === _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA) {
          _messageEvent2['default'].emitUpdateModifyTime(src.id, message.parentMsg._id);
        }
        return cb(null, message);
      }
      _modulesLogger2['default'].error(src.id, 'Call addMessagetoDownloadableClientFormatMessage failed ' + err.message);
      return cb(err);
    });
  };
  
  exports.addMessageWhenNoIdtoDownloadableClientFormatMessage = function (src, data, cb) {
    _async2['default'].parallel([function (InternalCallback) {
      if (!data.sender.username || !data.sender.displayname || !data.sender.picture_url) {
        getSenderPublicInfo(src, data, InternalCallback);
      } else {
        return InternalCallback(null);
      }
    }, function (InternalCallback) {
      exports.addMessageWhenNoIdtoNoSenderPublicInfo(src, data, InternalCallback);
    }, function (InternalCallback) {
      getParentMsgInfo(src, data, InternalCallback);
    }], function (err, results) {
      if (!err) {
        var sender = results[0];
        var message = results[1];
        var parentMsg = null;
        if (results[2]) {
          parentMsg = results[2][0];
        }
        message.sender = _lodash2['default'].extend(message.sender, sender);
        if (parentMsg) {
          message.parentMsg = parentMsg;
        }
        //Throw event to update parentMessage if it is idea and data._id is not existed
        if (!data._id_ && message.parentMsg && message.parentMsg.category === _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA) {
          _messageEvent2['default'].emitUpdateModifyTime(src.id, message.parentMsg._id);
        }
        return cb(null, message);
      }
      _modulesLogger2['default'].error(src.id, 'Call addMessageWhenNoIdtoDownloadableClientFormatMessage failed ' + err.message, err);
      return cb(err);
    });
  };
  
  exports.queryByRef = function (src, data, cb) {
    var matchCondition = { topicId: data.topicId };
    var sort = { created: -1 };
    if (data.page <= 1) {
      delete data.nextRefObjId;
      delete data.prevRefObjId;
      data.page = 1;
    }
    var includeEqual = data.includeEqual || false;
    delete data.includeEqual;
  
    if (data.direction == _utilsServerConstants2['default'].DirectionAfter) {
      if (data.refTime) {
        matchCondition.created = { $gte: new Date(data.refTime) };
      } else {
        sort = { _id: -1 };
      }
    } else {
      if (data.refTime) {
        matchCondition.created = { $lte: new Date(data.refTime) };
      } else {
        sort = { _id: -1 };
      }
    }
  
    if (data.nextRefObjId) {
      if (includeEqual) {
        matchCondition._id = { $lte: _mongoose2['default'].Types.ObjectId(data.nextRefObjId) };
      } else {
        matchCondition._id = { $lt: _mongoose2['default'].Types.ObjectId(data.nextRefObjId) };
      }
      sort = { _id: -1 };
    } else if (data.prevRefObjId) {
      if (includeEqual) {
        matchCondition._id = { $gte: _mongoose2['default'].Types.ObjectId(data.prevRefObjId) };
      } else {
        matchCondition._id = { $gt: _mongoose2['default'].Types.ObjectId(data.prevRefObjId) };
      }
      sort = { _id: 1 };
    }
  
    var exeobj = _messageModel2['default'].find(matchCondition).sort(sort).limit(data.size + 1).lean();
    _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, results) {
      if (err) {
        _modulesLogger2['default'].error(src.id, 'queryByRef happen error', err.message);
        return cb(null, { results: [] });
      }
  
      if (results.length > data.size) {
        if (data.prevRefObjId) {
          results = results.reverse();
          return cb(null, { results: results.slice(1, data.size + 1), havingNextPage: true });
        }
        return cb(null, { results: results.slice(0, data.size), havingNextPage: true });
      } else {
        if (data.prevRefObjId) {
          results = results.reverse();
        }
        return cb(null, { results: results, havingNextPage: false });
      }
    });
  };
  
  exports.listTaskByTopic = function (src, data, cb) {
    var matchCondition = {
      topicId: data.topicId,
      category: data.category
    };
    matchCondition = _lodash2['default'].extend(matchCondition, data.filter);
    var sort = data.order;
    if (data.page <= 1) {
      data.page = 1;
    }
    var skip = data.size * (data.page - 1);
    var exeobj = _messageModel2['default'].find(matchCondition).sort(sort).skip(skip).limit(data.size + 1).lean();
    _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, results) {
      if (err) {
        _modulesLogger2['default'].error(src.id, 'listCategoryByTopic happen error', err.message);
        return cb(null, { results: [] });
      }
      if (results.length > data.size) {
        return cb(null, { results: results.slice(0, data.size), havingNextPage: true });
      } else {
        return cb(null, { results: results, havingNextPage: false });
      }
    });
  };
  
  exports.listIdeaByTopic = function (src, data, cb) {
    var matchCondition = {
      topicId: data.topicId,
      category: data.category
    };
    matchCondition = _lodash2['default'].extend(matchCondition, data.filter);
    var sort = data.order;
    if (data.page <= 1) {
      data.page = 1;
    }
    var skip = data.size * (data.page - 1);
    var exeobj = _messageModel2['default'].find(matchCondition).sort(sort).skip(skip).limit(data.size + 1).lean();
    _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, results) {
      if (err) {
        _modulesLogger2['default'].error(src.id, 'listCategoryByTopic happen error', err.message);
        return cb(null, { results: [] });
      }
      if (results.length > data.size) {
        return cb(null, { results: results.slice(0, data.size), havingNextPage: true });
      } else {
        return cb(null, { results: results, havingNextPage: false });
      }
    });
  };
  
  exports.toDownloadableClientFormatMessages = function (src, data, cb) {
    //here data is the list of message
    var functionName = '[toDownloadableClientFormatMessages] ';
    var userSet = new Set();
    var anonymousUserSet = new Set();
    var parentMsgSet = new Set();
    var convertedDatas = data;
    function step1(interCallback) {
      var dataCnt = 0;
      _async2['default'].each(data, function (msg, interCallback) {
        var msgCnt = dataCnt;
        dataCnt += 1;
        if (msg.sender.type == _utilsServerConstants2['default'].TypeUser && msg.sender._id && (!msg.sender.username || !msg.sender.displayname || !msg.sender.picture_url)) {
          userSet.add(msg.sender._id.toString());
        } else if (msg.sender.type == _utilsServerConstants2['default'].TypeAnonymous && msg.sender._id && (!msg.sender.displayname || !msg.sender.picture_url)) {
          anonymousUserSet.add(msg.sender._id.toString());
        }
        if (msg.parentMsg && msg.parentMsg._id && !msg.parentMsg.category) {
          parentMsgSet.add(msg.parentMsg._id.toString());
        }
  
        exports.toDownloadableClientFormatMessage(src, msg, function (err, convertedData) {
          if (err) {
            return interCallback(err);
          }
          //convertedDatas.push(convertedData);
          convertedDatas[msgCnt] = convertedData;
          return interCallback();
        });
      }, function (err) {
        if (err) {
          _modulesLogger2['default'].error(src.id, 'toDownloadableClientFormatMessages happen error', err);
          return interCallback(err);
        }
        return interCallback();
      });
    }
  
    function step2(interCallback) {
      _async2['default'].parallel([function (interCallback) {
        var userObjIds = [];
        if (userSet.size === 0) {
          return interCallback(null, []);
        }
        var _iteratorNormalCompletion2 = true;
        var _didIteratorError2 = false;
        var _iteratorError2 = undefined;
  
        try {
          for (var _iterator2 = userSet[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
            var userItm = _step2.value;
  
            userObjIds.push(_mongoose2['default'].Types.ObjectId(userItm));
          }
        } catch (err) {
          _didIteratorError2 = true;
          _iteratorError2 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion2 && _iterator2['return']) {
              _iterator2['return']();
            }
          } finally {
            if (_didIteratorError2) {
              throw _iteratorError2;
            }
          }
        }
  
        var exeobj = _userUserModel2['default'].find({ _id: { $in: userObjIds } }, { displayname: 1, picturefile: 1, username: 1 });
        _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, interCallback);
      }, function (interCallback) {
        var anonyObjIds = [];
        if (anonymousUserSet.size === 0) {
          return interCallback(null, []);
        }
        var _iteratorNormalCompletion3 = true;
        var _didIteratorError3 = false;
        var _iteratorError3 = undefined;
  
        try {
          for (var _iterator3 = anonymousUserSet[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
            var anonItm = _step3.value;
  
            anonyObjIds.push(_mongoose2['default'].Types.ObjectId(anonItm));
          }
        } catch (err) {
          _didIteratorError3 = true;
          _iteratorError3 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion3 && _iterator3['return']) {
              _iterator3['return']();
            }
          } finally {
            if (_didIteratorError3) {
              throw _iteratorError3;
            }
          }
        }
  
        var exeobj = _anonymousAnonymousModel2['default'].find({ _id: { $in: anonyObjIds } }, { displayname: 1, picturefile: 1, username: 1 });
        _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, interCallback);
      }, function (interCallback) {
        var parentMsgIds = [];
        if (parentMsgSet.size === 0) {
          return interCallback(null, []);
        }
        var _iteratorNormalCompletion4 = true;
        var _didIteratorError4 = false;
        var _iteratorError4 = undefined;
  
        try {
          for (var _iterator4 = parentMsgSet[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
            var parentMsgIdsItm = _step4.value;
  
            parentMsgIds.push(parentMsgIdsItm);
          }
        } catch (err) {
          _didIteratorError4 = true;
          _iteratorError4 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion4 && _iterator4['return']) {
              _iterator4['return']();
            }
          } finally {
            if (_didIteratorError4) {
              throw _iteratorError4;
            }
          }
        }
  
        var exeobj = _messageModel2['default'].find({ _id: { $in: parentMsgIds } }).lean();
        _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, results) {
          if (err) {
            _modulesLogger2['default'].error(src.id, "happen errors for get parent message", err);
            return interCallback(null, []);
          }
          exports.toDownloadableClientFormatMessages(src, results, interCallback);
        });
      }], function (err, result) {
        if (err) {
          _modulesLogger2['default'].error(src.id, "toDownloadableClientFormatMessages.step2 happen error", err);
          return interCallback(null, convertedDatas);
        }
        if (result) {
          var usersDict = {};
          var anonymousUsersDict = {};
          var parentMsgsDict = {};
          if (result.length > 0) {
            var users = result[0];
            if (users.length > 0) {
              var _iteratorNormalCompletion5 = true;
              var _didIteratorError5 = false;
              var _iteratorError5 = undefined;
  
              try {
                var _loop = function () {
                  var userItem = _step5.value;
  
                  if (userItem._id) {
                    usersDict[userItem._id] = { displayname: userItem.displayname,
                      picture_url: userItem.picture_url,
                      username: userItem.username };
                  }
                  setTimeout(function () {
                    syncMessageSenderTrigger(src, userItem, _utilsServerConstants2['default'].TypeUser);
                  }, 1000);
                };
  
                for (var _iterator5 = users[Symbol.iterator](), _step5; !(_iteratorNormalCompletion5 = (_step5 = _iterator5.next()).done); _iteratorNormalCompletion5 = true) {
                  _loop();
                }
              } catch (err) {
                _didIteratorError5 = true;
                _iteratorError5 = err;
              } finally {
                try {
                  if (!_iteratorNormalCompletion5 && _iterator5['return']) {
                    _iterator5['return']();
                  }
                } finally {
                  if (_didIteratorError5) {
                    throw _iteratorError5;
                  }
                }
              }
            }
          }
          if (result.length > 1) {
            var anonymousUsers = result[1];
            var _iteratorNormalCompletion6 = true;
            var _didIteratorError6 = false;
            var _iteratorError6 = undefined;
  
            try {
              var _loop2 = function () {
                var anonymousItem = _step6.value;
  
                anonymousUsersDict[anonymousItem._id] = { displayname: anonymousItem.displayname,
                  picture_url: anonymousItem.picture_url,
                  username: anonymousItem.username };
                setTimeout(function () {
                  syncMessageSenderTrigger(src, anonymousItem, _utilsServerConstants2['default'].TypeAnonymous);
                }, 1000);
              };
  
              for (var _iterator6 = anonymousUsers[Symbol.iterator](), _step6; !(_iteratorNormalCompletion6 = (_step6 = _iterator6.next()).done); _iteratorNormalCompletion6 = true) {
                _loop2();
              }
            } catch (err) {
              _didIteratorError6 = true;
              _iteratorError6 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion6 && _iterator6['return']) {
                  _iterator6['return']();
                }
              } finally {
                if (_didIteratorError6) {
                  throw _iteratorError6;
                }
              }
            }
          }
          if (result.length > 2) {
            var parentMsgs = result[2];
            var _iteratorNormalCompletion7 = true;
            var _didIteratorError7 = false;
            var _iteratorError7 = undefined;
  
            try {
              var _loop3 = function () {
                var parentMsgItem = _step7.value;
  
                parentMsgsDict[parentMsgItem._id] = parentMsgItem;
                setTimeout(function () {
                  syncParentMessageTitleTrigger(src, parentMsgItem);
                }, 1000);
              };
  
              for (var _iterator7 = parentMsgs[Symbol.iterator](), _step7; !(_iteratorNormalCompletion7 = (_step7 = _iterator7.next()).done); _iteratorNormalCompletion7 = true) {
                _loop3();
              }
            } catch (err) {
              _didIteratorError7 = true;
              _iteratorError7 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion7 && _iterator7['return']) {
                  _iterator7['return']();
                }
              } finally {
                if (_didIteratorError7) {
                  throw _iteratorError7;
                }
              }
            }
          }
  
          var _iteratorNormalCompletion8 = true;
          var _didIteratorError8 = false;
          var _iteratorError8 = undefined;
  
          try {
            for (var _iterator8 = convertedDatas[Symbol.iterator](), _step8; !(_iteratorNormalCompletion8 = (_step8 = _iterator8.next()).done); _iteratorNormalCompletion8 = true) {
              var msg = _step8.value;
  
              if (msg.sender.type == _utilsServerConstants2['default'].TypeUser && msg.sender._id in usersDict) {
                msg.sender = _lodash2['default'].extend(msg.sender, usersDict[msg.sender._id]);
              } else if (msg.sender.type == _utilsServerConstants2['default'].TypeAnonymous && msg.sender._id in anonymousUsersDict) {
                msg.sender = _lodash2['default'].extend(msg.sender, anonymousUsersDict[msg.sender._id]);
              }
              if (msg.parentMsg && msg.parentMsg._id && msg.parentMsg._id in parentMsgsDict) {
                msg.parentMsg = parentMsgsDict[msg.parentMsg._id];
              }
            }
          } catch (err) {
            _didIteratorError8 = true;
            _iteratorError8 = err;
          } finally {
            try {
              if (!_iteratorNormalCompletion8 && _iterator8['return']) {
                _iterator8['return']();
              }
            } finally {
              if (_didIteratorError8) {
                throw _iteratorError8;
              }
            }
          }
        }
        return interCallback(null, convertedDatas);
      });
    }
    if (data.length === 0) {
      return cb(null, data);
    }
    _async2['default'].series([function (interCallback) {
      step1(interCallback);
    }, function (interCallback) {
      step2(interCallback);
    }], function (err, results) {
      return cb(err, results[1]);
    });
  };
  
  exports.toDownloadableClientFormatMessagesIngoreParentMsg = function (src, data, cb) {
    //here data is the list of message 
    var userSet = new Set();
    var anonymousUserSet = new Set();
    var convertedDatas = [];
    function step1(interCallback) {
      _async2['default'].each(data, function (msg, interCallback) {
        if (msg.sender.type == _utilsServerConstants2['default'].TypeUser && msg.sender._id) {
          userSet.add(msg.sender._id.toString());
        } else if (msg.sender.type == _utilsServerConstants2['default'].TypeAnonymous && msg.sender._id) {
          anonymousUserSet.add(msg.sender._id.toString());
        }
        exports.toDownloadableClientFormatMessage(src, msg, function (err, convertedData) {
          if (err) {
            return interCallback(err);
          }
          convertedDatas.push(convertedData);
          return interCallback();
        });
      }, function (err) {
        if (err) {
          _modulesLogger2['default'].error(src.id, 'toDownloadableClientFormatMessagesIngoreParentMsg happen error', err);
          return interCallback(err);
        }
        return interCallback();
      });
    }
  
    function step2(interCallback) {
      _async2['default'].parallel([function (interCallback) {
        var userObjIds = [];
        if (userSet.size === 0) {
          return interCallback(null, []);
        }
        var _iteratorNormalCompletion9 = true;
        var _didIteratorError9 = false;
        var _iteratorError9 = undefined;
  
        try {
          for (var _iterator9 = userSet[Symbol.iterator](), _step9; !(_iteratorNormalCompletion9 = (_step9 = _iterator9.next()).done); _iteratorNormalCompletion9 = true) {
            var userItm = _step9.value;
  
            userObjIds.push(_mongoose2['default'].Types.ObjectId(userItm));
          }
        } catch (err) {
          _didIteratorError9 = true;
          _iteratorError9 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion9 && _iterator9['return']) {
              _iterator9['return']();
            }
          } finally {
            if (_didIteratorError9) {
              throw _iteratorError9;
            }
          }
        }
  
        _utilsDbwrapper2['default'].execute(_userUserModel2['default'], _userUserModel2['default'].find, src.id, { _id: { $in: userObjIds } }, interCallback);
      }, function (interCallback) {
        var anonyObjIds = [];
        if (anonymousUserSet.size === 0) {
          return interCallback(null, []);
        }
        var _iteratorNormalCompletion10 = true;
        var _didIteratorError10 = false;
        var _iteratorError10 = undefined;
  
        try {
          for (var _iterator10 = anonymousUserSet[Symbol.iterator](), _step10; !(_iteratorNormalCompletion10 = (_step10 = _iterator10.next()).done); _iteratorNormalCompletion10 = true) {
            var anonItm = _step10.value;
  
            anonyObjIds.push(_mongoose2['default'].Types.ObjectId(anonItm));
          }
        } catch (err) {
          _didIteratorError10 = true;
          _iteratorError10 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion10 && _iterator10['return']) {
              _iterator10['return']();
            }
          } finally {
            if (_didIteratorError10) {
              throw _iteratorError10;
            }
          }
        }
  
        _utilsDbwrapper2['default'].execute(_anonymousAnonymousModel2['default'], _anonymousAnonymousModel2['default'].find, src.id, { _id: { $in: anonyObjIds } }, interCallback);
      }], function (err, result) {
        if (result) {
          var usersDict = {};
          var anonymousUsersDict = {};
          if (result.length > 0) {
            var users = result[0];
            var _iteratorNormalCompletion11 = true;
            var _didIteratorError11 = false;
            var _iteratorError11 = undefined;
  
            try {
              for (var _iterator11 = users[Symbol.iterator](), _step11; !(_iteratorNormalCompletion11 = (_step11 = _iterator11.next()).done); _iteratorNormalCompletion11 = true) {
                var userItem = _step11.value;
  
                usersDict[userItem._id] = userItem.toJSON().profile;
              }
            } catch (err) {
              _didIteratorError11 = true;
              _iteratorError11 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion11 && _iterator11['return']) {
                  _iterator11['return']();
                }
              } finally {
                if (_didIteratorError11) {
                  throw _iteratorError11;
                }
              }
            }
          }
          if (result.length > 1) {
            var anonymousUsers = result[1];
            var _iteratorNormalCompletion12 = true;
            var _didIteratorError12 = false;
            var _iteratorError12 = undefined;
  
            try {
              for (var _iterator12 = anonymousUsers[Symbol.iterator](), _step12; !(_iteratorNormalCompletion12 = (_step12 = _iterator12.next()).done); _iteratorNormalCompletion12 = true) {
                var anonymousItem = _step12.value;
  
                var anonymous = anonymousItem.toJSON();
                anonymousUsersDict[anonymousItem._id] = { displayname: anonymous.displayname,
                  picture_url: anonymous.picture_url,
                  username: anonymous.username };
              }
            } catch (err) {
              _didIteratorError12 = true;
              _iteratorError12 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion12 && _iterator12['return']) {
                  _iterator12['return']();
                }
              } finally {
                if (_didIteratorError12) {
                  throw _iteratorError12;
                }
              }
            }
          }
          var _iteratorNormalCompletion13 = true;
          var _didIteratorError13 = false;
          var _iteratorError13 = undefined;
  
          try {
            for (var _iterator13 = convertedDatas[Symbol.iterator](), _step13; !(_iteratorNormalCompletion13 = (_step13 = _iterator13.next()).done); _iteratorNormalCompletion13 = true) {
              var msg = _step13.value;
  
              if (msg.sender.type == _utilsServerConstants2['default'].TypeUser && msg.sender._id in usersDict) {
                msg.sender = _lodash2['default'].extend(msg.sender, usersDict[msg.sender._id]);
              } else if (msg.sender.type == _utilsServerConstants2['default'].TypeAnonymous && msg.sender._id in anonymousUsersDict) {
                msg.sender = _lodash2['default'].extend(msg.sender, anonymousUsersDict[msg.sender._id]);
              }
            }
          } catch (err) {
            _didIteratorError13 = true;
            _iteratorError13 = err;
          } finally {
            try {
              if (!_iteratorNormalCompletion13 && _iterator13['return']) {
                _iterator13['return']();
              }
            } finally {
              if (_didIteratorError13) {
                throw _iteratorError13;
              }
            }
          }
        }
        return interCallback(null, convertedDatas);
      });
    }
    if (data.length === 0) {
      return cb(null, data);
    }
    _async2['default'].series([function (interCallback) {
      step1(interCallback);
    }, function (interCallback) {
      step2(interCallback);
    }], function (err, results) {
      return cb(err, results[1]);
    });
  };
  
  exports.fillTopicTitleInMsgs = function (src, listOfMsgs, cb) {
    var functionName = '[getFillTopicTitleForMsgs] ';
    if (listOfMsgs.length == 0) {
      return cb(null, []);
    }
    var inList = (function () {
      var _inList = [];
      var _iteratorNormalCompletion14 = true;
      var _didIteratorError14 = false;
      var _iteratorError14 = undefined;
  
      try {
        for (var _iterator14 = listOfMsgs[Symbol.iterator](), _step14; !(_iteratorNormalCompletion14 = (_step14 = _iterator14.next()).done); _iteratorNormalCompletion14 = true) {
          var item = _step14.value;
  
          _inList.push(item.topicId);
        }
      } catch (err) {
        _didIteratorError14 = true;
        _iteratorError14 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion14 && _iterator14['return']) {
            _iterator14['return']();
          }
        } finally {
          if (_didIteratorError14) {
            throw _iteratorError14;
          }
        }
      }
  
      return _inList;
    })();
    var exeobj = _topicTopicModel2['default'].find({ '_id': { '$in': inList } }, { title: 1 });
    _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, results) {
      if (err) {
        _modulesLogger2['default'].error(src.id, functionName + ' Query topic title by id list happen error.', err);
        return cb(null);
      }
      var topicIdObjDict = new Map();
      var _iteratorNormalCompletion15 = true;
      var _didIteratorError15 = false;
      var _iteratorError15 = undefined;
  
      try {
        for (var _iterator15 = listOfMsgs[Symbol.iterator](), _step15; !(_iteratorNormalCompletion15 = (_step15 = _iterator15.next()).done); _iteratorNormalCompletion15 = true) {
          var msgItem = _step15.value;
  
          var topicidKey = msgItem.topicId.toString();
          if (topicIdObjDict.has(topicidKey)) {
            msgItem.topicTitle = topicIdObjDict.get(topicidKey).title;
          } else {
            var _iteratorNormalCompletion16 = true;
            var _didIteratorError16 = false;
            var _iteratorError16 = undefined;
  
            try {
              for (var _iterator16 = results[Symbol.iterator](), _step16; !(_iteratorNormalCompletion16 = (_step16 = _iterator16.next()).done); _iteratorNormalCompletion16 = true) {
                var topicItem = _step16.value;
  
                if (topicItem._id.toString() == topicidKey) {
                  msgItem.topicTitle = topicItem.title;
                  topicIdObjDict.set(topicItem._id.toString(), topicItem);
                  break;
                }
              }
            } catch (err) {
              _didIteratorError16 = true;
              _iteratorError16 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion16 && _iterator16['return']) {
                  _iterator16['return']();
                }
              } finally {
                if (_didIteratorError16) {
                  throw _iteratorError16;
                }
              }
            }
          }
        }
      } catch (err) {
        _didIteratorError15 = true;
        _iteratorError15 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion15 && _iterator15['return']) {
            _iterator15['return']();
          }
        } finally {
          if (_didIteratorError15) {
            throw _iteratorError15;
          }
        }
      }
  
      return cb(null, listOfMsgs);
    });
  };
  
  exports.getLatestMessageByParent = function (src, parentInfos, cb) {
    //Each parentInfo has following property
    //{_id:'',  size:1}
    //The returned of this function will have no parent message!!!
    var parallelLastMsgsFun = function parallelLastMsgsFun(parentInfo) {
      var innerFun = function innerFun(callback) {
        var exeobj = _messageModel2['default'].find({ "parentMsg._id": parentInfo._id, "category": _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.CHAT }).sort({ "_id": -1 }).limit(parentInfo.size);
        _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, msgs) {
          if (err) {
            _modulesLogger2['default'].warn(src.id, "getLatestMessageByParent when query last messages happen error.", err);
            return callback(null, []);
          }
          return callback(null, msgs);
        });
      };
      return innerFun;
    };
  
    var parallelChatMsgCountFun = function parallelChatMsgCountFun(parentInfo) {
      var innerFun = function innerFun(callback) {
        _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].count, src.id, { "parentMsg._id": parentInfo._id, "category": _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.CHAT }, function (err, count) {
          if (err) {
            _modulesLogger2['default'].warn(src.id, "getLatestMessageByParent when query count happen error.", err);
            return callback(null, 0);
          }
          parentInfo.chatCount = count;
          setTimeout(function () {
            syncChatCountTrigger(src, parentInfo);
          }, 1000);
          return callback(null, count);
        });
      };
      var innerFun2 = function innerFun2(callback) {
        return callback(null, parentInfo.chatCount);
      };
  
      if (parentInfo.chatCount === undefined) {
        return innerFun;
      } else {
        return innerFun2;
      }
    };
  
    var parallelLikeMsgCountFun = function parallelLikeMsgCountFun(parentInfo) {
      var innerFun = function innerFun(callback) {
        _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].count, src.id, { "parentMsg._id": parentInfo._id, "category": _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.LIKE }, function (err, count) {
          if (err) {
            _modulesLogger2['default'].warn(src.id, "getLatestMessageByParent when query count happen error.", err);
            return callback(null, 0);
          }
          parentInfo.likeCount = count;
          setTimeout(function () {
            syncLikeCountTrigger(src, parentInfo);
          }, 1000);
          return callback(null, count);
        });
      };
      var innerFun2 = function innerFun2(callback) {
        return callback(null, parentInfo.likeCount);
      };
      if (parentInfo.likeCount === undefined) {
        return innerFun;
      } else {
        return innerFun2;
      }
    };
  
    var parallelFuns = [];
    var _iteratorNormalCompletion17 = true;
    var _didIteratorError17 = false;
    var _iteratorError17 = undefined;
  
    try {
      for (var _iterator17 = parentInfos[Symbol.iterator](), _step17; !(_iteratorNormalCompletion17 = (_step17 = _iterator17.next()).done); _iteratorNormalCompletion17 = true) {
        var parentInfoItem = _step17.value;
  
        if (!parentInfoItem.size) {
          parentInfoItem.size = 1;
        }
        //parallelFuns.push(parallelLastMsgsFun(parentInfoItem));
        parallelFuns.push(parallelChatMsgCountFun(parentInfoItem));
        parallelFuns.push(parallelLikeMsgCountFun(parentInfoItem));
      }
    } catch (err) {
      _didIteratorError17 = true;
      _iteratorError17 = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion17 && _iterator17['return']) {
          _iterator17['return']();
        }
      } finally {
        if (_didIteratorError17) {
          throw _iteratorError17;
        }
      }
    }
  
    _async2['default'].waterfall([function (interCallBack) {
      _async2['default'].parallel(parallelFuns, function (err, result) {
        if (err) {
          _modulesLogger2['default'].warn(src.id, "getLatestMessageByParent query messages happen error.", err);
          return interCallBack(null, parentInfos);
        }
        for (var index in parentInfos) {
          var parentInfoItem = parentInfos[index];
          //parentInfoItem.data = result[index * 3];
          parentInfoItem.chatCount = result[index * 2];
          parentInfoItem.likeCount = result[index * 2 + 1];
        }
        return interCallBack(null, parentInfos);
      });
    }],
    //    (parentInfos, interCallBack) => {
    //      let msgList = [];
    //      for (let parentInfo of parentInfos){
    //        let dataItem = parentInfo.data;
    //        if (dataItem && dataItem.length > 0){
    //          msgList = msgList.concat(dataItem);
    //        }
    //      }
    //      exports.toDownloadableClientFormatMessagesIngoreParentMsg(src, msgList, (err, results) => {
    //        let resultsIterIdx = 0;
    //        for (let parentInfoItem of parentInfos){
    //          let parentInfoData = parentInfoItem.data;
    //          let datalength = parentInfoData.length;
    //          for (let dataIdx = 0; dataIdx < datalength; ++dataIdx){
    //            if (resultsIterIdx < results.length){
    //              parentInfoData[dataIdx] = results[resultsIterIdx];
    //              ++resultsIterIdx;
    //            }
    //          }
    //        }
    //        return interCallBack(err, parentInfos);
    //      });
    //    }
    function (err, result) {
      if (err) {
        _modulesLogger2['default'].warn(src.id, "getLatestMessageByParent query sender happen error.", err);
      }
      return cb(err, result);
    });
  };
  
  var signTokenPreviewFileUrl = function signTokenPreviewFileUrl(src, data, cb) {
    var functionName = '[signTokenPreviewFileUrl] ';
    var payload = {
      messageId: data._id.toString(),
      fileId: data.content.data[0].fileId
    };
    _modulesLogger2['default'].info(src.id, functionName + 'Sign a one hour previous file token with payload', payload);
    try {
      return cb(null, _jsonwebtoken2['default'].sign(payload, _config2['default'].secrets.session, { expiresInSeconds: 3600 }));
    } catch (err) {
      _modulesLogger2['default'].error(src.id, functionName + 'Sign a one hour previous file token failed', err);
      return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SignJWTFailed));
    }
  };
  
  exports.getPreviewFileUrl = function (src, data, cb) {
    var functionName = '[getPreviewFileUrl] ';
    var fileObj = data.content.data[0];
    if (fileObj.convertStatus == _utilsServerConstants2['default'].ConvertStatusSuccess && fileObj.pages > 0) {
      (function () {
        var url = src.fullurl + "/fileviewer/index.html";
        _modulesLogger2['default'].info(src.id, functionName + 'There exists converted result in gcs. the previous part of url=' + url);
        signTokenPreviewFileUrl(src, data, function (err, token) {
          if (err) {
            _modulesLogger2['default'].warn(src.id, functionName + 'Sign url failed');
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].GetPreviewUrlFailed));
          } else {
            url += '?token=' + token;
            _modulesLogger2['default'].info(src.id, functionName + 'Create singed url=' + url);
            return cb(null, url);
          }
        });
      })();
    } else {
      _modulesLogger2['default'].warn(src.id, functionName + 'There is no converted result in gcs convertStatus=' + fileObj.convertStatus + ' pages=' + fileObj.pages);
      return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].GetPreviewUrlFailed));
    }
  };
  
  exports.getViewUrls = function (src, data, cb) {
    var functionName = '[getViewUrls] ';
    _modulesLogger2['default'].info(src.id, functionName + 'Get file object by messageId=' + data.messageId + ' fileId=' + data.fileId);
    _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].findOne, src.id, { "_id": data.messageId, "content.data.fileId": data.fileId }, { "content.data.$": 1 }, function (err, result) {
      if (err) {
        _modulesLogger2['default'].error(src.id, functionName + 'Get file object by messageId=' + data.messageId + ' fileId=' + data.fileId + ' failed', err);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].GetviewUrlsFailed));
      }
      if (!result) {
        _modulesLogger2['default'].warn(src.id, functionName + 'Get file object by messageId=' + data.messageId + ' fileId=' + data.fileId + ' failed, no record');
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].GetviewUrlsFailed));
      }
      var fileObj = result.content.data[0].toJSON();
      if (fileObj.convertStatus != _utilsServerConstants2['default'].ConvertStatusSuccess || fileObj.pages <= 0) {
        _modulesLogger2['default'].warn(src.id, functionName + 'Get file object by messageId=' + data.messageId + ' fileId=' + data.fileId + ' failed, ' + 'For invalid fileObj convertStatus=' + fileObj.convertStatus + ' pages=' + fileObj.pages);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].GetviewUrlsFailed));
      }
      var pgsize = Math.min(data.offset + data.size, fileObj.pages);
      if (pgsize === 0) {
        pgsize = fileObj.pages;
      }
      _modulesLogger2['default'].info(src.id, functionName + 'Will sign page from pagenum=' + (data.offset + 1) + 'to pagenum=' + pgsize);
      var extname = _fileviewerFileviewBackend2['default'].getConvertedFileExt(src, fileObj);
      var pages = [];
      var pageNum = data.offset;
      _async2['default'].whilst(function () {
        return pageNum < pgsize;
      }, function (interCallback) {
        var data = { key: fileObj.fileId + '_convert/page_' + (pageNum + 1) + extname };
        _modulesFile2['default'].getDownloadSignedUrl(src, data, function (err, result) {
          if (err) {
            _modulesLogger2['default'].error(src.id, functionName + 'Failed to sign download url=' + data.key, err);
            return interCallback(err, pageNum);
          }
          ++pageNum;
          pages.push({ page: pageNum, url: result });
          return interCallback(null, pageNum);
        });
      }, function (err, n) {
        if (err) {
          _modulesLogger2['default'].warn(src.id, functionName + 'Failed to get view urls messageId=' + data.messageId + ' fileId=' + data.fileId);
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].GetviewUrlsFailed));
        }
        _modulesLogger2['default'].info(src.id, functionName + 'Successful to get view urls messageId=' + data.messageId + ' fileId=' + data.fileId);
        return cb(null, { data: pages, totalPages: fileObj.pages });
      });
    });
  };
  
  //Message events callback
  _messageEvent2['default'].onUpdateModifyTime(function (src, msgId) {
    var srcid = 'on_updatemodifytime';
    var functionName = '[MessageEvent.onUpdateModifyTime] ';
    if (src && src.id) {
      srcid = src.id;
    }
    _modulesLogger2['default'].info(srcid, functionName + 'Change the the modified timestamp!');
    _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].update, srcid, { _id: msgId }, { modified: Date.now() }, function (err, createdMessage) {
      if (err) {
        _modulesLogger2['default'].info(srcid, functionName + 'Change the the modified timestamp failed!');
        _modulesLogger2['default'].error(srcid, err.message);
      } else {
        _modulesLogger2['default'].info(srcid, functionName + 'Change the the modified timestamp successfully!');
      }
    });
  });
  
  _messageEvent2['default'].onCardDeleted(function (src, message) {
    _modulesLogger2['default'].info(src.id, 'Event started Task/Idea Deleted', message._id);
    _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].remove, src.id, { "parentMsg._id": message._id }, function (err, removedMessage) {
      if (err) {
        _modulesLogger2['default'].error(src.id, err);
      }
      _modulesLogger2['default'].info(src.id, 'Comments deleted for task/idea with id : ' + message._id);
    });
  });
  
  var convertFilelistsFromMessage = function convertFilelistsFromMessage(src, msg, cb) {
    var functioName = '[convertFilelistsFromMessage] ';
    var nativefiles = [];
    if (msg.content && msg.content.data) {
      nativefiles = msg.content.data.filter(function (fileItem) {
        return fileItem.provider == _fluxConstantsMessageConstants2['default'].DATA_PROVIDER_TYPES.NATIVE && (!fileItem.convertStatus || fileItem.convertStatus == _utilsServerConstants2['default'].ConvertStatusNotStart);
      });
    }
    _modulesLogger2['default'].info(src.id, functioName + 'Get ' + nativefiles.length + 'native files');
    _async2['default'].forEachOf(nativefiles, function (nativeFileItem, idx, interCallback) {
      _fileviewerFileviewBackend2['default'].convertViewFile(src, msg._id, nativeFileItem, interCallback);
    }, function (err, result) {
      _modulesLogger2['default'].info(src.id, functioName + 'Finish trigger tasks to convert files');
      return cb(null);
    });
  };
  
  _messageEvent2['default'].onMessageCreated(function (src, newMsg) {
    var functioName = '[onMessageCreated] ';
    _modulesLogger2['default'].info(src.id, functioName + 'Event try to convert native file', newMsg._id);
    convertFilelistsFromMessage(src, newMsg, function () {
      _modulesLogger2['default'].info(src.id, functioName + 'Finish trigger tasks to convert files');
    });
  });
  
  _messageEvent2['default'].onMessageUpdated(function (src, updateMsg) {
    var functioName = '[onMessageUpdated] ';
    _modulesLogger2['default'].info(src.id, functioName + 'Event try to convert native file', updateMsg._id);
    convertFilelistsFromMessage(src, updateMsg, function () {
      _modulesLogger2['default'].info(src.id, functioName + 'Finish trigger tasks to convert files');
    });
  });
  
  function syncMessageSenderTrigger(src, userInfo, atype) {
    var functionName = '[syncMessageSenderTrigger]';
    var syncdata = {};
    syncdata.senderId = userInfo._id.toString();
    syncdata.senderType = atype;
    syncdata.senderData = {};
    syncdata.senderData['sender.username'] = userInfo.username;
    syncdata.senderData['sender.displayname'] = userInfo.displayname;
    syncdata.senderData['sender.picture_url'] = userInfo.picture_url;
    _taskqueueTaskqueueBackend2['default'].launchDefer(src, 'syncMessageSenderDefer', syncdata, { defferOption: true,
      backoff_seconds: 300,
      attempts: 3,
      callback: function callback(err, result) {
        if (!err) {
          _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Trigger a task to sync topicmessage sender successfully', functionName), syncdata);
        } else {
          _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Trigger a task to sync topicmessage sender failed', functionName), syncdata);
        }
      }
    });
  }
  
  function syncParentMessageTitleTrigger(src, parentMsg) {
    var functionName = '[syncParentMessageTitleTrigger]';
    var syncdata = {};
    syncdata.parentMsgId = parentMsg._id.toString();
    syncdata.parentMsgBodyText = parentMsg.content.bodyText;
    syncdata.parentMsgCategory = parentMsg.category;
  
    _taskqueueTaskqueueBackend2['default'].launchDefer(src, 'syncParentMsgBodyTextDefer', syncdata, { defferOption: true,
      backoff_seconds: 300,
      attempts: 3,
      callback: function callback(err, result) {
        if (!err) {
          _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Trigger a task to sync parent message bodyText successfully', functionName), syncdata);
        } else {
          _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Trigger a task to sync parent message bodyText failed', functionName), syncdata);
        }
      }
    });
  }
  
  function syncChatCountTrigger(src, msgObj) {
    var functionName = '[syncChatCountTrigger]';
    var syncdata = {};
    syncdata.messageId = msgObj._id;
    syncdata.chatCount = msgObj.chatCount;
    _taskqueueTaskqueueBackend2['default'].launchDefer(src, 'syncChatCountDefer', syncdata, { defferOption: true,
      backoff_seconds: 300,
      attempts: 3,
      callback: function callback(err, result) {
        if (!err) {
          _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Trigger a task to sync chat count successfully', functionName), syncdata);
        } else {
          _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Trigger a task to sync chat count failed', functionName), syncdata);
        }
      }
    });
  }
  
  function syncLikeCountTrigger(src, msgObj) {
    var functionName = '[syncLikeCountTrigger]';
    var syncdata = {};
    syncdata.messageId = msgObj._id;
    syncdata.likeCount = msgObj.likeCount;
    _taskqueueTaskqueueBackend2['default'].launchDefer(src, 'syncLikeCountDefer', syncdata, { defferOption: true,
      backoff_seconds: 300,
      attempts: 3,
      callback: function callback(err, result) {
        if (!err) {
          _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Trigger a task to sync like count successfully', functionName), syncdata);
        } else {
          _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Trigger a task to sync like count failed', functionName), syncdata);
        }
      }
    });
  }
  
  function syncMessageSenderDefer(src, data, cb) {
    var functionName = '[syncMessageSenderDefer] ';
    _modulesLogger2['default'].info(src.id, _util2['default'].format('%s sync topicmessage sender info.', functionName), data);
    var senderId = data.senderId;
    var senderType = data.senderType;
    var senderData = data.senderData;
    _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].update, src.id, { 'sender._id': senderId, 'sender.type': senderType }, { '$set': senderData }, { 'multi': true }, function (err, result) {
      if (err) {
        _modulesLogger2['default'].error(src.id, _util2['default'].format('%s sync topicmessage sender info failed.', functionName), err);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SyncMessageSenderFailed));
      } else {
        _modulesLogger2['default'].info(src.id, _util2['default'].format('%s sync topicmessage sender info successfully.', functionName));
        return cb(null);
      }
    });
  }
  _taskqueueTaskqueueBackend2['default'].registerDeferHandle('syncMessageSenderDefer', syncMessageSenderDefer);
  
  function syncParentMsgBodyTextDefer(src, data, cb) {
    var functionName = '[syncParentMsgBodyTextDefer]';
    _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Sync bodyText of parent message.', functionName), data);
    var parentMsgId = data.parentMsgId;
    var parentMsgBodyText = data.parentMsgBodyText;
    var parentMsgCategory = data.parentMsgCategory;
    _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].update, src.id, { 'parentMsg._id': parentMsgId }, { '$set': { 'parentMsg.bodyText': parentMsgBodyText, 'parentMsg.category': parentMsgCategory } }, { 'multi': true }, function (err, result) {
      if (err) {
        _modulesLogger2['default'].error(src.id, _util2['default'].format('%s Sync title of parent message failed.', functionName), err);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SyncParentMessageTitleFailed));
      } else {
        _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Sync title of parent message successfully.', functionName));
        return cb(null);
      }
    });
  }
  _taskqueueTaskqueueBackend2['default'].registerDeferHandle('syncParentMsgBodyTextDefer', syncParentMsgBodyTextDefer);
  
  function syncChatCountDefer(src, data, cb) {
    var functionName = '[syncChatCountDefer]';
    _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Sync chat counter.', functionName), data);
    var messageId = data.messageId;
    var chatCount = data.chatCount;
    _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].update, src.id, { '_id': messageId }, { '$set': { 'chatCount': chatCount } }, function (err, result) {
      if (err) {
        _modulesLogger2['default'].error(src.id, _util2['default'].format('%s Sync chat counter failed.', functionName), err);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SyncParentMessageTitleFailed));
      } else {
        _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Sync chat counter successfully.', functionName));
        return cb(null);
      }
    });
  }
  _taskqueueTaskqueueBackend2['default'].registerDeferHandle('syncChatCountDefer', syncChatCountDefer);
  
  function syncLikeCountDefer(src, data, cb) {
    var functionName = '[syncLikeCountDefer]';
    _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Sync like counter.', functionName), data);
    var messageId = data.messageId;
    var likeCount = data.likeCount;
    _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].update, src.id, { '_id': messageId }, { '$set': { 'likeCount': likeCount } }, function (err, result) {
      if (err) {
        _modulesLogger2['default'].error(src.id, _util2['default'].format('%s Sync like counter failed.', functionName), err);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SyncParentMessageTitleFailed));
      } else {
        _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Sync like counter successfully.', functionName));
        return cb(null);
      }
    });
  }
  _taskqueueTaskqueueBackend2['default'].registerDeferHandle('syncLikeCountDefer', syncLikeCountDefer);

/***/ },
/* 27 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var path = __webpack_require__(20);
  var _ = __webpack_require__(11);
  // var version = require('../version.json');
  
  if (!process.env['NODE_ENV'] || ['logan-testing', 'logan-staging', 'logan-production'].indexOf(process.env['NODE_ENV']) < 0) {
    process.env.NODE_ENV = 'development';
  } else {
    process.env.NODE_ENV = process.env['NODE_ENV'];
  }
  
  function requiredProcessEnv(name) {
    if (!process.env[name]) {
      throw new Error('You must set the ' + name + ' environment variable');
    }
    return process.env[name];
  }
  
  // All configurations will extend these options
  // ============================================
  var all = {
    // Root path of server
    root: path.normalize(__dirname + '/..'),
    supportEmail: 'support@esna.com',
    noreplyEmail: 'noreply@esna.com',
    version: __webpack_require__(152).version,
    // Server port
    // Server IP
    ip: process.env.IP || '0.0.0.0',
    // Secret for session, you will want to change this and make it an environment variable
    secrets: {
      session: 'logan-secret'
    },
    // List of user roles
    userRoles: ['guest', 'user', 'admin'],
  
    sendgrid: {
      username: 'onesna',
      password: '$esna12tech34!'
    },
    traceOnError: true,
    commonSecretJwt: '6757500084'
  };
  // Export the config object based on the NODE_ENV
  // ==============================================
  module.exports = _.merge(all, __webpack_require__(156)("./" + process.env.NODE_ENV + '.js') || {});

/***/ },
/* 28 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _gcs = __webpack_require__(148);
  
  var _gcs2 = _interopRequireDefault(_gcs);
  
  exports.getUploadSignedUrl = function (src, data, cb, expiration) {
    _gcs2['default'].getUploadSignedUrl(src, data, cb, expiration);
  };
  
  exports.getDownloadSignedUrl = function (src, data, cb, expiration) {
    _gcs2['default'].getDownloadSignedUrl(src, data, cb, expiration);
  };
  
  exports.getUploadPublicUrl = function (src, data, cb, expiration) {
    _gcs2['default'].getUploadPublicUrl(src, data, cb, expiration);
  };
  
  exports.getDownloadPublicUrl = function (src, data, cb, expiration) {
    _gcs2['default'].getDownloadPublicUrl(src, data, cb, expiration);
  };
  
  exports.copyFile = function (src, data, cb) {
    _gcs2['default'].copyFile(src, data, cb);
  };
  
  exports.listFiles = function (src, data, cb) {
    _gcs2['default'].listFiles(src, data, cb);
  };
  
  exports.createFileObj = function (src, data, cb) {
    _gcs2['default'].createFileObj(src, data, cb);
  };
  
  exports.deleteFiles = function (src, data, cb) {
    _gcs2['default'].deleteFiles(src, data, cb);
  };

/***/ },
/* 29 */
/***/ function(module, exports) {

  module.exports = require("jsonwebtoken");

/***/ },
/* 30 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5),
      Schema = mongoose.Schema;
  var config = __webpack_require__(4);
  
  var AnonymousSchema = new Schema({
      displayname: String,
      username: String,
      picturefile: String,
      secret: String,
      aType: { type: String, 'default': 'anonymous' },
      created: { type: Date, 'default': Date.now }
  });
  
  /**
   * Virtuals
   */
  AnonymousSchema.set('toJSON', {
      virtuals: true
  });
  
  AnonymousSchema.options.toJSON = {
      transform: function transform(doc, ret, options) {
          delete ret.__v;
          delete ret.id;
          return ret;
      },
      virtuals: true
  };
  function rStr() {
      var _again = true;
  
      _function: while (_again) {
          _again = false;
          var s = Math.random().toString(36).slice(2);if (s.length === 16) {
              return s;
          } else {
              _again = true;
              s = undefined;
              continue _function;
          }
      }
  };
  
  AnonymousSchema.pre("save", function (next) {
      this.secret = rStr();
      next();
  });
  
  AnonymousSchema.virtual('picture_url').get(function () {
      if (!this.picturefile) {
          return 'https://www.onesna.com/norevimages/noimage.jpg';
      }
      if (this.picturefile.indexOf('http://') > -1 || this.picturefile.indexOf('https://') > -1) {
          return this.picturefile;
      }
      return 'https://storage.googleapis.com/' + config.bucket + '/' + this.picturefile;
  });
  
  AnonymousSchema.virtual('profile').get(function () {
      return {
          'displayname': this.displayname,
          'username': this.username,
          'picture_url': this.picture_url
      };
  });
  module.exports = mongoose.model('Anonymous', AnonymousSchema);

/***/ },
/* 31 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var util = __webpack_require__(12),
      EventEmitter = process.EventEmitter,
      instance;
  
  function UserEvent() {
      EventEmitter.call(this);
  }
  
  util.inherits(UserEvent, EventEmitter);
  
  UserEvent.prototype.emitUserSubscribe = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('userSubscribe');
      this.emit.apply(this, args);
  };
  
  UserEvent.prototype.onUserSubscribe = function (callback) {
      this.on('userSubscribe', callback);
  };
  
  UserEvent.prototype.emitUserUpdated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('userUpdated');
      this.emit.apply(this, args);
  };
  
  UserEvent.prototype.onUserUpdated = function (callback) {
      this.on('userUpdated', callback);
  };
  
  UserEvent.prototype.emitUserCreated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('userCreated');
      this.emit.apply(this, args);
  };
  
  UserEvent.prototype.onUserCreated = function (callback) {
      this.on('userCreated', callback);
  };
  
  UserEvent.prototype.emitUserDeleted = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('userDeleted');
      this.emit.apply(this, args);
  };
  
  UserEvent.prototype.onUserDeleted = function (callback) {
      this.on('userDeleted', callback);
  };
  
  UserEvent.prototype.emitUserInvited = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('userInvited');
      this.emit.apply(this, args);
  };
  
  UserEvent.prototype.onUserInvited = function (callback) {
      this.on('userInvited', callback);
  };
  
  var exportMe = {
      getInstance: function getInstance() {
          return instance || (instance = new UserEvent());
      }
  };
  
  module.exports = exportMe.getInstance();

/***/ },
/* 32 */
/***/ function(module, exports) {

  "use strict";
  
  Object.defineProperty(exports, "__esModule", {
  	value: true
  });
  
  var gaConstants = {
  	c_Topic: "Topics",
  	a_newTopic: "Create New Topic",
  	a_inTopicInvite: "Member invited to Topic",
  	a_acceptInvite: "Member accepted Invite",
  
  	c_Enroll: "Enrolls",
  	a_newEnroll: "Request for Enrollment",
  	a_approveEnroll: "Approved an Enrollment",
  
  	c_Socket: "Spaces",
  	a_onVideoEnd: "Video Session End",
  	a_onVideoStart: "Video Session Start",
  	a_onScreenShareStart: "ScreenShare Session Start",
  	a_onScreenShareEnd: "ScreenShare Session End",
  	a_joinRoom: "Join",
  	a_switchTopic: "Switch",
  
  	// a_onConnect: "Connection Established",
  	// a_onDisconnect: "Connection End",
  
  	c_Message: "Messages",
  	a_sendText: "Text Message",
  	a_sendTask: "Task",
  	a_sendIdea: "Idea",
  	a_sendMedia: "Media",
  	a_sendLink: "Link",
  	a_sendVideo: "Video",
  	a_sendImage: "Image",
  
  	c_Collaboration: "Collaborations",
  	a_startVideoSession: "Start Video Session",
  	a_startScreeShare: "Start Screen Share Session",
  
  	c_Email: "Emails",
  	a_newInviteEmail: "Send Invite Email",
  	a_newEnrollEmail: "Send Enroll Request Email",
  	a_EnrollApprovedEmail: "Send Enroll Approved Email"
  };
  
  exports["default"] = gaConstants;
  module.exports = exports["default"];

/***/ },
/* 33 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _config = __webpack_require__(147);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _logger = __webpack_require__(1);
  
  var _logger2 = _interopRequireDefault(_logger);
  
  var _config3 = __webpack_require__(4);
  
  var _config4 = _interopRequireDefault(_config3);
  
  var _request = __webpack_require__(19);
  
  var _request2 = _interopRequireDefault(_request);
  
  var _constants = __webpack_require__(32);
  
  var _constants2 = _interopRequireDefault(_constants);
  
  var _fluxConstantsMessageConstants = __webpack_require__(17);
  
  var _fluxConstantsMessageConstants2 = _interopRequireDefault(_fluxConstantsMessageConstants);
  
  var options = {
    url: 'https://www.google-analytics.com/collect',
    accept: '*/*',
    form: {
      v: 1,
      tid: _config4['default'].googleAnalyticsId,
      cid: 555
    },
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    }
  };
  
  exports.postEvent = function (data) {
    var postOption = options;
    postOption.form.t = "event";
    postOption.form.ec = data.category;
    postOption.form.ea = data.action;
    postOption.form.el = data.label;
    postOption.form.ev = data.value;
    _request2['default'].post(options, function (err, response) {
      if (err || response.statusCode !== 200) {
        _logger2['default'].error(err, 'Wrong response!: ');
        // } else {
        //   logger.info("ga event sent");
      }
    });
  };
  
  exports.postMessageEvent = function (msg) {
    var data = {
      category: _constants2['default'].c_Message,
      label: msg.sender.type
    };
    if (msg.category === _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.TASK) {
      data.action = _constants2['default'].a_sendTask;
    }
    if (msg.category === _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.CHAT) {
      if (msg.content.data && msg.content.data.length > 0) {
        data.action = _constants2['default'].a_sendMedia;
      } else {
        data.action = _constants2['default'].a_sendText;
      }
    }
    if (msg.category === _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA) {
      data.action = _constants2['default'].a_sendIdea;
    }
    exports.postEvent(data);
  };

/***/ },
/* 34 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
  	value: true
  });
  var logger = __webpack_require__(1);
  var config = __webpack_require__(4);
  var projectId = config.projectId; // E.g. 'grape-spaceship-123'
  var credential = {
  	projectId: projectId,
  	keyFilename: config.gcloudKey
  };
  
  exports['default'] = { credential: credential, bucket: config.bucket, tempExtneralBucket: config.tempExtneralBucket };
  module.exports = exports['default'];

/***/ },
/* 35 */
/***/ function(module, exports) {

  module.exports = require("crypto");

/***/ },
/* 36 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _fileviewCommon = __webpack_require__(37);
  
  var _fileviewCommon2 = _interopRequireDefault(_fileviewCommon);
  
  var _modulesFile = __webpack_require__(28);
  
  var _modulesFile2 = _interopRequireDefault(_modulesFile);
  
  var _gcloudLibStorage = __webpack_require__(44);
  
  var _gcloudLibStorage2 = _interopRequireDefault(_gcloudLibStorage);
  
  var _modulesFileGcsConfigJs = __webpack_require__(34);
  
  var _modulesFileGcsConfigJs2 = _interopRequireDefault(_modulesFileGcsConfigJs);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _process = __webpack_require__(21);
  
  var _process2 = _interopRequireDefault(_process);
  
  var _request = __webpack_require__(19);
  
  var _request2 = _interopRequireDefault(_request);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _util = __webpack_require__(12);
  
  var _util2 = _interopRequireDefault(_util);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _crypto = __webpack_require__(35);
  
  var _crypto2 = _interopRequireDefault(_crypto);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _messageMessageEvent = __webpack_require__(16);
  
  var _messageMessageEvent2 = _interopRequireDefault(_messageMessageEvent);
  
  var _cloudconvert = __webpack_require__(163);
  
  var _cloudconvert2 = _interopRequireDefault(_cloudconvert);
  
  var asposeStorageName = (function () {
    if (_modulesFileGcsConfigJs2['default'].bucket == 'onesnatesting') {
      return "gcs_logan_testing";
    } else {
      return null;
    }
  })();
  
  var getTempFileAcl = function getTempFileAcl() {
    if (_modulesFileGcsConfigJs2['default'].bucket == 'onesnatesting') {
      return { entity: 'gcsexternaluseresna@gmail.com', role: _gcloudLibStorage2['default'].acl.READER_ROLE };
    } else {
      return null;
    }
  };
  
  var getAsposeAppSID = function getAsposeAppSID() {
    if (_modulesFileGcsConfigJs2['default'].tempExtneralBucket == 'onesnatesting_temp_external') {
      return 'eabc00d7-72fa-4015-b6a3-dc4b2f36da07';
    } else {
      return null;
    }
  };
  
  var getAsposeAppKey = function getAsposeAppKey() {
    if (_modulesFileGcsConfigJs2['default'].tempExtneralBucket == 'onesnatesting_temp_external') {
      return '9d532b975fa6cfe3a35e4d7d8b26e789';
    } else {
      return null;
    }
  };
  
  var asposSign = function asposSign(src, request_url, joinCharVal) {
    var functionName = '[asposSign ]';
    var appSID = getAsposeAppSID();
    var appKey = getAsposeAppKey();
    if (!appSID || !appKey) {
      _modulesLogger2['default'].error(src.id, functionName + 'There is no App SID or App Key of Aspose for ' + _process2['default'].env.NODE_ENV);
      throw new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AsposeNoSIDOrKey);
    }
    var joinChar = '&';
    if (joinCharVal === '') {
      joinChar = '';
    }
    var unsignedURL = request_url + joinChar + "appsid=" + appSID;
    var signature = _crypto2['default'].createHmac('sha1', appKey).update(unsignedURL).digest('base64').replace('=', '');
    unsignedURL = unsignedURL + "&signature=" + signature;
    return unsignedURL;
  };
  
  var getAsposeApiBaseUrl = function getAsposeApiBaseUrl() {
    return "https://api.aspose.com/v1.1/";
  };
  
  var setPagesToMetaData = function setPagesToMetaData(src, messageId, fileId, pages, cb) {
    var functionName = '[setPagesToMetaData] ';
    _modulesLogger2['default'].info(src.id, functionName + 'Set pages messageId=' + messageId, +' fileId=' + fileId + ' pages=' + pages);
    _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].update, src.id, { "_id": messageId, "content.data.fileId": fileId }, { "$set": { "content.data.$.pages": pages } }, function (err, numAffected) {
      if (!err && numAffected) {
        _modulesLogger2['default'].info(src.id, functionName + 'Set pages successfully');
        _messageMessageEvent2['default'].emitUpdateModifyTime(src, messageId);
        return cb(null);
      } else {
        _modulesLogger2['default'].warn(src.id, functionName + 'Set pages failed', err, numAffected);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SetPagesFailed));
      }
    });
  };
  
  var setPagingToMetaData = function setPagingToMetaData(src, messageId, fileId, paging, cb) {
    var functionName = '[setPagingToMetaData] ';
    _modulesLogger2['default'].info(src.id, functionName + 'Set pages messageId=' + messageId, +' fileId=' + fileId + ' paging=' + paging);
    _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].update, src.id, { "_id": messageId, "content.data.fileId": fileId }, { "$set": { "content.data.$.metaData.paging": paging } }, function (err, numAffected) {
      if (!err && numAffected) {
        _modulesLogger2['default'].info(src.id, functionName + 'Set paging successfully');
        _messageMessageEvent2['default'].emitUpdateModifyTime(src, messageId);
        return cb(null);
      } else {
        _modulesLogger2['default'].warn(src.id, functionName + 'Set paging failed', err, numAffected);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SetPagingFailed));
      }
    });
  };
  
  var removeTempfolder = function removeTempfolder(src, convertObj, cb) {
    var functionName = '[removeTempfolder] ';
    _modulesLogger2['default'].info(src.id, functionName + 'Will remove files in bucket=' + _modulesFileGcsConfigJs2['default'].tempExtneralBucket + 'path=' + convertObj.fileId + '_convert/');
    _modulesFile2['default'].deleteFiles(src, {
      bucketName: _modulesFileGcsConfigJs2['default'].tempExtneralBucket,
      prefix: convertObj.fileId + '_convert/'
    }, function (err, result) {
      if (err) {
        _modulesLogger2['default'].error(src.id, functionName + 'remove files in bucket=' + _modulesFileGcsConfigJs2['default'].tempExtneralBucket + 'path=' + convertObj.fileId + '_convert/ failed', err);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
      }
      _modulesLogger2['default'].info(src.id, functionName + 'Will remove files in bucket=' + _modulesFileGcsConfigJs2['default'].tempExtneralBucket + 'path=' + convertObj.fileId + '_convert/ successfully');
      return cb(null);
    });
  };
  
  function notifyClientsMessageUpdateSender(src, data) {
    var functionName = '[notifyClientsMessageUpdateSender] ';
    var options = {
      method: 'POST',
      url: _utilsServerHelper2['default'].getFullUrlByType(src, 'socket') + '/api/fileviewer/notify-callback',
      headers: {
        'Authorization': 'API_KEY ' + _config2['default'].ESNA_API_KEY
      },
      body: data,
      json: true
    };
    var topicId = data.topicId;
    var msgId = data.payload.msgId;
  
    _modulesLogger2['default'].info(src.id, functionName + 'Send to socket server to notify client update topic=' + topicId + 'messageId=' + msgId, options);
    (0, _request2['default'])(options, function (err, response, body) {
      if (err) {
        _modulesLogger2['default'].error(src.id, functionName + 'Failed to notify client', err);
      } else {
        if (response && response.statusCode == _utilsServerConstants2['default'].HttpSuccessStatus) {
          _modulesLogger2['default'].info(src.id, functionName + 'Successful to notify client');
        } else {
          _modulesLogger2['default'].info(src.id, functionName + 'Failed to notify client', body);
        }
      }
    });
  }
  
  function notifyClientsMessageUpdate(src, convertObj) {
    var functionName = '[notifyClientsMessageUpdate] ';
    _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].find, src.id, { 'content.data.fileId': convertObj.fileId }, { '_id': 1, 'topicId': 1 }, function (err, results) {
      if (err) {
        _modulesLogger2['default'].error(src.id, functionName + 'Query by fildId=' + convertObj.fileId + 'happen error', err);
        return;
      }
      var thumbnailInfo = thumbnailCreateInfoGetter();
      var convertStatus = convertObj.convertedFileObj.convertStatus || 0;
      var _iteratorNormalCompletion = true;
      var _didIteratorError = false;
      var _iteratorError = undefined;
  
      try {
        var _loop = function () {
          var msgItem = _step.value;
  
          if (convertStatus == _utilsServerConstants2['default'].ConvertStatusSuccess) {
            var inData = { key: convertObj.fileId + '_convert/' + thumbnailInfo.fileName, msg: msgItem };
            _modulesFile2['default'].getDownloadSignedUrl(src, inData, function (err, url) {
              if (err) {
                _modulesLogger2['default'].error(src.id, functionName + 'Get download url of thumbnail failed', err);
              } else {
                _modulesLogger2['default'].info(src.id, functionName + 'Get previewUrl=' + url);
                var msgId = msgItem._id.toString();
                var topicId = msgItem.topicId.toString();
                var data = {
                  topicId: topicId,
                  payload: { topicId: topicId, messageId: msgId, content: { data: [{
                        fileId: convertObj.fileId,
                        convertStatus: _utilsServerConstants2['default'].ConvertStatusSuccess,
                        thumbnailUrl: url
                      }] } }
                };
                notifyClientsMessageUpdateSender(src, data);
              }
            });
          } else if (convertStatus == _utilsServerConstants2['default'].ConvertStatusFailed) {
            var msgId = msgItem._id.toString();
            var topicId = msgItem.topicId.toString();
            var data = {
              topicId: topicId,
              payload: { topicId: topicId, messageId: msgId, content: { data: [{
                    fileId: convertObj.fileId,
                    convertStatus: _utilsServerConstants2['default'].ConvertStatusFailed
                  }] } }
            };
            notifyClientsMessageUpdateSender(src, data);
          } else if (convertStatus == _utilsServerConstants2['default'].ConvertStatusProgressing) {
            var msgId = msgItem._id.toString();
            var topicId = msgItem.topicId.toString();
            var data = {
              topicId: topicId,
              payload: { topicId: topicId, messageId: msgId, content: { data: [{
                    fileId: convertObj.fileId,
                    convertStatus: _utilsServerConstants2['default'].ConvertStatusProgressing
                  }] } }
            };
            if (convertObj.convertedFileObj.pages) {
              data.payload.content.data[0].pages = convertObj.convertedFileObj.pages;
            }
            notifyClientsMessageUpdateSender(src, data);
          }
        };
  
        for (var _iterator = results[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
          _loop();
        }
      } catch (err) {
        _didIteratorError = true;
        _iteratorError = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion && _iterator['return']) {
            _iterator['return']();
          }
        } finally {
          if (_didIteratorError) {
            throw _iteratorError;
          }
        }
      }
    });
  }
  
  var cloudconvertApiKey = (function () {
    if (_modulesFileGcsConfigJs2['default'].bucket == 'onesnatesting') {
      return "OmRL2_Kxjb1M4cPSZMvkCKObjtM_UrgAUMO5Z33Ehdri1hCPZhwLTmg7PsEE3n_SY-S1XLE7mmghTQHIC2UWnQ";
    } else if (_modulesFileGcsConfigJs2['default'].bucket == 'onesna') {
      return "OmRL2_Kxjb1M4cPSZMvkCKObjtM_UrgAUMO5Z33Ehdri1hCPZhwLTmg7PsEE3n_SY-S1XLE7mmghTQHIC2UWnQ";
    } else {
      return null;
    }
  })();
  var cloudconvertProjectid = (function () {
    if (_modulesFileGcsConfigJs2['default'].bucket == 'onesnatesting') {
      return "onesnatesting";
    } else if (_modulesFileGcsConfigJs2['default'].bucket == 'onesna') {
      return "esna.com:onesna-all";
    } else {
      return null;
    }
  })();
  
  var cloudconvertBucket = (function () {
    return _modulesFileGcsConfigJs2['default'].tempExtneralBucket;
  })();
  
  var cloudconertCredentials = (function () {
    if (_modulesFileGcsConfigJs2['default'].bucket == 'onesnatesting') {
      return { "type": "service_account",
        "project_id": "onesnatesting",
        "private_key_id": "add1d17f5fda11284956bf6ea6553e10d8336cc9",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCWMyH8pLhKzmG/\numsWLuu8FlgWBmRseJuBnNDk4/S3GgrOWnt+qufxbMxUnYjO0YBttnx4QCOmhxb9\n3teijpBbvM1VQUEtYs7xUwdCNV0ofnPFybJsD0v/ykHltVLRo7c0fHTbUKyugLBs\nzgfBXS2R089kB56yoLcyPz4zvo6CYYpW3dmuF9dcvR13M5QhzsTVQxVRqUO98bk9\nVypWxGCnnWpLEI37I1fAFaweHu+9us17+l5DXeSt1iN8OOsLQTnkdZVe/iyYKdVX\ne44J772YsYMd/uO/CtIwhzoemZRgfdgSzB/h6oMms0AIru/XyHayZ9nppD9YMsU0\n7zu0d+l/AgMBAAECggEAfDXa9Ghv84UK9xg9+MFit0+vFr/AiqeOyjgZ1D/jnwxN\nRWs0V4MUfuXfcFY6zfYZBCH2eydnlA6BZ/7CSq8lGIhhMhDdyp+8zXtBNHKXEKbK\nLRXolE5uJiFoL4Os8qs2FZSausfTlhfcTo5vgWwCBGeqSWm3xrb76PS+BuKeTZj8\nxsaF/wnHJMAj313qsCPTh4pV3TXuYTWQIgidFvhhl72+3vcahXTDhZUAj9Kb4vIR\nWLNPXDOVkFUtKZ10NRdxQRWY8Fb+GnDdwYjUCHWx2NLrQhkJUSpj/qiXEdtN0HUb\nxLgy8cY/8sBdLk5q0U+Ya4BYDcPlL/FyfVIYUqG+GQKBgQDq1oWJDnDv+dnIC58y\n+SMXknVjA4fACcJt6bHpsDTb2objgUblhDJLk2Ds9bRSoqIScGRrEUjE/z7mWAhM\nTxlZfsqEGoUgOVnXGjnO6EGsJitdr5dghLJPtCQz0LFJrOGtg0W2jOxmoKPRZ8P3\nF85vL4hwRRAC0odPgNegNMQ6uwKBgQCjvBdahX6GxOZEzO/UxDfR9MbIuta1z2bg\n/jZt0tFS8tnRLOfsi++thy6wKVxAOZFz5DPnYTWPqtY5d6uY8jQsyIIjXRBSQeGR\ngJGb6DEAmwivSWr6St1/1L8ppLzmAv5hj965SECdcUByxJd5P+C9rqzHXIu4W/B1\ncKgZ6lbqDQKBgHwfHH9faaP9K/WG5wMbGUgpOfA2enau8dwES+vXHWkirG7s8lr3\nL1owsGcuSrvuh7k1PG42uX6d5lH7L4+dsylRUZrXJYvtpCWEEA/jRGrH1d3zpA/4\nswJblVLpt/rX7IQ4QQ2GmKB5wXw52yLrq0mrFvM4HYlQWwJTeCSOHzVnAoGAdamd\nPrfgDQlCUP7U+plnY8H7eBSMZ2r8C4OjqZhuRKWwUdlrcVm+i30x1/ZhDOZR2G6N\nviDlVLD38aRF9EtZozUUEEW4jOQ7LUyvVtKtJDpFK3IfJm7Wbh58oXh5JvHPzFyP\nOabqiDnyjocoM0HsR2NXVozy+zFWw46JvtXgT6ECgYEA45yF6GJoJtKNFZ6ECKOn\n/Ax3/qYLaOxolv537JR1FxxS9wW9zDnjpe3w3ua0K6xt1MXCCFuxgD473GIsX97/\n4AqzUrnyRF+Mg7Z9sX06a2YAMfJXxSrSro2raPEQngjZp7dbsqU3+FYKYeIf6BKT\nH2NJ2Lzwzt5WpL3mYiy5MEU=\n-----END PRIVATE KEY-----\n",
        "client_email": "cloudconvertapi@onesnatesting.iam.gserviceaccount.com",
        "client_id": "114943556601628676554",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://accounts.google.com/o/oauth2/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/cloudconvertapi%40onesnatesting.iam.gserviceaccount.com"
      };
    } else if (_modulesFileGcsConfigJs2['default'].bucket == 'onesna') {
      return {
        "type": "service_account",
        "project_id": "esna.com:onesna-all",
        "private_key_id": "276c82198ae690309e2e0dfd7320c9fa6c93e503",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDMOueHPVVYx8sR\nmsI4CdWP/+nZ7f2NUlbqk1i1abrZvhNKRyJQVgSurxOO6XNq0EbGfOrOFJvkbyRM\nc/1QwmFdB7Ssmqao1f1gBmtspqPQfKWsL+SsTaK7Jo6Y2+h8sNU9mLlEHTdUOLTE\n0Kea0pxvo7znVhL3wtitNO8BqnizzmCCadHpjDfzLB9xvK+Jcvscyj58/dSDyDNa\niIBGK1l5WiQcai9m1pr6qMcvGNKFvpt/ihPwP5QMHy6XdSkmZaeXu+UYfnruEdR+\nrALJvxiz5THQ65WSny1RwM7tF5FnCWMW84mKaFvWUkA1zT0DSFZ7zF1KpgqQiYW/\n+KRvjLZvAgMBAAECggEBAKWMSglySjCBI7bNgAn0zsy/YUxqglGAITxc3FeRsQi3\n7uMS7lm4oGsJOA1sZ0Z6NiTHNX5/bi6peP8QNpK0PkAu8uHHKrlJXO3txj54hemG\nYLVGzVJuTC7wfj6iY75PiUs49VSlaig3HzE7AeGaP3yveXz8ZLu5kfI1KlhrWxRE\nDbPbuAYTjLQH7ht9em6/x2zYqfcdGRv5L+TpsfMvtrE78NFP3X0uCKgT4Uy07Olw\nyECRtMmD5A90CSrZm1AMPs4CMNYl0Y2MoOfNfXL0zseBW3ijmFkpNvjHK+ULB1pE\n4sNsygqItJSGGqQUjJwuDjcEcRpPmYWdPiuY4gNrrwECgYEA/DWo6TOgcWPiKH4T\nKWJnXq/3TgCbc3JBKhygKY3IHHRqCWY/SfgcAJJOcS/qXvGpb4nJpDTNDTkCr1ks\n0uFUZ/p7t4EEiGbKaPqS6aBT/m82x+c94ZvDFVxPQRVFcitjCxFWW3p39L2CJW9w\nqLkoX8suSA+/R/OvX5egG/qIHyECgYEAz0yme5Auat4Qw3M2EqbVEdlxHwS0zQHJ\nmHgX1uYtuFciyhhCEkM+zlhoyTlOXTn/2D1BRLZzoxX/VHnZqj7wmd8NkNcmfDet\n5ZYvs922RPFt2F852f3UeqP5bMjFjWgKXDj3a+beYl5Tx9cnlk9a4LXi4I5D5qb/\nQXeXtfwX848CgYAnajNljn3qepOjhGB2PTyuXY2mkQ26MwbgD+0v0UqOt9rCcUo+\nwxmNNVAw/C4CfH3gQoZStTW+dURoJuWMZ06LmWewO+d7caT8VvySqk22G6dSAl93\nXKJWOkDgiPR7bTBjUGhQj4kjpGIse4f9tkILBnPLKzrXgcvMgqOw+6w+QQKBgGKX\n8C6gmpMVXx+2cidY1coRgy3fjSZcDUfJBn2dKG2ec9tuwi3xcbOudNgPu2e3qClu\nqNZHeKQ+WBwTgCTqnoBwiAE1cwZtbPXfAn0nnAMaWMYqNFer1B0oU/8bVmo064iF\nR5g4S9i5SFupxxhEUdLCb0+iGkVfc9PtT2isp6+dAoGBAM9uNHL0ms0HSTkUs7Mb\nyMsQOh8bJe8vyXBmGIazg17Fj9MTPdus2sdYecN/W4NQb7II2ET60SpM+FcBn349\nNQ0pAxGtp+8r4y5LDX7GS+gySt791UKDmT60DO+0jNMz7NHy1nml26fghaPUhv6w\nCLLOF20/mqsQbU5Mnb4qC/R2\n-----END PRIVATE KEY-----\n",
        "client_email": "cloudconvertapi@onesna-all.esna.com.iam.gserviceaccount.com",
        "client_id": "117867548539991076540",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://accounts.google.com/o/oauth2/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/cloudconvertapi%40onesna-all.esna.com.iam.gserviceaccount.com"
      };
    } else {
      return null;
    }
  })();
  
  function fileInfoFromCloudConvert(src, format, path, cb) {
    var functionName = '[fileInfoFromCloudConvert] ';
    var cloudconvertobj = new _cloudconvert2['default'](cloudconvertApiKey);
    _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Get file information by cloud convert. format=%s, path=%s', functionName, format, path));
    var convertparam = {
      "inputformat": format,
      "mode": "info",
      "input": {
        "googlecloud": {
          "projectid": cloudconvertProjectid,
          "bucket": cloudconvertBucket,
          "credentials": cloudconertCredentials
        }
      },
      "file": path
    };
    var process = cloudconvertobj.convert(convertparam, function (err, result) {
      if (err) {
        _modulesLogger2['default'].error(src.id, _util2['default'].format('%s Get file information by cloud convert failed', functionName), err, convertparam);
        if (err && err.code === 422) {
          err = new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError);
        }
        return cb(err);
      } else {
        if (result && result.data && result.data.info && result.data.info.Pages) {
          _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Get page number = %s', functionName, result.data.info.Pages));
          return cb(null, parseInt(result.data.info.Pages));
        } else {
          _modulesLogger2['default'].warn(src.id, _util2['default'].format('%s Can not get page number from file. Exist convert task', functionName));
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
        }
      }
    });
  }
  
  function cloudConvertConvertfile(src, inParams, progresscb, cb) {
    var functionName = '[cloudConvertConvertfile] ';
    var cloudconvertobj = new _cloudconvert2['default'](cloudconvertApiKey);
    var processobj = null;
    var format = inParams.format,
        outformat = inParams.outformat,
        path = inParams.path,
        outpath = inParams.outpath,
        processurl = inParams.processurl,
        converteroptions = inParams.converteroptions;
    if (!processurl) {
      _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Convert file %s from format=%s to path %s with format=%s.', functionName, path, format, outpath, outformat));
      var convertparam = {
        "inputformat": format,
        "outputformat": outformat,
        "input": {
          "googlecloud": {
            "projectid": cloudconvertProjectid,
            "bucket": cloudconvertBucket,
            "credentials": cloudconertCredentials
          }
        },
        "file": path,
        "timeout": 0,
        "output": {
          "googlecloud": {
            "projectid": cloudconvertProjectid,
            "bucket": cloudconvertBucket,
            "credentials": cloudconertCredentials
          }
        },
        "path": outpath
      };
      if (converteroptions) {
        convertparam.converteroptions = converteroptions;
      }
      processobj = cloudconvertobj.convert(convertparam, function (err, result) {
        if (err) {
          _modulesLogger2['default'].error(src.id, _util2['default'].format('%s Convert file happens error', functionName), err, convertparam);
        } else {
          _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Convert file successfully %s', functionName, path));
        }
        if (!cloudconvertobj.convertedCallbacked) {
          if (err && err.code === 422) {
            err = new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError);
          }
          cloudconvertobj.convertedCallbacked = true;
          return cb(err, result);
        }
      });
    } else {
      _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Convert file %s from format=%s to path %s with format=%s already started query status by url=%s.', functionName, path, format, outpath, outformat, processurl));
      var Process = __webpack_require__(164);
      processobj = new Process(cloudconvertobj);
      processobj.url = processurl;
      processobj.wait(function (err, result) {
        if (err) {
          _modulesLogger2['default'].error(src.id, _util2['default'].format('%s Convert file happens error', functionName), err);
        } else {
          _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Convert file successfully %s', functionName, processobj.url));
        }
        if (!processobj.convertedCallbacked) {
          if (err && err.code === 422) {
            err = new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError);
          }
          processobj.convertedCallbacked = true;
          return cb(err, result);
        }
      });
    }
    processobj.on('progress', function (err, result) {
      return progresscb(err, result);
    });
    return processobj;
  }
  
  function initilizeConvertingProcess(src, data, cb) {
    var functionName = '[initilizeConvertingProcess] ';
    var convertObj = data.convertObj;
    var oriDocument = data.oriDocument || 'oriDocument';
    var endRequestForRequestEndSoon = false;
    _async2['default'].waterfall([
    //Query file information from database
    function (interCallback) {
      _modulesLogger2['default'].info(src.id, _util2['default'].format(functionName + 'Get file object from message by messageId=%s fileId=%s.', convertObj.messageId, convertObj.fileId));
      _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].findOne, src.id, { '_id': convertObj.messageId,
        'content.data.fileId': convertObj.fileId }, { "content.data.$": 1 }, function (err, msgObj) {
        if (!err && msgObj) {
          _modulesLogger2['default'].info(src.id, _util2['default'].format(functionName + 'Get file object from message by messageId=%s fileId=%s successfully.', convertObj.messageId, convertObj.fileId));
          return interCallback(err, msgObj.content.data[0].toJSON());
        }
        _modulesLogger2['default'].info(src.id, _util2['default'].format(functionName + 'Get file object from message by messageId=%s fileId=%s failed.', convertObj.messageId, convertObj.fileId), err);
        return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
      });
    },
    //copy the file to that folder
    function (fileObj, interCallback) {
      if (fileObj.convertStatus == _utilsServerConstants2['default'].ConvertStatusSuccess || fileObj.convertStatus == _utilsServerConstants2['default'].ConvertStatusFailed) {
        _modulesLogger2['default'].info(src.id, functionName + "The file already converted before with status ", fileObj.convertStatus);
        return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskqueueEndBeforeTimout));
      }
      convertObj.convertedFileObj = fileObj;
      if (fileObj.pages) {
        _modulesLogger2['default'].info(src.id, functionName + 'The file already copied');
        return interCallback(null, fileObj);
      }
      _modulesLogger2['default'].info(src.id, functionName + 'Copy file to temp convert folder with bucket=' + _modulesFileGcsConfigJs2['default'].tempExtneralBucket + ' Folder=logan/' + convertObj.fileId + '_convert/');
      _modulesFile2['default'].copyFile(src, {
        srcBucketName: _modulesFileGcsConfigJs2['default'].bucket,
        srcFileName: convertObj.fileId,
        destBucketName: _modulesFileGcsConfigJs2['default'].tempExtneralBucket,
        destFileName: convertObj.fileId + '_convert/' + oriDocument
      }, function (err, result) {
        if (err) {
          _modulesLogger2['default'].warn(src.id, functionName + 'Copy file failed', err);
        } else {
          _modulesLogger2['default'].info(src.id, functionName + 'Copy file successfully');
        }
        return interCallback(err, fileObj);
      });
    }], function (err, result) {
      if (endRequestForRequestEndSoon) {
        _fileviewCommon2['default'].endRequestAndLauchAnotherDefer(src, convertObj, function (err) {
          return cb(err);
        });
      } else {
        return cb(err, result);
      }
    });
  }
  
  function cloudConvertPdftoSvg(src, data, cb) {
    var functionName = '[cloudConvertPdftoSvg] ';
    var convertObj = data.convertObj;
    var fileObj = data.fileObj;
    var oriDocument = data.oriDocument || 'oridocument' + '.pdf';
    var endRequestForRequestEndSoon = false;
    _async2['default'].waterfall([
    //get the page number of the slides
    function (interCallback) {
      if (fileObj.pages) {
        _modulesLogger2['default'].info(src.id, functionName + 'The slides file already get page number before. pages=' + fileObj.pages);
        return interCallback(null, fileObj);
      }
      fileInfoFromCloudConvert(src, 'pdf', 'logan/' + convertObj.fileId + '_convert' + '/' + oriDocument, function (err, pages) {
        if (err) {
          if (err.code == _errorsErrors2['default'].TaskNoRetryError) {
            return interCallback(err);
          } else {
            _modulesLogger2['default'].warn(src.id, _util2['default'].format('%s Get page from cloudconvert happen error. Try later', functionName));
            return interCallback(_errorsErrors2['default'].FileConvertFailed);
          }
        } else {
          setPagesToMetaData(src, convertObj.messageId, convertObj.fileId, pages, function (err, result) {
            if (err) {
              _modulesLogger2['default'].error(src.id, functionName + 'Set page to file failed', err);
              return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
            } else {
              _modulesLogger2['default'].info(src.id, functionName + 'Set page to file successfully');
              fileObj.pages = pages;
              fileObj.convertStatus = _utilsServerConstants2['default'].ConvertStatusProgressing;
              notifyClientsMessageUpdate(src, convertObj);
              return interCallback(null, fileObj);
            }
          });
        }
      });
    },
    //Use cloud convert api to split pdf file to svg files
    function (fileObj, interCallback) {
      _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Convert file from pdf to svg', functionName));
      var options = {
        format: 'pdf',
        outformat: 'svg',
        path: 'logan/' + convertObj.fileId + '_convert' + '/' + oriDocument,
        outpath: 'logan/' + convertObj.fileId + '_convert' + '/',
        processurl: convertObj.extraData.pdfToSvgProcessurl
  
      };
      if (data.pdftosvgConverteroptions) {
        options.converteroptions = data.pdftosvgConverteroptions;
      }
      var processobj = cloudConvertConvertfile(src, options, function (err, result) {
        if (_utilsServerHelper2['default'].requestWillEndSoon(src)) {
          _modulesLogger2['default'].info(src.id, 'This request will end soon, create another taskqueue to continue working');
          endRequestForRequestEndSoon = true;
          return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskqueueEndBeforeTimout));
        }
      }, function (err, result) {
        delete convertObj.extraData.pdfToSvgProcessurl;
        if (err) {
          _modulesLogger2['default'].warn(src.id, functionName + 'Convert pdf to svg happen error', err);
          if (err.code == _errorsErrors2['default'].TaskNoRetryError) {
            return interCallback(err);
          } else {
            return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
          }
        } else {
          _modulesLogger2['default'].info(src.id, functionName + 'Convert pdf to svg successfully');
          return interCallback(null, fileObj);
        }
      });
  
      if (processobj && processobj.url && !convertObj.extraData.pdfToSvgProcessurl) {
        convertObj.extraData.pdfToSvgProcessurl = processobj.url;
      }
    }], function (err, result) {
      if (endRequestForRequestEndSoon) {
        _fileviewCommon2['default'].endRequestAndLauchAnotherDefer(src, convertObj, function (err) {
          return cb(err);
        });
      } else {
        return cb(err, result);
      }
    });
  }
  
  var thumbnailCreateInfoGetter = function thumbnailCreateInfoGetter() {
    return {
      fileName: 'thumbnail.jpg',
      outformat: 'jpg',
      contentType: 'image/jpeg'
    };
  };
  
  function convertPdfToThumbnail(src, data, cb) {
    var functionName = '[convertPdfToThumbnail] ';
    var convertObj = data.convertObj;
    var oriDocument = data.oriDocument || 'oridocument' + '.pdf';
    var thumbnaulInfo = thumbnailCreateInfoGetter();
    var fileObj = data.fileObj;
    var dstFile = 'logan/' + convertObj.fileId + '_convert' + '/' + thumbnaulInfo.fileName;
    var srcFile = 'logan/' + convertObj.fileId + '_convert' + '/' + oriDocument;
    var options = {
      format: 'pdf',
      outformat: thumbnaulInfo.outformat,
      path: srcFile,
      outpath: dstFile,
      converteroptions: {
        "resize": "1000x1000",
        "resizeenlarge": true,
        "page_range": "0-0"
      }
    };
    _modulesLogger2['default'].info(src.id, functionName + 'Will convert pdf page 1 to jpeg file with options', options);
    cloudConvertConvertfile(src, options, function (err, result) {}, function (err, result) {
      if (err) {
        _modulesLogger2['default'].warn(src.id, functionName + 'Convert pdf page 1 to jpeg happen error', err);
        if (err.code == _errorsErrors2['default'].TaskNoRetryError) {
          return interCallback(err);
        } else {
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
        }
      } else {
        _modulesLogger2['default'].info(src.id, functionName + 'Convert pdf page 1 to jpeg successfully');
        return cb(err, fileObj);
      }
    });
  }
  
  function copyBackRealFolder(src, data, cb) {
    var functionName = '[copyBackRealFolder] ';
    var convertObj = data.convertObj;
    var fileObj = data.fileObj;
    var oriDocument = data.oriDocument || 'oridocument';
  
    _modulesLogger2['default'].info(src.id, functionName + 'List all svg files from converted folder');
    var filePrefix = oriDocument + '_';
    if (fileObj.pages == 1 && convertObj instanceof cloudConvertToSvgFileView) {
      filePrefix = oriDocument + '.' + convertObj.outformat;
    }
    _modulesFile2['default'].listFiles(src, { bucketName: _modulesFileGcsConfigJs2['default'].tempExtneralBucket,
      prefix: convertObj.fileId + '_convert/' + filePrefix
    }, function (err, results) {
      _modulesLogger2['default'].info(src.id, functionName + 'List all svg files from converted folder with files number=' + results.length);
      if (results.length < fileObj.pages) {
        _modulesLogger2['default'].warn(src.id, functionName + 'Happen some errors for list pages. pagenumber should be ' + fileObj.pages);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
      }
      _async2['default'].forEachOf(results, function (aSrcFile, idx, interCallback) {
        var cutPosString = 'logan/';
        var cutPos = aSrcFile.metadata.name.indexOf(cutPosString);
        var path = null;
        if (cutPos >= 0) {
          path = aSrcFile.metadata.name.substring(cutPos + cutPosString.length);
        } else {
          _modulesLogger2['default'].warn(src.id, functionName + 'Failed to get path from name=' + aSrcFile.metadata.name);
        }
        if (path) {
          path = path.replace(filePrefix, 'page_');
          path = path.replace('page_0', 'page_');
          if (path.endsWith('page_')) {
            path = path + '1' + '.' + convertObj.outformat;
          }
  
          _modulesLogger2['default'].info(src.id, functionName + 'Will copy file to bucket=' + _modulesFileGcsConfigJs2['default'].bucket + ' path=' + path);
          _modulesFile2['default'].createFileObj(src, { bucketName: _modulesFileGcsConfigJs2['default'].bucket,
            path: path
          }, function (err, destFileObj) {
            aSrcFile.copy(destFileObj, function (err, result) {
              if (err) {
                _modulesLogger2['default'].warn(src.id, functionName + 'Copy file failed', err);
                return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
              }
              result.setMetadata({ contentType: 'image/svg+xml' }, function (err, apiResponse) {
                if (err) {
                  _modulesLogger2['default'].error(src.id, functionName + 'Set mimetype image/svg+xml failed', err);
                  return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                } else {
                  return interCallback(null);
                }
              });
            });
          });
        } else {
          return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
        }
      }, function (err) {
        if (err) {
          _modulesLogger2['default'].warn(src.id, functionName + 'Copy converted file back to real folder happen error', err);
        } else {
          _modulesLogger2['default'].info(src.id, functionName + 'Copy converted file back to real folder successfully');
        }
        return cb(err, fileObj);
      });
    });
  }
  
  function copyThumbnailRealFolder(src, data, cb) {
    var functionName = '[copyThumbnailRealFolder] ';
    var convertObj = data.convertObj;
    var fileObj = data.fileObj;
    var thumbnailInfo = thumbnailCreateInfoGetter();
    var fileName = data.thumbnailfileName || thumbnailInfo.fileName;
    _modulesFile2['default'].listFiles(src, { bucketName: _modulesFileGcsConfigJs2['default'].tempExtneralBucket,
      prefix: convertObj.fileId + '_convert/' + fileName
    }, function (err, results) {
      if (results.length < 1) {
        _modulesLogger2['default'].warn(src.id, functionName + 'There is no thumbnail of ', convertObj.fileId + '_convert/' + fileName);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
      }
      var aSrcFile = results[0];
      _modulesFile2['default'].createFileObj(src, { bucketName: _modulesFileGcsConfigJs2['default'].bucket,
        path: convertObj.fileId + '_convert/' + thumbnailInfo.fileName
      }, function (err, destFileObj) {
        aSrcFile.copy(destFileObj, function (err, result) {
          if (err) {
            _modulesLogger2['default'].warn(src.id, functionName + 'Copy file failed', err);
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
          }
          result.setMetadata({ contentType: thumbnailInfo.contentType }, function (err, apiResponse) {
            if (err) {
              _modulesLogger2['default'].error(src.id, functionName + 'Set mimetype ' + thumbnailInfo.contentType + ' failed', err);
              return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
            } else {
              return cb(null, fileObj);
            }
          });
        });
      });
    });
  }
  
  function _cleanWork(src, data, cb) {
    var functionName = '[cleanWork] ';
    var convertObj = data.convertObj;
    _modulesLogger2['default'].info(src.id, functionName + 'Begin do clean work');
    var thumbnailInfo = thumbnailCreateInfoGetter();
    _async2['default'].waterfall([function (interCallback) {
      if (convertObj.convertedFileObj) {
        var convertStatus = convertObj.convertedFileObj.convertStatus || 0;
        if (convertStatus == _utilsServerConstants2['default'].ConvertStatusSuccess || convertStatus == _utilsServerConstants2['default'].ConvertStatusFailed) {
          _modulesLogger2['default'].info(src.id, functionName + 'Update all files in topic message with fileId=' + convertObj.fileId + ' with status=' + convertStatus);
          _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].update, src.id, { 'content.data.fileId': convertObj.fileId }, { '$set': {
              'content.data.$.convertStatus': convertStatus,
              'content.data.$.thumbnailFile': convertStatus == _utilsServerConstants2['default'].ConvertStatusSuccess ? convertObj.fileId + '_convert/' + thumbnailInfo.fileName : '',
              'modified': Date.now() } }, { multi: true, 'new': true }, function (err, updateResults) {
            if (err) {
              _modulesLogger2['default'].error(src.id, functionName + 'Update all files with same fileId failed', err);
              return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ConvertFileCleanWorkFailed));
            } else {
              notifyClientsMessageUpdate(src, convertObj);
            }
          });
        }
      } else {
        _modulesLogger2['default'].warn(src.id, functionName + 'There is no convertedFileObj in convertObj!!!');
      }
      return interCallback(null);
    }, function (interCallback) {
      removeTempfolder(src, convertObj, function (err) {
        if (err) {
          _modulesLogger2['default'].warn(src.id, functionName + 'Remove temp folder failed', err);
        } else {
          _modulesLogger2['default'].info(src.id, functionName + 'Remove temp folder failed successfully');
        }
        return cb(err);
      });
    }], function (err, result) {});
  }
  
  function cloudConvertToPdf(src, data, cb) {
    var functionName = '[cloudConvertToPdf] ';
    var convertObj = data.convertObj;
    var fileObj = data.fileObj;
    var oriDocument = data.oriDocument || 'oridocument';
  
    if (fileObj.pages) {
      _modulesLogger2['default'].info(src.id, functionName + 'The slides file already get page number before. pages=' + fileObj.pages);
      return cb(null, fileObj);
    }
    _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Convert file from format=%s to pdf', functionName, convertObj.informat));
    var options = {
      format: convertObj.informat,
      outformat: 'pdf',
      path: 'logan/' + convertObj.fileId + '_convert' + '/' + oriDocument + '.' + convertObj.informat,
      outpath: 'logan/' + convertObj.fileId + '_convert' + '/' + oriDocument + '.pdf',
      processurl: convertObj.extraData.excelToPdfProcessurl
    };
    if (data.toPdfConverteroptions) {
      options.converteroptions = data.toPdfConverteroptions;
    }
    var processobj = cloudConvertConvertfile(src, options, function (err, result) {
      if (_utilsServerHelper2['default'].requestWillEndSoon(src)) {
        _modulesLogger2['default'].info(src.id, 'This request will end soon, create another taskqueue to continue working');
        _fileviewCommon2['default'].endRequestAndLauchAnotherDefer(src, convertObj, function (err) {
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
        });
      }
    }, function (err, result) {
      delete convertObj.extraData.excelToPdfProcessurl;
      if (err) {
        _modulesLogger2['default'].warn(src.id, _util2['default'].format('%s Convert file from format=%s to pdf happen error', functionName, convertObj.informat), err);
        if (err.code == _errorsErrors2['default'].TaskNoRetryError) {
          return cb(err);
        } else {
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
        }
      } else {
        _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Convert file from format=%s to pdf happen error successfully', functionName, convertObj.informat));
        return cb(null, fileObj);
      }
    });
    if (processobj && processobj.url && !convertObj.extraData.excelToPdfProcessurl) {
      convertObj.extraData.excelToPdfProcessurl = processobj.url;
    }
  }
  
  var cloudConvertToSvgFileView = (function (_fileViewCommon$FileViewer) {
    _inherits(cloudConvertToSvgFileView, _fileViewCommon$FileViewer);
  
    function cloudConvertToSvgFileView() {
      _classCallCheck(this, cloudConvertToSvgFileView);
  
      _get(Object.getPrototypeOf(cloudConvertToSvgFileView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(cloudConvertToSvgFileView, [{
      key: 'cleanWork',
      value: function cleanWork(cb) {
        var inData = {
          convertObj: this
        };
        _cleanWork(this.src, inData, cb);
      }
    }, {
      key: 'toPdf',
      value: function toPdf(inData, cb) {
        cloudConvertToPdf(this.src, inData, cb);
      }
    }, {
      key: 'convert',
      value: function convert(cb) {
        var self = this;
        var functionName = '[docToSvgFileView.convert] ';
        var endRequestForRequestEndSoon = false;
        var oriDocument = 'oridocument';
        _async2['default'].waterfall([
        //Query file information from database
        function (interCallback) {
          var inData = {
            convertObj: self,
            oriDocument: oriDocument + '.' + self.informat
          };
          initilizeConvertingProcess(self.src, inData, interCallback);
        },
        //Convert to pdf file
        function (fileObj, interCallback) {
          var inData = {
            convertObj: self,
            fileObj: fileObj,
            oriDocument: oriDocument
          };
          self.toPdf(inData, interCallback);
        },
        //Convert pdf to svg   
        function (fileObj, interCallback) {
          var inData = {
            convertObj: self,
            fileObj: fileObj,
            oriDocument: oriDocument + '.pdf'
          };
          cloudConvertPdftoSvg(self.src, inData, interCallback);
        },
        //Copy converted folder back to real official folder
        function (fileObj, interCallback) {
          var inData = {
            convertObj: self,
            fileObj: fileObj,
            oriDocument: oriDocument
          };
          copyBackRealFolder(self.src, inData, interCallback);
        },
        //Create thumbnail
        function (fileObj, interCallback) {
          var inData = {
            convertObj: self,
            fileObj: fileObj,
            oriDocument: oriDocument + '.pdf'
          };
          convertPdfToThumbnail(self.src, inData, interCallback);
        },
        //Copy thumbnail file to official folder
        function (fileObj, interCallback) {
          var inData = {
            convertObj: self,
            fileObj: fileObj,
            oriDocument: oriDocument,
            thumbnailfileName: oriDocument + '.jpg'
          };
          copyThumbnailRealFolder(self.src, inData, interCallback);
        }], function (err, result) {
          if (endRequestForRequestEndSoon) {
            _fileviewCommon2['default'].endRequestAndLauchAnotherDefer(self.src, self, function (err) {
              return cb(err);
            });
          } else {
            return cb(err, result);
          }
        });
      }
    }]);
  
    return cloudConvertToSvgFileView;
  })(_fileviewCommon2['default'].FileViewer);
  
  exports['default'] = {
    asposeStorageName: asposeStorageName,
    asposSign: asposSign,
    getAsposeApiBaseUrl: getAsposeApiBaseUrl,
    setPagesToMetaData: setPagesToMetaData,
    setPagingToMetaData: setPagingToMetaData,
    removeTempfolder: removeTempfolder,
    notifyClientsMessageUpdate: notifyClientsMessageUpdate,
    cloudconvertApiKey: cloudconvertApiKey,
    cloudconvertProjectid: cloudconvertProjectid,
    cloudconertCredentials: cloudconertCredentials,
    cloudconvertBucket: cloudconvertBucket,
    fileInfoFromCloudConvert: fileInfoFromCloudConvert,
    cloudConvertConvertfile: cloudConvertConvertfile,
    cloudConvertPdftoSvg: cloudConvertPdftoSvg,
    cloudConvertToPdf: cloudConvertToPdf,
    initilizeConvertingProcess: initilizeConvertingProcess,
    copyBackRealFolder: copyBackRealFolder,
    cleanWork: _cleanWork,
    cloudConvertToSvgFileView: cloudConvertToSvgFileView
  };
  module.exports = exports['default'];

/***/ },
/* 37 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _modulesMemcache = __webpack_require__(48);
  
  var _modulesMemcache2 = _interopRequireDefault(_modulesMemcache);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _messageMessageEvent = __webpack_require__(16);
  
  var _messageMessageEvent2 = _interopRequireDefault(_messageMessageEvent);
  
  var ConvertLockTime = 10;
  
  var FileViewer = (function () {
    function FileViewer(src, messageId, fileId, handleKey, informat, outformat, extraData) {
      _classCallCheck(this, FileViewer);
  
      this.fileId = fileId;
      this.messageId = messageId;
      this.src = src;
      this.handleKey = handleKey;
      this.convertedFileObj = null;
      this.informat = informat;
      this.outformat = outformat;
      this.extraData = extraData || {};
    }
  
    _createClass(FileViewer, [{
      key: 'getProperties',
      value: function getProperties() {
        return {
          fileId: this.fileId,
          messageId: this.messageId,
          src: this.src,
          handleKey: this.handleKey,
          informat: this.informat,
          outformat: this.outformat,
          extraData: this.extraData
        };
      }
    }, {
      key: 'setProperties',
      value: function setProperties(inData) {
        this.fileId = inData.fileId;
        this.messageId = inData.messageId;
        this.src = inData.src;
        this.handleKey = inData.handleKey;
        this.informat = inData.informat;
        this.outformat = inData.outformat;
        this.extraData = inData.extraData;
      }
    }, {
      key: 'setConvertStatus',
      value: function setConvertStatus(statusValue, cb) {
        var _this = this;
  
        var functionName = '[FileViewer.setConvertStatus] ';
        var self = this;
        _modulesLogger2['default'].info(this.src.id, functionName + 'Set convert status messageId=' + this.messageId + ' fileId=' + this.fileId + ' status=' + statusValue);
        _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].update, this.src.id, { "_id": this.messageId, "content.data.fileId": this.fileId }, { "$set": { "content.data.$.convertStatus": statusValue } }, function (err, numAffected) {
          if (!err && numAffected) {
            _modulesLogger2['default'].info(self.src.id, functionName + 'Set convert status successfully');
            if (_this.convertedFileObj) {
              _this.convertedFileObj.convertStatus = statusValue;
            }
            _messageMessageEvent2['default'].emitUpdateModifyTime(self.src, _this.messageId);
            return cb(null, statusValue);
          } else {
            _modulesLogger2['default'].warn(self.src.id, functionName + 'Set convert status successfully failed', err, numAffected);
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SetConvertStatusFailed));
          }
        });
      }
    }, {
      key: 'convert',
      value: function convert(cb) {
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NoSuchConverter));
      }
    }, {
      key: 'validateConvert',
      value: function validateConvert(cb) {
        var functionName = '[validateConvert] ';
        var key = _utilsServerConstants2['default'].ConvertMemcacheKeyPrefix + this.fileId;
        var self = this;
        _modulesLogger2['default'].info(this.src.id, functionName + 'Add key=' + key + ' to memcache to guareentee only one convert request can process');
        _modulesMemcache2['default'].add(this.src, key, '', ConvertLockTime, function (err, result) {
          if (!err && result) {
            _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].findOne, { 'content.data': { 'fileId': self.fileId, 'convertStatus': { $ne: _utilsServerConstants2['default'].ConvertStatusNotStart } } }, function (err, result) {
              if (!err && result) {
                _modulesLogger2['default'].info(self.src.id, functionName + 'The file begin with fileId=' + self.fileId + ' will begin convert soon');
                return cb(null);
              } else {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'The file already begin convert fileId=' + self.fileId);
                return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AlreadyStartConvert));
              }
            });
          } else {
            _modulesLogger2['default'].warn(self.src.id, functionName + 'Ask for convert same file at same time fileId=' + self.fileId);
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AlreadyStartConvert));
          }
        });
      }
    }, {
      key: 'cleanWork',
      value: function cleanWork(cb) {
        var functionName = '[FileViewer.cleanWork] ';
        _modulesLogger2['default'].info(this.src.id, functionName + 'Null clean work');
        return cb(null);
      }
    }]);
  
    return FileViewer;
  })();
  
  exports.FileViewer = FileViewer;
  exports.endRequestAndLauchAnotherDefer = function (src, convertObj, cb) {
    var functionName = '[endRequestAndLauchAnotherDefer] ';
    var data = { messageId: convertObj.migrateId,
      fileId: convertObj.fileId,
      handleKey: convertObj.handleKey,
      informat: convertObj.informat,
      outformat: converObj.outformat,
      extraData: convertObj.extraData
    };
    _modulesLogger2['default'].info(src.id, functionName + 'Launch another task to continue convert working!');
    return taskqueue.launchDefer(src, 'convertAFileDefer', data, { defferOption: true,
      backoff_seconds: 300,
      attempts: 3,
      callback: function callback(err, result) {
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskqueueEndBeforeTimout));
      }
    });
  };

/***/ },
/* 38 */
/***/ function(module, exports) {

  'use strict';
  
  exports.getIssFromHostname = function (hostname) {
    var parts = hostname.split('.');
    if (parts.length >= 3) {
      return parts.slice(parts.length - 2).join('.');
    } else {
      return hostname;
    }
  };

/***/ },
/* 39 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
  	value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror = __webpack_require__(41);
  
  var _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror2 = _interopRequireDefault(_node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror);
  
  var _componentsTranslate = __webpack_require__(47);
  
  var _componentsTranslate2 = _interopRequireDefault(_componentsTranslate);
  
  var _ZSLogger = __webpack_require__(49);
  
  var _ZSLogger2 = _interopRequireDefault(_ZSLogger);
  
  var ns = '[MeetingConstants]';
  
  var MeetingConstants = {};
  
  MeetingConstants.DEFAULT_END_TIME_DURATION = 1;
  MeetingConstants.ATTENDEE_TYPES = {
  	ADMIN: {
  		type: 'admin',
  		text: _componentsTranslate2['default'].get('ADMIN'),
  		icon: 'fa fa-key',
  		img: 'key.svg'
  	},
  	MEMBER: {
  		type: 'member',
  		text: _componentsTranslate2['default'].get('MEMBER'),
  		icon: 'fa fa-user',
  		img: 'businessman.svg'
  	},
  	GUEST: {
  		type: 'guest',
  		text: _componentsTranslate2['default'].get('GUEST'),
  		icon: 'fa fa-lock',
  		img: 'lock.svg'
  	}
  };
  
  MeetingConstants.getAttendeeObjectByType = function (type) {
  	for (var i in MeetingConstants.ATTENDEE_TYPES) {
  		if (MeetingConstants.ATTENDEE_TYPES[i].type == type) {
  			return MeetingConstants.ATTENDEE_TYPES[i];
  		}
  	}
  	return null;
  };
  
  MeetingConstants.copyUserAsAttendee = function (user) {
  	return {
  		_id: user._id,
  		type: user.aType || user.type,
  		displayname: user.displayname,
  		picture_url: user.picture_url,
  		username: user.username
  	};
  };
  
  MeetingConstants.INVITE_CHANNEL_TYPES = {
  	SERVER: 'server',
  	CLIENT: 'client'
  };
  
  MeetingConstants.API = {
  	//userRooms: 'api/users/{userid}/meetings/',
  	//privateRoom: 'api/chat/directroom/{userid}/',
  	TOPIC_URL: '/api/topics/{topicid}/',
  	TOPIC_JOIN_URL: '/api/topics/:topicid/join',
  	TOPIC_INVITES_URL: '/api/topics/{topicid}/invites/',
  	TOPIC_INVITE_URL: '/api/topics/invites/{inviteid}',
  	TOPIC_INVITE_JOIN_URL: '/api/topics/invites/{inviteid}/join',
  	TOPIC_QUITE_URL: '/api/topics/{topicid}/quit/',
  
  	TOPICS_URL: '/api/topics/',
  	TOPICS_INVITE_URL: '/api/topics/invite/',
  	GET_MESSAGE_BY_ID_URL: '/api/messages/{id}',
  
  	roomByUniqueName: '/api/meetings/uniquename/{unique_name}',
  	chatServers: '/api/chat/servers/',
  	mailSend: '/api/1.0/email_service/send/'
  };
  
  MeetingConstants.ACTIONS = (0, _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror2['default'])({
  	ROOM_LOADED: null,
  	LOAD_TOPIC_MESSAGES_STREAM: null
  });
  
  MeetingConstants.AUDIO_NOTIFICATION_TYPES = {
  	NEW_CHAT: 'new_chat'
  };
  
  MeetingConstants.ROOM_TYPES = {
  	'SE_ROOM_DIRECT': 'direct',
  	'SE_ROOM_GROUP': 'group'
  };
  
  MeetingConstants.generateUUID = function () {
  	var d = new Date().getTime();
  	var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
  		var r = (d + Math.random() * 16) % 16 | 0;
  		d = Math.floor(d / 16);
  		return (c == 'x' ? r : r & 0x7 | 0x8).toString(16);
  	});
  	return uuid;
  };
  
  MeetingConstants.isMobileBrowser = function () {
  	var func = ns + '[isMobileBrowser]';
  	var bIsMobile = false;
  	try {
  		if (/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)) {
  			bIsMobile = true;
  			_ZSLogger2['default'].error(ns, 'this is is MOBILE APP');
  		}
  		if ($(window).width() < 760) {
  			bIsMobile = true;
  			//          Log.error(ns, 'SMALL Screen < 760px is DETECTED');
  		} else {
  				//          Log.error(ns, 'Large Screen > 760px is DETECTED');
  			}
  	} catch (e) {
  		_ZSLogger2['default'].error(func, e);
  	}
  	return bIsMobile;
  };
  
  MeetingConstants.isUserRoomAdmin = function (room, userid) {
  	var func = ns + "[isUserRoomAdmin] ";
  	try {
  		for (var i in room.parties) {
  			if (room.parties[i].userid == userid && room.parties[i].party_type == CHAT_CONSTS.ROOM_PARTY_TYPES.SE_ROOM_PARTICIPANT_ADMIN) {
  				return true;
  			}
  		}
  	} catch (e) {
  		_ZSLogger2['default'].error(func, e);
  	}
  	return false;
  };
  
  MeetingConstants.isUserMemberOfRoom = function (room, userid) {
  	var func = ns + "[isUserMemberOfRoom] ";
  	try {
  		for (var i in room.parties) {
  			if (room.parties[i].userid == userid) {
  				return true;
  			}
  		}
  	} catch (e) {
  		_ZSLogger2['default'].error(func, e);
  	}
  	return false;
  };
  
  MeetingConstants.getUserTopicRole = function (topic, user) {
  	var func = ns + "[getUserTopicRole] ";
  	var role = MeetingConstants.ATTENDEE_TYPES.GUEST.type;
  	//Log.log(func, 'topic', topic, 'user', user);
  	if (topic.members) {
  		for (var i in topic.members) {
  			if ((topic.members[i].member == user._id || topic.members[i].member == user.member) && topic.members[i].memberType == 'userId') {
  				role = topic.members[i].role;
  			}
  		}
  	}
  	return role;
  };
  
  exports['default'] = MeetingConstants;
  module.exports = exports['default'];

/***/ },
/* 40 */
/***/ function(module, exports) {

  //extend Date object //added by Ray 2016/03/10
  "use strict";
  
  Date.prototype.addDays = function (days) {
  	var dat = new Date(this.valueOf());
  	dat.setDate(dat.getDate() + days);
  	return dat;
  };
  
  Date.prototype.addHours = function (h) {
  	this.setTime(this.getTime() + h * 60 * 60 * 1000);
  	return this;
  };
  
  Date.prototype.addMinutes = function (m) {
  	this.setTime(this.getTime() + m * 60 * 1000);
  	return this;
  };

/***/ },
/* 41 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Copyright 2013-2015, Facebook, Inc.
   * All rights reserved.
   *
   * This source code is licensed under the BSD-style license found in the
   * LICENSE file in the root directory of this source tree. An additional grant
   * of patent rights can be found in the PATENTS file in the same directory.
   *
   * @providesModule keyMirror
   * @typechecks static-only
   */
  
  'use strict';
  
  var invariant = __webpack_require__(153);
  
  /**
   * Constructs an enumeration with keys equal to their value.
   *
   * For example:
   *
   *   var COLORS = keyMirror({blue: null, red: null});
   *   var myColor = COLORS.blue;
   *   var isColorValid = !!COLORS[myColor];
   *
   * The last line could not be performed if the values of the generated enum were
   * not equal to their keys.
   *
   *   Input:  {key1: val1, key2: val2}
   *   Output: {key1: key1, key2: key2}
   *
   * @param {object} obj
   * @return {object}
   */
  var keyMirror = function (obj) {
    var ret = {};
    var key;
    !(obj instanceof Object && !Array.isArray(obj)) ? process.env.NODE_ENV !== 'production' ? invariant(false, 'keyMirror(...): Argument must be an object.') : invariant(false) : undefined;
    for (key in obj) {
      if (!obj.hasOwnProperty(key)) {
        continue;
      }
      ret[key] = key;
    }
    return ret;
  };
  
  module.exports = keyMirror;

/***/ },
/* 42 */
/***/ function(module, exports) {

  module.exports = require("escape-string-regexp");

/***/ },
/* 43 */
/***/ function(module, exports) {

  module.exports = require("fs");

/***/ },
/* 44 */
/***/ function(module, exports) {

  module.exports = require("gcloud/lib/storage");

/***/ },
/* 45 */
/***/ function(module, exports) {

  module.exports = require("querystring");

/***/ },
/* 46 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5),
      Schema = mongoose.Schema;
  
  var TopicUserSchema = new Schema({
      userId: { type: Schema.Types.ObjectId }, //The user id
      userType: String,
      targetId: { type: Schema.Types.ObjectId },
      targetType: String,
      title: String,
      lastAccess: Date,
      role: String,
      meta: Schema.Types.Mixed
  });
  
  /**
   * Virtuals
   */
  
  //tags: [String]
  TopicUserSchema.set('toJSON', {
      virtuals: true
  });
  
  TopicUserSchema.index({ userId: 1, targetId: 1, userType: 1 }, { unique: true });
  TopicUserSchema.index({ userId: 1, userType: 1 });
  TopicUserSchema.options.toJSON = {
  
      transform: function transform(doc, ret, options) {
          delete ret.__v;
          delete ret.id;
          return ret;
      },
      virtuals: true,
      minimize: true
  };
  
  module.exports = mongoose.model('TopicUser', TopicUserSchema);

/***/ },
/* 47 */
/***/ function(module, exports, __webpack_require__) {

  /*! React Starter Kit | MIT License | http://www.reactstarterkit.com/ */
  
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _react = __webpack_require__(90);
  
  var _react2 = _interopRequireDefault(_react);
  
  var _counterpart = __webpack_require__(170);
  
  var _counterpart2 = _interopRequireDefault(_counterpart);
  
  var _reactTranslateComponent = __webpack_require__(189);
  
  var _reactTranslateComponent2 = _interopRequireDefault(_reactTranslateComponent);
  
  var Translation = {
    language: null,
    Component: _reactTranslateComponent2['default'],
    bind: function bind(key) {
      "use strict";
      var self = this;
      if (!self.language) {
        this.setLanguage('en');
      }
      return self.language.messages[key] ? { __html: self.language.messages[key] } : { __html: key };
    },
    get: function get(key) {
      "use strict";
      var self = this;
      if (!self.language) {
        this.setLanguage('en');
      }
      return self.language.messages[key] ? self.language.messages[key] : key;
    },
    initLanguage: function initLanguage(navigator) {
      "use strict";
      //let lang = navigator.language.indexOf("-") > -1 ? navigator.language.split("-")[0] : navigator.language;
  
      var lang = navigator.language;
      lang = lang.indexOf("en") > -1 ? "en" : lang;
      this.setLanguage(lang);
    },
    setLanguage: function setLanguage(lang) {
      "use strict";
      var file = undefined;
      try {
        file = __webpack_require__(155)("./" + lang);
      } catch (e) {
  
        file = __webpack_require__(53);
        lang = "en";
      }
      file.locale = lang;
      this.language = file;
      _counterpart2['default'].registerTranslations(lang, this.language);
      _counterpart2['default'].setLocale(lang);
    }
  };
  
  exports['default'] = Translation;
  module.exports = exports['default'];

/***/ },
/* 48 */
/***/ function(module, exports, __webpack_require__) {

  //Currently we use redis as memcache backend
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _redis = __webpack_require__(63);
  
  var _redis2 = _interopRequireDefault(_redis);
  
  var _configEnvEnvironmentIndex = __webpack_require__(27);
  
  var _configEnvEnvironmentIndex2 = _interopRequireDefault(_configEnvEnvironmentIndex);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var redisMemcahe = null;
  function initRedisMemcahe() {
    console.log('initRedisMemcahe begin');
    var tempRedisMemcahe = _redis2['default'].createClient(_configEnvEnvironmentIndex2['default'].redis.port, _configEnvEnvironmentIndex2['default'].redis.host, { tls: _configEnvEnvironmentIndex2['default'].redis.ssl,
      auth_pass: _configEnvEnvironmentIndex2['default'].redis.auth,
      retry_strategy: function retry_strategy(options) {
        if (options.error.code === 'ECONNREFUSED') {
          // End reconnecting on a specific error and flush all commands with a individual error
          return new Error('The server refused the connection');
        }
        if (options.total_retry_time > 1000 * 60 * 60) {
          // End reconnecting after a specific timeout and flush all commands with a individual error
          return new Error('Retry time exhausted');
        }
        if (options.times_connected > 10) {
          // End reconnecting with built in error
          return undefined;
        }
        // reconnect after
        return Math.max(options.attempt * 100, 3000);
      }
    });
    tempRedisMemcahe.on('ready', function () {
      redisMemcahe = tempRedisMemcahe;
      console.log('initRedisMemcahe ready now');
    });
    tempRedisMemcahe.on('error', function (err) {
      console.log('Happen connection error', err);
      redisMemcahe = null;
    });
    tempRedisMemcahe.on('reconnecting', function (err) {
      console.log('Redis is reconnecting ...');
    });
  }
  setTimeout(initRedisMemcahe, 0);
  
  exports.add = function (src, key, val, timeout, cb) {
    if (redisMemcahe) {
      redisMemcahe.set(key, val, 'NX', 'EX', timeout, function (err, reply) {
        if (err) {
          _modulesLogger2['default'].warn(src.id, 'Memcahe add happen error' + err.toString());
          return cb(err);
        } else {
          if (reply == 'OK') {
            return cb(null, true);
          } else {
            return cb(null, false);
          }
        }
      });
    } else {
      cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MemcacheNotReady));
    }
  };
  
  exports.set = function (src, key, val, timeout, cb) {
    if (redisMemcahe) {
      redisMemcahe.set(key, val, 'EX', timeout, function (err, reply) {
        if (err) {
          _modulesLogger2['default'].warn(src.id, 'Memcahe add happen error' + err.toString());
          return cb(err);
        } else {
          if (reply == 'OK') {
            return cb(null, true);
          } else {
            return cb(null, false);
          }
        }
      });
    } else {
      cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MemcacheNotReady));
    }
  };
  
  exports.get = function (src, key, cb) {
    if (redisMemcahe) {
      redisMemcahe.get(key, function (err, reply) {
        if (err) {
          _modulesLogger2['default'].warn(src.id, 'Memcahe get happen error' + err.toString());
          return cb(err);
        } else {
          return cb(null, reply);
        }
      });
    } else {
      cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MemcacheNotReady));
    }
  };
  
  exports.del = function (src, key, cb) {
    if (redisMemcahe) {
      redisMemcahe.del(key, function (err, reply) {
        if (err) {
          _modulesLogger2['default'].warn(src.id, 'Memcahe del happen error' + err.toString());
          if (cb) {
            return cb(err);
          }
        } else {
          if (reply == 0) {
            if (cb) {
              return cb(null, false);
            }
          } else {
            if (cb) {
              return cb(null, true);
            }
          }
        }
      });
    } else {
      cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MemcacheNotReady));
    }
  };

/***/ },
/* 49 */
/***/ function(module, exports) {

  module.exports = require("ZSLogger");

/***/ },
/* 50 */
/***/ function(module, exports) {

  module.exports = require("node-uuid");

/***/ },
/* 51 */
/***/ function(module, exports) {

  module.exports = require("os");

/***/ },
/* 52 */
/***/ function(module, exports) {

  module.exports = require("pmx");

/***/ },
/* 53 */
/***/ function(module, exports) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  var logan_en = {
    messages: {
      MEET_ME: 'Project Logan®',
      KEY_IN_YOUR_TOPIC: 'Key in your topic',
      START_MEETING: 'Start Meeting',
      INVITE_PARTICIPANTS: 'Invite Participants',
      SHARE: 'Share',
      MICROPHONE: 'Microphone',
      CAMERA: 'Camera',
      DEVICE: 'Device',
      REALDEVICE: 'Real Device',
      FAKEDEVICE: 'Fake Device',
      SCREEN: 'Screen',
      APPLICATION: 'Application',
      WINDOW: 'Window',
      NEXT_PAGE: 'Next page',
      ZOOM_IN: 'Zoom in',
      REMOVE: 'Remove',
      WRITE_YOUR_COMMENT_HERE: 'Write your comment here',
      CREATING_THUMBNAILS: 'Creating thumbnails',
      ZOOM_OUT: 'Zoom out',
      FILE_CONVERSION_IN_PROGRESS: 'File conversion in progress',
      UPLOADING_FILES: 'Uploading files',
      CLICK_TO_EDIT_THE_DESCRIPTION: 'Click here to edit the description',
      ROTATE: 'Rotate',
      PEOPLE: 'people',
      PERSON: 'person',
      NO_MORE_MEMBERS: 'No more members',
      MUTE_THIS_PARTICIPANT: 'Mute this participant',
      YOU: 'You',
      CLICK_TO_EDIT: 'Click to edit',
      CLICK_TO_ATTACH_MORE_FILES: 'Click to attach more files',
      PREVIOUS_PAGE: 'Previous page',
      PREPARING_PREVIEW: 'preparing preview...',
      PREVIEW_NOT_READY: 'preview not yet ready ...',
      NO_PREVIEW_AVAILABLE: 'No preview available',
      FAILED_TO_CREATE_PREVIEW: 'Sorry, there was a problem previewing this file',
      MEETME_INVITATION_SUBJECT: 'Video Chat Invite: {0}',
      MEETME_INVITATION_BODY: 'Hi There,<br/>{0} is inviting you to join a Video Chat<br/><br/>Click the following link…<br/>{1}<br/><br/><br/> ** Created using  Project Logan @ OnEsna®',
      MEETING_TOPIC_CANNOT_BE_BLANK: 'Don\'t forget to key in the topic!',
      INVITATION_SENT_SUCCESSFULLY: 'A video chat invitation is sent to all parties.',
      VIDEO_CALL_IS_ABOUT_TO_END: 'This video session is about to end.', // (<B>{0}</B>)
      STAY_CONNECTED: 'Stay Connected',
      NO_PARTIES_ADDED: 'No Parties Added!',
      PLEASE_INVITE_OTHER_TO_JOIN: 'Please invite others to join.',
      INVITE_PEOPLE: 'Invite People',
      YOUR_RECENT_MEETINGS: 'Your Recent Meetings',
      MEETING_PARTIES: 'Meeting Parties',
      ENTER_YOUR_NAME: 'Enter your name',
      ENTER_YOUR_EMAIL: 'Enter your email',
      ADD_MORE: 'Add more',
      CLICK_TO_ADD_FILES: 'Click to add files',
      EMAIL: 'Email',
      NAME: 'Name',
      TODAY: 'Today',
      YESTERDAY: 'Yesterday',
      DAYS: 'days',
      AGO: 'ago',
      TOMORROW: 'Tomorrow',
      CLICK_TO_ENLARGE_MOUSE_WHEEL_TO_ZOOM: 'Click to enlarge, mouse wheel to zoom',
      NO_NAME: 'NO NAME',
      WANT_TO_CREATE_A_NEW_SPACE: 'Want to create a new space?',
      NO_PROBLEM_REQUEST_PERMISSION_FROM_ONE_OF_OUR_ADMINISTRATORS_HERE: 'No problem! Request permission from one of our administrators',
      HERE: 'here',
      NO_PROBLEM_TYPE_YOUR_NAME_AND_YOUR_EMAIL_HIT_SUBMIT_AND_SOON_A_ZANG_SPACES_ADMINISTRATOR_WILL_APPROVE_YOUR_REQUEST: 'No problem! Type your name and your email, hit "Submit Request" and soon you will receive an email by a Zang Spaces administrator who will approve your request',
      JOIN_MEETING: 'Join Meeting',
      EXPAND_COMMENTS: 'Expand comments',
      COLLAPSE_COMMENTS: 'Collapse comments',
      NAME_IS_REQUIRED: 'Don\'t forget to proivde your name',
      PICTURE_IS_REQUIRED: 'Please provide a photo snapshot!',
      THIS_ROOM_IS_NOT_OPEN_TO_PUBLIC: 'This room is not open to public',
      ACCESS_DENIED: 'Access Denied!',
      MEETING_HISTORY: 'Meeting History',
      IDEA_BOARD: 'Posts',
      MEMBERS: 'Members',
      STICKY_DOCS: 'Sticky Docs',
      WORK_SPACE: 'Work Space',
      SUBMIT: 'Submit',
      SUBMIT_REQUEST: 'Submit request',
      TO_DO: 'To-Do',
      YES: 'Yes',
      TASK_TITLE: 'Task Title',
      TASK_DESCRIPTION: 'Task Description',
      TASK_DUE_DATE: 'Task Due Date',
      DUE: 'Due',
      TASK_ASSIGN_TO: 'Assign To',
      ASSIGN: 'Assign',
      PLEASE_PROVIDE_A_TITLE_FOR_THIS_TASK: 'Please provide a title for this task',
      ATTENDEES: 'Attendees',
      REPLY: 'reply',
      CONNECTING_TO_VIDEO_CONFERENCE: 'Connecting to Video Conference',
      WAITING_FOR_OTHER_PARTIES_TO_JOIN: 'Waiting for other parties to join...',
      TASK: 'Task',
      DRAG_AND_DROP_IMAGES_OR_PDF_TO_UPLOAD: 'Drag Images or PDF files to upload',
      SHARE_YOUR_IDEA: 'Drag files or images here and share your post',
      POSTED_AN_IDEA: 'Created A Post',
      MUTE_AUDIO: 'Mute Audio',
      UNMUTE_AUDIO: 'Unmute Audio',
      THIS_REQUEST_IS_ALREADY_APPROVED_ARE_YOU_SURE_YOU_WANT_TO_DISAPPROVE_IT: 'This request is already approved. Are you sure you want to disapprove it?',
      THIS_REQUEST_IS_ALREADY_APPROVED: 'This request is already approved',
      HANGUP: 'Hangup',
      RECENT_TOPICS: 'Recent Topics',
      TRENDING_TOPICS: 'Trending Meetings',
      START_A_MEETING: 'Start A Meeting',
      NEW_IDEA_SHARED: 'New Post Shared',
      SHARE_SCREEN: 'Share Screen',
      STOP_SCREEN_SHARING: 'Stop screen sharing',
      VIDEO_SETTINGS: 'Video Settings',
      TEXT_WITH_HTML: "Top<br />Bottom",
      SIGN_IN: 'Sign In',
      USERNAME: 'Username',
      PASSWORD: 'Password',
      LOGIN: 'Login',
      PAGE_NOT_FOUND: "Page Not Found",
      NO: 'No',
      GO_HOME: "Go Home",
      SORRY_VIDEO_CANNOT_BE_PLAYED_WITHIN_THIS_BROWSER: "Sorry, video cannot be played within this browser :(",
      CLICK_TO_DOWNLOAD_AND_INSTALL_CHROME_FOR_THE_BEST_ZANG_SPACES_EXPERIENCE: "Click to download and install Chrome for the best Zang Spaces experience.",
      SORRY_BUT_THE_PAGE_YOU_WERE_TRYING_TO_VIEW_DOES_NOT_EXIST: "Sorry, but the page you were trying to view does not exist.",
      SEND_A_MESSAGE: 'Send a Message',
      JOIN_AS_GUEST: 'Join as Guest',
      CREATE_AN_ACCOUNT: 'Create account',
      OR_LOGIN_WITH: 'or login with',
      OR_JOIN_WITH: 'or join with',
      JOIN_WITH: 'Join with',
      JOIN_THIS_SPACE_WITH: 'Join this space with',
      OR_JOIN_THIS_SPACE_WITH: 'or join this space with',
      GOGGLE_PLUS: 'Google+',
      OFFICE_365: 'Office 365',
      SALESFORCE: 'Salesforce',
      ONESNA: 'OnEsna',
      DOWNLOAD: 'Download',
      SHOW_ADVANCED_OPTIONS: 'Show Advanced Options',
      MEMBER: 'Member',
      MEMBER_SPACES: 'Member Spaces',
      GUEST: 'Guest',
      GUEST_SPACES: 'Guest Spaces',
      GROUPS: 'Groups',
      ALL_SPACES: 'All Spaces',
      DIRECT_SPACES: 'Direct Spaces',
      GUEST_ONETIME: 'One Time Guest',
      ADMIN: 'Admin',
      INVALID_EMAIL_FORMAT: 'Invalid Email Address!',
      PLEASE_ENTER_VALID_EMAIL: 'Please enter a valid email.',
      DISPLAYNAME_CANNOT_BE_BLANK: 'Displayname cannot be blank!',
      USER_PHOTO_IS_REQUIRED: 'User photo is required!',
      SCHEDULE: 'Schedule',
      POSTED: 'Posted',
      START: 'Start',
      CONNECTION_FAILED_FAILED_TO_CONNECT_TO_SERVER_ERROR_PLACEHOLDER: 'Connection Failed.Failed to connect to server.Error: {code} {reason}',
      SERVER_CONNECTION_FAILED: 'Server connection failed',
      AUDIO_DEVICE_FAILURE_COULD_NOT_GET_ACCESS_TO_AUDIO_DEVICE: 'Audio Device Failure.Could not get access to audio device',
      CONNECTING_TO_TOPIC: 'Connecting to ',
      CALL_TERMINATED: 'Call terminated ',
      CALL_FAILED: 'Call failed ',
      CONNECTED_TO_TOPIC: 'Connected to topic ',
      LEAVE_VIDEO_SESSION: 'Leave video session',
      REENTER_VIDEO_SESSION: 'Re-enter video session',
      PENDING: 'Pending',
      COMPLETED: 'Completed',
      APPROVED: 'Approved',
      AWAITING: 'Awaiting',
      REJECTED: 'Rejected',
      TESTING: 'Testing',
      COMMENTS: 'Comments',
      HISTORY: 'History',
      SAVE_CHANGE: 'Save Changes',
      SAVE: 'Save',
      ENROLLMENT_REQUEST: 'Enrollment request',
      CLOSE: 'Close',
      TASK_TITLE_CANNOT_BE_BLANK: 'Task title cannot be blank!',
      LEAVE_COMMENT: 'Drag files or images here or leave a comment',
      LEAVE_TOPIC: 'Leave Topic',
      JOIN_TOPIC: 'Join Topic',
      DISCONNECTED: 'Disconnected',
      CREATE_NEW_TASK: 'New Task',
      MY_TASKS: 'My Tasks',
      EVERYONE_TASKS: 'Everyone Tasks',
      NETWORK_CONNECTION: 'Network connection',
      YOUR_NETWORK_CONNECTION_IS_LOST: 'Your network connection is lost',
      YOUR_NETWORK_CONNECTION_IS_NOW_RESTORED: 'Your network connection is now restored',
      STILL_NO_NETWORK_CONNECTION: 'Still no network connection',
      MEDIA_ERROR: 'Media error',
      IT_SEEMS_THAT_YOU_DONT_HAVE_A_CAMERA_AND_A_MICROPHONE_ON_YOUR_DEVICE: 'It seems that you don\'t have a camera and a microphone on your device',
      VIDEO_ENABLED: 'Video enabled',
      VIDEO_DISABLED: 'Video disabled',
      CREATED_BY: 'Created by',
      AUDIO_ENABLED: 'Audio enabled',
      AUDIO_DISABLED: 'Audio disabled',
      COMMENTED_ON: 'left a comment on',
      SHARED_AN_IDEA: 'shared a post',
      ASSIGNED_A_TASK: 'assigned a task',
      CREATED_A_TASK: 'created a task',
      SHARED_AN_IMAGE: 'shared an image',
      SHARED_A_VIDEO: 'shared a video',
      SHARED_A_LINK: 'shared a link',
      SHARED_NEW_IMAGES: 'shared new images',
      TASKS: 'Tasks',
      JOINING_TOPIC: 'Joining topic...',
      CONTRIBUTORS: 'Contributors',
      LOGOUT: "Logout",
      CANCEL: 'Cancel',
      OK: 'OK',
      NO: "No",
      ARE_YOUR_SURE_YOU_WANT_TO_LOGOUT: 'Are you sure your want to logout?',
      NEW_TOPIC: 'New Topic',
      USER_SETTINGS: 'User settings',
      HOME: 'Home',
      DASHBOARD: 'Dashboard',
      START_A_NEW_TOPIC: 'Start New Topic',
      DISABLE_VIDEO: 'Disable Video',
      ENABLE_VIDEO: 'Enable Video',
      CHAT: 'Chat',
      INVITE: 'Invite',
      SEARCH_FOR_PARTICIPANTS: 'Search for participants',
      SEARCH_FOR_TOPICS: 'Search for topics...',
      SEARCH: 'Search...',
      SHARE_AN_IDEA: 'Share A Post',
      START_VIDEO: 'Start Video',
      STOP_VIDEO: 'Stop Video',
      INVITING: 'Inviting',
      GUEST_TAKE_YOUR_PICTURE_AND_TYPE_YOUR_NAME: 'Guest, take a picture and type your name',
      TAKE_A_PHOTO_AND_TYPE_IN_YOUR_NAME_TO_JOIN_AS_A_GUEST: 'Take a photo and type in your name to join as guest',
      TYPE_IN_YOUR_NAME_TO_JOIN_AS_A_GUEST: 'Type in your name to join as guest',
      JOIN_THE_TOPIC: 'Join the topic',
      NAME_CANNOT_BE_BLANK: 'Name cannot be blank',
      VIDEO_SERVER_CONNECTION_FAILED: 'Video server connection failed. Please call back',
      THERE_WAS_AN_ERROR_WITH_YOUR_MEDIA_CONNECTION_PLEASE_JOIN_AGAIN: 'There was an error with your connection. Please join again',
      CONNECTING: 'Connecting',
      YOUR_ARE_NOT_CONNECTED_OR_YOUR_SESSION_HAS_EXPIRED_REDIRECTING_TO_LOGIN_PAGE: 'You are not connected or your session has expired. Redirecting to login page',
      ADD_COMMENT: 'Add Comment',
      ACTIVITY: 'Activity',
      SAVE_COMMENT: 'Save Comment',
      WRITE_A_COMMENT: 'Write a comment...',
      ANONYMOUS: 'Anonymous',
      SAVING: 'Saving...',
      INCLUDE_ALL_MEMBERS: 'Include all members',
      COPY_TOPIC_LINK: 'Copy link',
      COPIED_TO_CLIPBOARD: 'Copied to clipboard',
      CREATE_A_TOPIC: 'Create a topic',
      LETS_GET_STARTED: 'Let\'s get started!',
      THIS_MAY_TAKE_FEW_SECONDS: 'This may take couple of seconds.',
      TYPE_TO_FIND_PEOPLE: 'Type to find people...',
      CREATE_TOPIC_TIP: 'To create a private or group space, simply name your space and invite friends or colleagues.',
      CHANGE_YOUR_PROFILE_PIC: 'Change your profile picture',
      CHANGE_PICTURE: 'Change Picture',
      PROFILE: 'Profile',
      LICENSES: 'Licenses',
      APPS: 'Apps',
      SETTINGS: 'Settings',
      CHANGE_PASSWORD: 'Change Password',
      I_LIKE_IT: 'I like it!',
      TAKE_A_PICTURE_OF_YOU: 'Take a picture of you',
      UPLOADING_THUMBNAILS: 'Uploading thumbnails...',
      FINISHED_UPLOADING: 'Finished uploading',
      TAKE_A_PICTURE_OF_YOUR_SELF: 'Take a picture of yourself',
      DO_YOU_LIKE_IT: 'Do you like it?',
      TAKE_A_PICTURE: 'Take a picture',
      CHANGING: 'Changing...',
      INSTALL_EXTENSION: 'Install Extension',
      YOU_ARE_SHARING_YOUR_SCREEN: 'You are sharing your screen.',
      YOUR_SCREEN_SHARE_ENDED: 'Your screen share ended!',
      SHARING_SCREEN: 'Sharing Screen',
      OR: 'or',
      READING_FILE: 'Reading file...',
      INCORRECT_FILE_EXTENSION: 'Incorrect file extension',
      ONE_FROM_YOUR_DEVICE: 'one from your device',
      CHOOSE: 'choose',
      SHRINK_VIDEO: 'Shrink Video',
      EXPAND_VIDEO: 'Expand Video',
      FULL_SCREEN: 'Full Screen',
      EXIT_FULL_SCREEN: 'Exit Full Screen',
      ENLARGE_VIDEO: 'Enlarge Video',
      ENLARGE_SCREEN: 'Enlarge SCREEN',
      ENLARGE: 'Enlarge',
      SCREEN_SHARING_IN_PROGRESS: 'Screen sharing in progress.',
      STARTED_SCREEN_SHARE: '({name}) is sharing screen.',
      ENDED_SCREEN_SHARE: '({name}) stopped sharing screen.',
      VIEW: 'View',
      DO_YOU_WANT_TO_OVERRIDE_THEM: 'Do you want to override them?',
      YES: 'Yes',
      NO: 'No',
      PIN: 'Pin',
      DAYS_AGO: 'days ago',
      IN: 'in',
      UN_PIN: 'Un-Pin',
      HANG_UP: 'Hang Up',
      CALL_BACK: 'Call Back',
      COPY_THIS_LINK: 'Copy this link',
      LOAD_COUNT_COMMENTS: 'Load {count} Comments',
      LIKE: 'Like',
      ADD_PEOPLE: 'Add People',
      CLICK_TO_ADD_MEMBERS: 'Click to add members',
      VIDEO_ON: 'Video On',
      VIDEO_OFF: 'Video Off',
      AUDIO_ON: 'Audio On',
      AUDIO_OFF: 'Audio Off',
      ATTENDING_FROM_DESKTOP: 'Attending From Desktop',
      ATTENDING_FROM_MOBILE: 'Attending From Mobile',
      NO_ACTIVE_CALLS: 'No Active Calls',
      JOIN_LIVE_CALL: 'Join Live Call',
      JOIN_START_LIVE_CALL: 'Join/start Live Call',
      SELECT_THE_ABOVE_ICON_TO_JOIN_THE_CURRENT_VIDEO_CALL: 'Click the above icon to join the current video call',
      SELECT_THE_ABOVE_ICON_TO_START_A_THE_VIDEO_CALL: 'Click the above icon to start the video call',
      JOIN_THIS_LIVE_VIDEO_MEETING: 'Join this live video meeting',
      THERE_IS_A_MEETING_GOING_ON_WITHOUT_YOU: 'There\'s a meeting going on without you.',
      SELECT_TO_JOIN_IT_NOW: 'Select to join it now!',
      START_A_VIDEO_CALL: 'Start a video call!',
      NEED_TO_HAVE_A_QUICK_FACE_TO_FACE_WITH_YOUR_TEAM: 'Need to have a quick face-to-face with your team?',
      SELECT_TO_START_A_VIDEO_CALL_NOW: 'Select to start a video call now!',
      NEW_SPACE: 'New Space',
      ACTIVE_SPACES: 'Active spaces',
      NAME_YOUR_NEW_SPACE: 'Name your new space',
      CREATE_A_SPACE: 'Create a space',
      MESSAGES: 'Messages',
      WHITEBOARD: 'Whiteboard',
      ZANG_SPACES: 'Zang Spaces',
      UPLOAD_FILE: 'Upload file',
      RECENT_FILES: 'Recent Files',
      RECENT_POSTS: 'Recent Posts',
      SORRY: 'Sorry',
      CANNOT_BE_UPLOADED_YOUR_FILE_NEEDS_AT_LEAST_1_BYTE_IN_SIZE_PLEASE_TRY_AGAIN: 'cannot be uploaded. Your file needs to be at least 1 bytes in size. Please try again',
      PLEASE_CHOOSE_AN_IMAGE_THAT_HAS_ONE_OF_THE_FOLLOWING_EXTENSTIONS: 'Please choose an image that has one of the following extensions: {extensions}',
      CONNECTING_TO_YOUR_CAMERA: 'Connecting to your camera...',
      SEND: 'Send',
      ATTACH: 'Attach',
      ATTACHMENTS: 'Attachments',
      UNSTABLE_CONNECTION_TRYING_TO_RECONNECT: 'Unstable connection. Trying to reconnect...',
      APPROVE_ENROLLMENT_REQUESTS: 'Approve requests',
      SUBMITTING_REQUEST: 'Submitting request...',
      REQUEST_SENT: 'Request sent',
      REQUEST_ERROR_PLEASE_TRY_AGAIN: 'Request error please try again',
      APPROVE_REQUESTS: 'Approve requests',
      SEARCH_BY_EMAIL: 'Search by email...',
      NEXT: 'Next',
      PREVIOUS: 'Previous',
      OF: 'of',
      APPROVE: 'Approve',
      DELETE: 'Delete',
      REQUESTED_ON: 'Requested on',
      LOADING: 'Loading...',
      APPROVE_OR_DELETE_REQUESTS: 'Approve or delete requests',
      ENROLLMENT_REQUESTS: 'Enrollment requests',
      APPROVING: 'Approving...',
      DISAPPROVE: 'Disapprove',
      WE_HAVE_ALREADY_RECEIVED_A_REQUEST_FOR_THIS_EMAIL_ADDRESS: 'We have already received a request for this email address',
      ENROLL: 'Enroll',
      START_USING_ZANG_SPACES: 'Start using Zang Spaces',
      THERE_WAS_AN_ERROR_SAVING_THIS_PLACEHOLDER_PLEASE_OPEN_IT_AGAIN: 'There was an error updating this {placeholder}. Please open it again',
      FILL_OUT_THE_FORM_BELOW_AND_ONE_OF_OUR_ADMINISTRATORS_WILL_CONTACT_YOU_RE_APPROVED: 'Fill out the form below and one of our administrators <br /> will contact you once you\'re approved.',
      YOUR_REQUEST_WAS_SUBMITTED_SUCCESSFULLY_YOU_WILL_RECEIVE_AN_EMAIL_NOTIFICATION_ONCE_YOU_ARE_APPROVED: 'Your request was submitted successfully! You will receive an email notification once you\'re approved',
      YOUR_ARE_NOT_AUTHORIZED_TO_START_A_NEW_SPACE: 'You are not authorized to start a new space',
      ZANG_ACCOUNT: 'Zang Account',
      SUCCESSFULLY_SAVED: 'Successfully saved',
      THIS_PLACEHOLDER_HAS_ALREADY_BEEN_UPDATED_BY_ANOTHER_MEMBER_PLEASE_COPY_YOUR_WORK_AND_OPEN_THE_PLACEHOLDER_AGAIN: 'This {placeholder} has already been updated by another member. Please copy your work and open the {placeholder} again',
      ZANG: 'Zang',
      JOIN_THE_SPACE: 'Join space',
      JOINING_SPACE: 'Joining space',
      ADD_A_NEW_ENROLL_ADMIN_EMAIL: 'Add a new enroll admin (type an email)',
      ADD_COMMENT: 'Add Comment',
      ENROLLMENT_ADMINS: 'Enrollment admins',
      ADD: 'Add',
      REQUEST_INFORMATION: 'Request information',
      STATUS: 'Status',
      ACTIONS: 'Actions',
      RESET: 'Reset',
      FILTER: 'Filter',
      MANAGE_ALL_REQUESTS: 'Manage all requests',
      AUTO_APPROVE: 'Auto approve',
      ADD_NEW: 'Add new',
      NEW_ENROLLMENT_ADDED_SUCCESSFULLY: 'New enrollment added successfully',
      THERE_IS_ALREADY_AN_ENROLLMENT_WITH_THIS_EMAIL_OR_WITH_A_USER_THAT_USES_THIS_EMAIL: 'There is already an enrollment with this email or with a user that uses this email',
      THIS_REQUEST_HAS_BEEN_DELETED: 'This request has been deleted',
      THE_REQUEST_IS_STILL_WAITING_FOR_APPROVAL: 'The request is still waiting for approval',
      THE_REQUEST_HAS_ALREADY_BEEN_APPROVED_CLICK_HERE_TO_START_USING_ZANG_SPACES: 'The request has already been approved! Click <a href="{url}" target="_blank">here</a> to start using Zang Spaces',
      YOU_VE_BEEN_INVITED_BY: 'You\'ve been invited by',
      TO_JOIN: 'to join',
      CREATE: 'Create',
      IDEA: 'Post',
      ADD_IDEA: 'Add post',
      ADD_TASK: 'Add task',
      SHARE_A_NEW: 'Share a new',
      UPLOAD_IN: 'Upload in',
      SELECT_FILE: 'Select file',
      IDEA_NAME: 'Post name',
      DESCRIPTION: 'Description',
      TASK_NAME: 'Task name',
      DUE_DATE: 'Due date',
      SHARE: 'Share',
      NO_RESULTS_FOUND: 'No results found',
      NO_TASKS_FOUND: 'No tasks found',
      NO_POSTS_FOUND: 'No posts created',
      NO_UPLOADS_FOUND: 'No files been uploaded',
      NO_SPACES_FOUND: 'No spaces found',
      UPLOADING: 'Uploading',
      ASSIGN_TO: 'Assign to',
      SPACE: 'Space',
      STATUS: 'Status',
      SENDING: 'Sending...',
      DROP_FILES_HERE: 'Drop files here!',
      HOLD_SHIFT_TO_UPLOAD_INSTANTLY: 'Hold shift to upload instantly',
      FILE: 'File',
      FILES: 'Files',
      DASHBOARD: 'Dashboard',
      RECENT_UPLOADS: 'Recent Uploads',
      LOADING: 'Loading...',
      THIS_FILE_WILL_NOT_BE_UPLOADED: 'This file will not be uploaded',
      ZERO_BYTES_IN_SIZE_OR_INAPPROPRIATE_FILE_EXTENSION: 'Zero bytes in size or inappropriate extension',
      SHARE_SOMETHING: 'Share something',
      POST_AN_IDEA: 'Create a post',
      POST: 'Post',
      CREATE_A_TASK: 'Create a task',
      PRINT_SCREEN: 'Print Screen'
    }
  
  };
  
  exports['default'] = logan_en;
  module.exports = exports['default'];

/***/ },
/* 54 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _modulesFile = __webpack_require__(28);
  
  var _modulesFile2 = _interopRequireDefault(_modulesFile);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _nodeUuid = __webpack_require__(50);
  
  var _nodeUuid2 = _interopRequireDefault(_nodeUuid);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _anonymousAnonymousModel = __webpack_require__(30);
  
  var _anonymousAnonymousModel2 = _interopRequireDefault(_anonymousAnonymousModel);
  
  var _userUserModel = __webpack_require__(14);
  
  var _userUserModel2 = _interopRequireDefault(_userUserModel);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _utilsUtils = __webpack_require__(86);
  
  var _utilsUtils2 = _interopRequireDefault(_utilsUtils);
  
  var DEFAULT_UPLOAD_URL_DURATION = 10 * 60; //10 min
  var DEFAULT_DOWNLOAD_URL_DURATION = 1 * 60; //1min
  
  function getUploadSignedUrls(src, data, expiration, cb) {
      expiration = expiration || _utilsUtils2['default'].getSecondsFromNow(DEFAULT_UPLOAD_URL_DURATION);
      var processFiles = function processFiles(_x, _x2, _x3, _x4) {
          var _again = true;
  
          _function: while (_again) {
              var index = _x,
                  input = _x2,
                  output = _x3,
                  callback = _x4;
              _again = false;
  
              //console.log('[getUploadSignedUrls] input', input, index);
              if (!input) {
                  return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
              }
              if (index === input.length) {
                  return callback(null, output);
              }
  
              var cur_file = input[index];
              if (cur_file) {
                  cur_file.fileKey = cur_file.fileKey || _nodeUuid2['default'].v4();
                  _modulesFile2['default'].getUploadSignedUrl(src, { file: cur_file }, function (err, url) {
                      if (url) {
                          output.push({
                              fileKey: cur_file.fileKey,
                              url: url
                          });
                          return processFiles(index + 1, input, output, callback);
                      } else {
                          return processFiles(index + 1, input, output, callback);
                      }
                  }, expiration.getTime());
              } else {
                  _x = index + 1;
                  _x2 = input;
                  _x3 = output;
                  _x4 = callback;
                  _again = true;
                  cur_file = undefined;
                  continue _function;
              }
          }
      };
  
      processFiles(0, data.files, [], function (err, result) {
          if (err) {
              return cb(err);
          }
  
          return cb(null, result);
      });
  }
  
  function getDownloadSignedUrls(src, data, expiration, cb) {
      expiration = expiration || _utilsUtils2['default'].getSecondsFromNow(DEFAULT_DOWNLOAD_URL_DURATION);
      var processFiles = function processFiles(_x5, _x6, _x7, _x8) {
          var _again2 = true;
  
          _function2: while (_again2) {
              var index = _x5,
                  input = _x6,
                  output = _x7,
                  callback = _x8;
              _again2 = false;
  
              //console.log('[getDownloadSignedUrls] input', input, index);
              if (!input) {
                  return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
              }
              if (index === input.length) {
                  return callback(null, output);
              }
  
              var cur_file = input[index];
              if (cur_file) {
                  _modulesFile2['default'].getDownloadSignedUrl(src, { key: cur_file }, function (err, url) {
                      if (url) {
                          output.push({
                              fileKey: cur_file,
                              url: url
                          });
                          return processFiles(index + 1, input, output, callback);
                      } else {
                          return processFiles(index + 1, input, output, callback);
                      }
                  }, expiration.getTime());
              } else {
                  _x5 = index + 1;
                  _x6 = input;
                  _x7 = output;
                  _x8 = callback;
                  _again2 = true;
                  cur_file = undefined;
                  continue _function2;
              }
          }
      };
  
      processFiles(0, data.fileKeys, [], function (err, result) {
          if (err) {
              return cb(err);
          }
  
          return cb(null, result);
      });
  }
  
  exports.getUploadUrls = function (src, data, cb) {
      for (var i in data) {
          data[i].fileKey = _nodeUuid2['default'].v4(); //enforce key;
      }
      getUploadSignedUrls(src, data, null, cb);
  };
  
  exports.getUploadSignedUrls = function (src, data, expiration, cb) {
      getUploadSignedUrls(src, data, expiration, cb);
  };
  
  exports.getDownloadUrls = function (src, data, cb) {
      getDownloadSignedUrls(src, data, null, cb);
  };
  
  exports.getDownloadSignedUrls = function (src, data, expiration, cb) {
      getDownloadSignedUrls(src, data, expiration, cb);
  };
  
  exports.getProfileImageUploadUrl = function (src, data, cb) {
      var getPictureFileKey = function getPictureFileKey(user, picture, callback) {
          if (picture.dimension === 'original') {
              _modulesLogger2['default'].info(src.id, 'uploading an original picture');
              picture.fileKey = 'pictures/pfpic' + '_' + user.aType + '_' + _nodeUuid2['default'].v4();
              if (user.aType === 'anonymous') {
                  _utilsDbwrapper2['default'].execute(_anonymousAnonymousModel2['default'], _anonymousAnonymousModel2['default'].findOneAndUpdate, src.id, { _id: user._id }, {
                      $set: {
                          picturefile: picture.fileKey
                      }
                  }, { 'new': true }, function (err, updatedAnonymous) {
                      if (err) {
                          return callback(err);
                      }
                      return callback(null, picture);
                  });
              }
              if (user.aType === 'user') {
                  _utilsDbwrapper2['default'].execute(_userUserModel2['default'], _userUserModel2['default'].findOneAndUpdate, src.id, { _id: user._id }, {
                      $set: {
                          picturefile: picture.fileKey
                      }
                  }, { 'new': true }, function (err, updatedUser) {
                      if (err) {
                          return callback(err);
                      }
                      return callback(null, picture);
                  });
              }
          } else {
              if (!user.picturefile || user.picturefile.indexOf('pictures/') !== 0) {
                  return callback('error');
              }
              _modulesLogger2['default'].info(src.id, 'uploading a thumbnail picture');
              picture.fileKey = user.picturefile + '/' + picture.dimension + '_' + picture.dimension;
              return callback(null, picture);
          }
      };
  
      var processFiles = function processFiles(_x9, _x10, _x11, _x12) {
          var _again3 = true;
  
          _function3: while (_again3) {
              var index = _x9,
                  input = _x10,
                  output = _x11,
                  callback = _x12;
              _again3 = false;
  
              if (!input) {
                  return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
              }
              if (index === input.length) {
                  return callback(null, output);
              }
  
              var cur_file = input[index];
              if (cur_file) {
                  getPictureFileKey(data.user, cur_file, function (err, resultFile) {
                      if (err) {
                          return processFiles(index + 1, input, output, callback);
                      }
                      _modulesFile2['default'].getUploadPublicUrl(src, { file: resultFile }, function (err, url) {
                          if (url) {
                              output.push({
                                  fileKey: resultFile.fileKey,
                                  url: url
                              });
                              return processFiles(index + 1, input, output, callback);
                          } else {
                              return processFiles(index + 1, input, output, callback);
                          }
                      });
                  });
              } else {
                  _x9 = index + 1;
                  _x10 = input;
                  _x11 = output;
                  _x12 = callback;
                  _again3 = true;
                  cur_file = undefined;
                  continue _function3;
              }
          }
      };
  
      processFiles(0, data.files, [], function (err, result) {
          if (err) {
              return cb(err);
          }
  
          return cb(null, result);
      });
  };
  
  exports.getDownloadUrlsPublic = function (src, data, cb) {
      var processFiles = function processFiles(_x13, _x14, _x15, _x16) {
          var _again4 = true;
  
          _function4: while (_again4) {
              var index = _x13,
                  input = _x14,
                  output = _x15,
                  callback = _x16;
              _again4 = false;
  
              if (!input) {
                  return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
              }
              if (index === input.length) {
                  return callback(null, output);
              }
  
              var cur_file = input[index];
              if (cur_file) {
                  _modulesFile2['default'].getDownloadPublicUrl(src, { key: cur_file }, function (err, url) {
                      if (url) {
                          output.push({
                              fileKey: cur_file,
                              url: url
                          });
                          return processFiles(index + 1, input, output, callback);
                      } else {
                          return processFiles(index + 1, input, output, callback);
                      }
                  });
              } else {
                  _x13 = index + 1;
                  _x14 = input;
                  _x15 = output;
                  _x16 = callback;
                  _again4 = true;
                  cur_file = undefined;
                  continue _function4;
              }
          }
      };
  
      processFiles(0, data.fileKeys, [], function (err, result) {
          if (err) {
              return cb(err);
          }
  
          return cb(null, result);
      });
  };

/***/ },
/* 55 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Backend non api functions
   */
  'use strict';
  
  var _ = __webpack_require__(11);
  var Invite = __webpack_require__(111),
      utils = __webpack_require__(40),
      userEvent = __webpack_require__(31),
      userBusiness = __webpack_require__(23);
  
  /**
   * CRUD
   */
  exports.create = function (invite, cb) {
  	Invite.create(invite, function (err, data) {
  		if (err) {
  			return cb(err);
  		}
  
  		if (!data) {
  			return cb('not retrieving created invite');
  		} else {
  			return cb(null, data);
  		}
  	});
  };
  
  /**
   * First Layer
   */
  
  exports.checkList = function (tlist, cb) {
  	var processInvites = function processInvites(index, tl, callback) {
  		if (!tl || tl.constructor !== Array) {
  			return callback('ERROR: No input list');
  		}
  
  		var cur_t = tl[index];
  		if (!cur_t) {
  			return callback(null, tl);
  		}
  
  		if (cur_t.id) {
  			processInvites(index + 1, tl, callback);
  		} else {
  			Invite.create(cur_t, function (err, newInvite) {
  				if (err) {
  					return callback(err);
  				}
  				tl[index] = newInvite;
  				processInvites(index + 1, tl, callback);
  			});
  		}
  	};
  
  	processInvites(0, tlist, function (err, resultList) {
  		if (err) {
  			return cb(err);
  		}
  
  		return cb(null, resultList);
  	});
  };

/***/ },
/* 56 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var util = __webpack_require__(12),
      EventEmitter = process.EventEmitter,
      instance;
  
  function NotifyEvent() {
      EventEmitter.call(this);
  }
  
  util.inherits(NotifyEvent, EventEmitter);
  
  NotifyEvent.prototype.emitUserAccessed = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('notifyUserAccessed');
      this.emit.apply(this, args);
  };
  
  NotifyEvent.prototype.onUserAccessed = function (callback) {
      this.on('notifyUserAccessed', callback);
  };
  
  NotifyEvent.prototype.emitUserJoinInvite = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('notifyUserJoinInvite');
      this.emit.apply(this, args);
  };
  
  NotifyEvent.prototype.onUserJoinInvite = function (callback) {
      this.on('notifyUserJoinInvite', callback);
  };
  
  NotifyEvent.prototype.emitUserCreateTopic = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('notifyUserCreateTopic');
      this.emit.apply(this, args);
  };
  
  NotifyEvent.prototype.onUserCreateTopic = function (callback) {
      this.on('notifyUserCreateTopic', callback);
  };
  
  NotifyEvent.prototype.emitNotifyCreated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('notifyCreated');
      this.emit.apply(this, args);
  };
  
  NotifyEvent.prototype.onNotifyCreated = function (callback) {
      this.on('notifyCreated', callback);
  };
  
  NotifyEvent.prototype.emitNotifyDeleted = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('notifyDeleted');
      this.emit.apply(this, args);
  };
  
  NotifyEvent.prototype.onNotifyDeleted = function (callback) {
      this.on('notifyDeleted', callback);
  };
  
  NotifyEvent.prototype.emitNotifyInvited = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('notifyInvited');
      this.emit.apply(this, args);
  };
  
  NotifyEvent.prototype.onNotifyInvited = function (callback) {
      this.on('notifyInvited', callback);
  };
  
  NotifyEvent.prototype.emitUpdateModifyTime = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('updateModifyTime');
      this.emit.apply(this, args);
  };
  
  NotifyEvent.prototype.onUpdateModifyTime = function (callback) {
      this.on('updateModifyTime', callback);
  };
  
  var exportMe = {
      getInstance: function getInstance() {
          return instance || (instance = new NotifyEvent());
      }
  };
  
  module.exports = exportMe.getInstance();

/***/ },
/* 57 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * author: Eric Ding
   */
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _relationModel = __webpack_require__(71);
  
  var _relationModel2 = _interopRequireDefault(_relationModel);
  
  //import RelRebuildStatus from './relationrebuildstatus.model';
  
  var _modulesMemcache = __webpack_require__(48);
  
  var _modulesMemcache2 = _interopRequireDefault(_modulesMemcache);
  
  var _relationgraphModel = __webpack_require__(72);
  
  var _relationgraphModel2 = _interopRequireDefault(_relationgraphModel);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _taskqueueTaskqueueBackend = __webpack_require__(22);
  
  var _taskqueueTaskqueueBackend2 = _interopRequireDefault(_taskqueueTaskqueueBackend);
  
  var _userUserModel = __webpack_require__(14);
  
  var _userUserModel2 = _interopRequireDefault(_userUserModel);
  
  var _anonymousAnonymousModel = __webpack_require__(30);
  
  var _anonymousAnonymousModel2 = _interopRequireDefault(_anonymousAnonymousModel);
  
  var _userUserEvent = __webpack_require__(31);
  
  var _userUserEvent2 = _interopRequireDefault(_userUserEvent);
  
  var _anonymousAnonymousEvent = __webpack_require__(66);
  
  var _anonymousAnonymousEvent2 = _interopRequireDefault(_anonymousAnonymousEvent);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  exports.addRelations = function (src, data, cb) {
    //Comment out the function
    return cb(null);
    //The input data is array of relationship
    var failedAddedRelations = [];
    _async2['default'].each(data, function (relationItem, interCallback) {
      //relationItem._id = new mongoose.Types.ObjectId();
      _utilsDbwrapper2['default'].execute(_relationModel2['default'], _relationModel2['default'].create, src.id, relationItem, function (err, addedrelationItem) {
        if (err || !addedrelationItem) {
          if (err) {
            _modulesLogger2['default'].warn(src.id, "addRelations with object failed for reason", err);
          }
          _modulesLogger2['default'].warn(src.id, "addRelations with object failed", relationItem);
          failedAddedRelations.push(relationItem);
          interCallback();
        } else {
          //Trigger Event to update initiator or target
          rebuildRelationGraphs(src, addedrelationItem, function (err, result) {
            interCallback();
          });
        }
      });
    }, function () {
      return cb(null, failedAddedRelations);
    });
  };
  
  exports.delRelations = function (src, data, cb) {
    //The input data is array of relationship
    var failedRemovedRelations = [];
    _async2['default'].each(data, function (relationItem, interCallback) {
      _utilsDbwrapper2['default'].execute(_relationModel2['default'], _relationModel2['default'].findOneAndRemove, src.id, { relationdef_id: relationItem.relationdef_id }, function (err, removedItem) {
        if (err || !removedItem) {
          if (err) {
            _modulesLogger2['default'].warn(src.id, "delRelations with object failed for reason", err);
          }
          _modulesLogger2['default'].warn(src.id, "delRelations with object failed", relationItem);
          failedRemovedRelations.push(relationItem);
          interCallback();
        } else {
          //Trigger Event to update initiator or target
          rebuildRelationGraphs(src, addedrelationItem, function (err, result) {
            interCallback();
          });
        }
      });
    }, function () {
      return cb(null, failedRemovedRelations);
    });
  };
  
  exports.deleteTargetObj = function (src, targetObj, targetType, cb) {
    _async2['default'].parallel([function (interCallback) {
      var deleteCondition = { destinationId: targetObj._id,
        destinationType: targetType };
      var remover = _relationgraphModel2['default'].remove(deleteCondition);
      _utilsDbwrapper2['default'].execute(remover, remover.exec, src.id, interCallback);
    }, function (interCallback) {
      var deleteCondition = { $or: [{ target_id: targetObj._id, target_type: targetType }, { initiator_id: targetObj._id, initiator_type: targetType }] };
  
      _utilsDbwrapper2['default'].execute(_relationModel2['default'], remover.remove, src.id, deleteCondition, interCallback);
    }], function (err, results) {
      if (err) {
        _modulesLogger2['default'].error(src.id, "happen some error when remove data about relation and relationGraph", err);
      }
      return interCallback(err, results);
    });
  };
  
  exports.insertUpdateRelationGrph = function (src, relationGraphData, cb) {
    var updateCondition = { destinationId: relationGraphData.destinationId,
      destinationType: relationGraphData.destinationType };
  
    _utilsDbwrapper2['default'].execute(_relationgraphModel2['default'], _relationgraphModel2['default'].update, src.id, updateCondition, savedData, { upsert: true }, cb);
  };
  
  var relationGraphsBuildTypesSet = new Set([_utilsServerConstants2['default'].TypeUser]);
  
  //cst.TypeAnonymous
  var rebuildRelationWaitingTimeInSec = 10;
  
  function emitUserCreatedEvent(src, userid, cb) {
    _async2['default'].waterfall([function (interCallback) {
      _utilsDbwrapper2['default'].execute(_userUserModel2['default'], _userUserModel2['default'].findOne, src.id, { _id: userid }, interCallback);
    }, function (userObj, interCallback) {
      if (userObj) {
        _userUserEvent2['default'].emitUserCreated(src, userObj);
        interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskqueueRetry));
      } else {
        interCallback();
      }
    }], function (err, result) {
      cb(err, result);
    });
  }
  
  function emitAnonymousCreatedEvent(src, anonymousid, cb) {
    _async2['default'].waterfall([function (interCallback) {
      _utilsDbwrapper2['default'].execute(_anonymousAnonymousModel2['default'], _anonymousAnonymousModel2['default'].findOne, src.id, { _id: anonymousid }, interCallback);
    }, function (anonymousObj, interCallback) {
      if (anonymousObj) {
        _anonymousAnonymousEvent2['default'].emitAnonymousCreated(src, anonymousObj);
        interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskqueueRetry));
      } else {
        interCallback();
      }
    }], function (err, result) {
      cb(err, result);
    });
  }
  
  function emitAnonymousCreatedEvent(src, userid, cb) {
    _async2['default'].waterfall([function (interCallback) {
      _utilsDbwrapper2['default'].execute(_userUserModel2['default'], _userUserModel2['default'].findOne, reqid, { id: userid }, interCallback);
    }, function (userObj, interCallback) {
      _anonymousAnonymousEvent2['default'].emitAnonymousCreated(src, userObj);
    }], function (err, result) {
      cb(err, result);
    });
  }
  
  var buildTypesEvtDict = {};
  buildTypesEvtDict[_utilsServerConstants2['default'].TypeUser] = emitUserCreatedEvent;
  //buildTypesEvtDict[cst.TypeAnonymous] = emitAnonymousCreatedEvent;
  
  function rebuildTargetRelationGraphs(src, statusObj, cb) {
    _modulesLogger2['default'].info(src.id, "Begin runing rebuildInitiatorRelationGraphs " + JSON.stringify(statusObj));
    _async2['default'].waterfall([function (interCallback) {
      var memkeyval = 'relrebuildstatus_' + statusObj.destinationId + '_' + statusObj.destinationType;
      _modulesMemcache2['default'].del(src, memkeyval);
      interCallback(null, statusObj);
    }, function (statusObj, interCallback) {
      var qryCondition = { target_id: statusObj.destinationId,
        target_type: statusObj.destinationType };
      var prj = 'relationdef_id initiator_id initiator_type relation_type';
      _utilsDbwrapper2['default'].execute(_relationModel2['default'], _relationModel2['default'].find, src, qryCondition, prj, interCallback);
    }, function (relation_graphs, interCallback) {
      if (relationGraphsBuildTypesSet.has(statusObj.destinationType)) {
        var qryCondition = { destinationId: statusObj.destinationId,
          destinationType: statusObj.destinationType };
        var setVal = { 'relation_graphs': relation_graphs };
        _utilsDbwrapper2['default'].execute(_relationgraphModel2['default'], _relationgraphModel2['default'].update, src.id, qryCondition, setVal, interCallback);
      } else {
        interCallback();
      }
    }, function (updateResult, interCallback) {
      if (updateResult && !updateResult.n) {
        buildTypesEvtDict[statusObj.destinationType](src, statusObj.destinationId, interCallback);
      } else {
        interCallback();
      }
    }], function (err, result) {
      if (err) {
        _modulesLogger2['default'].warn(src.id, "rebuildTargetRelationGraphs happen error", err);
      }
      _modulesLogger2['default'].info(src.id, "End running rebuildInitiatorRelationGraphs");
      if (cb) {
        return cb(err, result);
      }
    });
  }
  
  _taskqueueTaskqueueBackend2['default'].registerDeferHandle('rebuildTargetRelationGraphs', rebuildTargetRelationGraphs);
  
  function rebuildRelationGraphs(src, relation, cb) {
    if (relationGraphsBuildTypesSet.has(relation.target_type)) {
      (function () {
        var statusObj = {
          destinationId: relation.target_id,
          destinationType: relation.target_type
        };
        //dbWp.execute(RelRebuildStatus, RelRebuildStatus.create, src.id, statusObj, (err, addedObj) => {
        var keyVal = 'relrebuildstatus_' + relation.target_type + '_' + relation.target_id;
        //let dataVal = json.stringify(statusObj);
        _modulesMemcache2['default'].add(src, keyVal, '', rebuildRelationWaitingTimeInSec, function (err, result) {
          if (!err && result) {
            _modulesLogger2['default'].info(src.id, "Trigger a task to rebuild Relation Graph after " + rebuildRelationWaitingTimeInSec.toString() + ' seconds', keyVal);
            _taskqueueTaskqueueBackend2['default'].launchDefer(src, 'rebuildTargetRelationGraphs', statusObj, { defferOption: true,
              delay: rebuildRelationWaitingTimeInSec,
              backoff_seconds: 300,
              attempts: 3,
              callback: cb
            });
          } else {
            return cb();
          }
        });
      })();
    }
  }
  
  var SpecialDomainPermConfig = {};
  SpecialDomainPermConfig[_utilsServerConstants2['default'].TypeMessage] = { collectionDB: __webpack_require__(13) };
  
  var getinitiatorInfo = function getinitiatorInfo(src, relType, object, cb) {
    if (relType == _utilsServerConstants2['default'].relationCreator) {
      if (object.creator && object.creator._id && object.creator.aType) {
        cb(null, { initiator_id: object.creator._id, initiator_type: object.creator.aType });
      } else {
        cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotCreatorError));
      }
    } else {
      if (object.parent && object.parent._id && object.parent.aType) {
        cb(null, { initiator_id: object.parent._id, initiator_type: object.parent.aType });
      } else {
        cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotParentError));
      }
    }
  };
  
  var specialDomainHanle = function specialDomainHanle(src, relType, object, objectType, cb) {
    var initiator_id = object;
    if (typeof object === 'object' && object._id) {
      getinitiatorInfo(src, relType, object, cb);
    } else {
      var collectionDB = SpecialDomainPermConfig[objectType].collectionDB;
      if (src._cachedActivityDomains && object + '_' + objectType in src._cachedActivityDomains) {
        var tempCheckObj = src._cachedActivityDomains[object + '_' + objectType];
        return getinitiatorInfo(src, relType, tempCheckObj, cb);
      }
      _utilsDbwrapper2['default'].execute(collectionDB, collectionDB.findOne, src.id, { _id: object }, function (err, resultObj) {
        if (!err && resultObj) {
          if (!src._cachedActivityDomains) {
            src._cachedActivityDomains = {};
          }
          src._cachedActivityDomains[object + '_' + objectType] = resultObj;
          getinitiatorInfo(src, relType, resultObj, cb);
        } else {
          cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
        }
      });
    }
  };
  
  var MaxRecursionDepth = 4;
  exports.hasPerm = function (src, userobj, relType, object, objectType, cb) {
    var recursionDepth = arguments.length <= 6 || arguments[6] === undefined ? 0 : arguments[6];
  
    var initiator_id = object;
    var initiator_type = objectType;
    if (typeof object === 'object' && object._id) {
      initiator_id = object._id.toString();
    }
    if (typeof objectType != 'string') {
      return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NoValidateObjectType));
    }
  
    if (initiator_id == userobj._id && initiator_type == userobj.aType) {
      return cb(null, true);
    }
  
    if (objectType in SpecialDomainPermConfig) {
      specialDomainHanle(src, relType, object, objectType, function (err, result) {
        if (err || !result) {
          return cb(null, false);
        } else {
          recursionDepth += 1;
          if (recursionDepth < MaxRecursionDepth) {
            return exports.hasPerm(src, userobj, relType, result.initiator_id, result.initiator_type, cb, recursionDepth);
          } else {
            return cb(null, false);
          }
        }
      });
    } else {
      if (relType == _utilsServerConstants2['default'].relationCreator) {
        if (initiator_type == userobj.aType && initiator_id.toString() == userobj._id.toString()) {
          return cb(null, true);
        }
      }
  
      var query = {
        initiator_id: initiator_id,
        initiator_type: initiator_type,
        target_id: userobj._id,
        target_type: userobj.aType,
        relation_type: relType
      };
      _utilsDbwrapper2['default'].execute(_relationModel2['default'], _relationModel2['default'].findOne, src.id, query, function (err, result) {
        if (err) {
          return cb(err, false);
        }
        if (!result) {
          return cb(null, false);
        } else {
          return cb(null, true);
        }
      });
    }
  };

/***/ },
/* 58 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5),
      Schema = mongoose.Schema,
      config = __webpack_require__(4);
  
  var TopicInviteSchema = new Schema({
      topicId: { type: Schema.Types.ObjectId, ref: 'Topic' },
      created: { type: Date, 'default': Date.now },
      modified: Date, //UTC
      startDateTime: Date, //UTC time
      endDateTime: Date, //UTC time
      invitees: [{
          invitee: String,
          inviteeType: { type: String, 'enum': ['userId', 'email'] }, //  userId
          role: String, // member, admin, guest,
          _id: false
      }],
      testvali: String
  });
  
  /**
   * Virtuals
   */
  TopicInviteSchema.set('toJSON', {
      virtuals: true
  });
  
  TopicInviteSchema.options.toJSON = {
  
      transform: function transform(doc, ret, options) {
          delete ret.__v;
          delete ret.id;
          return ret;
      },
      virtuals: true
  };
  /**
   * Methods
   */
  TopicInviteSchema.methods = {
      makeInviteUrl: function makeInviteUrl(domain) {
          return config.getLink(domain) + '/spaces/invites/' + this._id + '/join';
      },
      makeTopicUrl: function makeTopicUrl(domain) {
          return config.getLink(domain) + '/spaces/' + this.topicId;
      }
  };
  /**
   * Validate
   */
  
  module.exports = mongoose.model('TopicInvite', TopicInviteSchema);

/***/ },
/* 59 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5),
      Schema = mongoose.Schema;
  
  var OAuthAccessTokensSchema = new Schema({
      accessToken: { type: String },
      clientId: { type: String },
      userId: { type: Schema.Types.ObjectId },
      expires: { type: Date },
      scope: [String]
  });
  
  module.exports = mongoose.model('OAuthAccessTokens', OAuthAccessTokensSchema);

/***/ },
/* 60 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
  	value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror = __webpack_require__(41);
  
  var _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror2 = _interopRequireDefault(_node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror);
  
  var _ZSLogger = __webpack_require__(49);
  
  var _ZSLogger2 = _interopRequireDefault(_ZSLogger);
  
  var ns = '[SocketConstants]';
  
  var SocketConstants = {};
  SocketConstants.EVENT_NAMESPACE = {
  	SUBSCRIBE_CHANNEL: 'SUBSCRIBE_CHANNEL',
  	CHANNEL_SUBSCRIBED: 'CHANNEL_SUBSCRIBED',
  
  	UNSUBSCRIBE_CHANNEL: 'UNSUBSCRIBE_CHANNEL',
  	CHANNEL_UNSUBSCRIBED: 'CHANNEL_UNSUBSCRIBED',
  
  	SEND_GROUP_MESSAGE: 'SEND_GROUP_MESSAGE',
  	GROUP_MESSAGE_SENT: 'GROUP_MESSAGE_SENT',
  	SEND_GROUP_MESSAGE_FAILED: 'SEND_GROUP_MESSAGE_FAILED',
  
  	SEND_DIRECT_MESSAGE: 'SEND_DIRECT_MESSAGE',
  	DIRECT_MESSAGE_SENT: 'DIRECT_MESSAGE_SENT',
  	DIRECT_MESSAGE_SEND_FAILED: 'DIRECT_MESSAGE_SEND_FAILED',
  
  	START_MEDIA_SESSION: 'CREATE_MEDIA_SESSION', //start create a conference session for a topic if not created yet, any consecutive connections will, the session is closed after 10min of inactivities
  	MEDIA_SESSION_RESPONSE: 'MEDIA_SESSION_RESPONSE',
  	SEND_MEDIA_SESSION_EVENTS: 'SEND_MEDIA_SESSION_EVENTS',
  
  	PRESENCE_EVENT_RESPONSE: 'PRESENCE_EVENT_RESPONSE',
  	SEND_PRESENCE_EVENT: 'SEND_PRESENCE_EVENT',
  
  	ON_DISCONNECT: 'disconnect',
  	USER_DISCONNECTED: 'USER_DISCONNECTED',
  	ERROR: 'error',
  	CONNECTION_ERROR: 'connect_error'
  };
  
  SocketConstants.API = {};
  
  SocketConstants.ACTIONS = (0, _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror2['default'])({
  	SOCKET_CONNECT: null,
  	SOCKET_CONNECTED: null,
  	SOCKET_DISCONNECTED: null,
  	SOCKET_CONNECTION_ERROR: null,
  	SOCKET_RECONNECTION_ERROR: null,
  	SOCKET_RECONNECT_FAILED: null,
  	SOCKET_ERROR: null,
  	LOGGED_IN_SUCCESSFULLY: null,
  	GOT_GROUP_TYPING: null,
  	GOT_DIRECT_TYPING: null,
  
  	SEND_INVITE_TO_JOIN: null,
  	GOT_INVITE_TO_JOIN: null,
  
  	SET_MEETING_READ_MESSAGE: null,
  	GOT_MEETING_READ_MESSAGE: null,
  
  	SEND_GROUP_MESSAGE: null,
  	GOT_GROUP_MESSAGE: null,
  
  	START_MEDIA_SESSION: null,
  	MEDIA_SESSION_RESPONSE: null,
  	SEND_MEDIA_SESSION_EVENTS: null,
  
  	PRESENCE_EVENT_RESPONSE: null,
  	SEND_PRESENCE_EVENT: null,
  
  	SEND_DIRECT_MESSAGE: null,
  	GOT_DIRECT_MESSAGE: null,
  
  	SUBSCRIBE_CHANNEL: null,
  	CHANNEL_SUBSCRIBED: null,
  
  	UNSUBSCRIBE_CHANNEL: null,
  	CHANNEL_UNSUBSCRIBED: null,
  
  	USER_ENTERED_MEETING: null
  });
  
  SocketConstants.getRandomArbitrary = function (min, max) {
  	return Math.floor(Math.random() * max + min);
  };
  
  SocketConstants.TOKEN_AUTH_TYPES = {
  	ANONYMOUS: 'anonymous',
  	JWT: 'jwt'
  };
  
  SocketConstants.getChannelName = function (channel) {
  	var func = ns + '[getChannelName]';
  	try {
  		return channel.type + '_' + channel._id;
  	} catch (err) {
  		_ZSLogger2['default'].error(func, err);
  	}
  	return null;
  };
  
  exports['default'] = SocketConstants;
  module.exports = exports['default'];

/***/ },
/* 61 */
/***/ function(module, exports) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
  	value: true
  });
  exports['default'] = {
  	inviteUser: {
  		templateId: '115d773e-88e0-4fcd-8669-a7b2717f491f',
  		inviteContentText: function inviteContentText(data) {
  			return 'Hi, You have been invited to join ' + data.title + ' on Zang Spaces!\nFollow the link to join the meeting:  ' + data.link + '\n Zang Spaces Team';
  		},
  		inviteContentHtml: function inviteContentHtml(data) {
  			return '<html><body><p>Hi, You have been invited to join ' + data.title + ' on Zang Spaces!</p><p>Follow the link to join the meeting: &nbsp;' + data.link + '</p><p>Zang Spaces Team</p></body></html>';
  		},
  		tips: {
  			external: ['With Zang Spaces, you can post and share content with your team and spawn discussions with the <b>Idea Board</b>.', 'You can organize your team and keep them on track by assigning <b>Tasks</b> right from your team space. Don’t worry, Zang Spaces will automatically send reminders when they get near the due date as well!', 'You can view and manage all <b>Tasks</b> assigned to you across multiple teams. Make sure you mark those pending or completed so your team is aware of your progress!', 'You can easily schedule Zang Spaces meetings from <b>Microsoft Outlook</b>? Download the free plugin here!', 'You can quickly drag and drop files to the Chat screen to share them with your team.', 'Keep track of important stuff shared by your teammates by searching for what’s relevant to you in your <b>Group History</b>.', 'You can share your screen or escalate to a video call at any time.', 'Not a webapp fan? Good new! Zang Spaces comes with a <b>mobile companion app</b>. Get it here. '],
  			internal: ['Post and share stuff that inspires you on the <b>Idea Board</b> - cat videos, recipes, vacation selfies, actual work… it’s up to you!', "The <b>Idea Board</b> is sort of like a vision board, except it's even more life-changing...oh and that’s where you can post and share stuff with your team", "Micromanaging is so 2007… so, let Zang Spaces do it for you! Organize your team and keep them on track by assigning them <b>Tasks</b>, also let Zang Spaces do the reminding when something is due.", "Did you know that you can organize your team and keep them on track by assigning <b>Tasks</b> right from your team space? Don’t worry, Zang Spaces will automatically send reminders when they get near the due date as well!", "You can view and manage all <b>Tasks</b> assigned to you across multiple teams! Make sure you mark those pending or completed so your team is aware of your progress.", "Keep track of your <b>Tasks</b> across multiple teams and let people in on a view to what’s being worked on or what you’ve already finished.", "Ever wake up in a cold sweat only to remember that you forgot to do something? Use Zang Spaces to keep track of your <b>Tasks</b> and rest a little easier.", "It official! Zang Spaces and <b>Microsoft Outlook</b> are officially an item - schedule Zang Spaces meetings from Outlook with the free plugin here!", "Schedule Zang Spaces meetings from your <b>Microsoft Outlook</b> calendar with the free plugin! Woah what’s next, hoverboards? Oh wait,...they actually have those?", "Why upload a document or picture when you can drag and drop  those files directly to your Group Chat? The future is now.", "Unlike those “important” notes you write on the back of a napkin, the stuff you share in Zang Spaces is always accessible from the Group  History.", "Keep track of important stuff shared by your teammates by searching for what’s relevant to you in your <b>Group History</b>. You can also easily filter out all of your coworkers’ cat pictures if that’s become a problem in your group...", "With screen sharing and presentation modes, let people actually know what you’re talking about during your next Zang Spaces meeting.", "Make sure you're all set before sharing your screen in Zang Spaces during a video call. We wouldn't want a repeat of what happened last year! ", "Apparently everyone has a smartphone these days and they’re only used for selfies… well how about one more use? Download the mobile version of ‘Zang Spaces’ here.", "Everybody needs a companion, apparently the same is true for software, so do Zang Spaces a favor and pair it with its very own <b>mobile companion app</b> now.", "If you have to, delete some of your cat pictures from your phone, so you have room to download the mobile version of Zang Spaces here.", "Apparently TPS reports are a thing now. Why not keep others up-to-date by storing that file in your Sticky Docs where everyone can see it? High-five for teamwork!"]
  		}
  	},
  	requestControll: {
  		templateId: "dfc2d561-7255-4ae8-bc1f-99186f7c8d93"
  	},
  	requestApproved: {
  		templateId: "d1af090d-b3bc-4670-972f-db2b0e3e67db"
  	}
  };
  module.exports = exports['default'];

/***/ },
/* 62 */
/***/ function(module, exports) {

  /**
   * Created by andreasi on 11/6/2015.
   */
  
  "use strict";
  
  module.exports = {
    $is: function $is(v, objectType) {
      "use strict";
      return Object.prototype.toString.call(v) === "[object " + objectType + "]";
    },
    $array: function $array(v) {
      "use strict";
      return this.$is(v, "Array");
    },
    $object: function $object(v) {
      "use strict";
      return this.$is(v, "Object");
    },
    $function: function $function(v) {
      "use strict";
      return this.$is(v, "Function");
    },
    $number: function $number(v) {
      "use strict";
      return this.$is(v, "Number");
    },
    $boolean: function $boolean(v) {
      "use strict";
      return this.$is(v, "Boolean");
    },
    $string: function $string(v) {
      "use strict";
      return this.$is(v, "String");
    },
    $email: function $email(v) {
      "use strict";
      var re = /^([\w-]+(?:\.[\w-]+)*)@((?:[\w-]+\.)*\w[\w-]{0,66})\.([a-z]{2,6}(?:\.[a-z]{2})?)$/i;
      return re.test(v);
    },
    $url: function $url(v, pureLink) {
      if (pureLink && v && (v.indexOf('http://') > 0 || v.indexOf('https://') > 0) //not pure link, link is within a text content
      ) {
          return false;
        }
      return (/(https?:\/\/(?:www\.|(?!www))[^\s\.]+\.[^\s]{2,}|www\.[^\s]+\.[^\s]{2,})/.test(v)
      );
    },
    $blob: function $blob(v) {
      return v.indexOf('blob:') > -1;
    },
    $firefox: function $firefox() {
      "use strict";
      return navigator.mozGetUserMedia;
    },
    $chrome: function $chrome() {
      "use strict";
      return navigator.webkitGetUserMedia;
    },
    $empty: function $empty(v) {
      return v === undefined || v === "" || this.$array(v) && v.length === 0;
    },
    $imageMime: function $imageMime(mime) {
      if (mime.indexOf('image') >= 0) {
        //return (mime=='image/jpeg' || mime=='image/png');
        return true;
      }
      return false;
    },
    $videoMime: function $videoMime(mime) {
      if (mime.indexOf('video') >= 0) {
        //return (mime=='image/jpeg' || mime=='image/png');
        return true;
      }
      return false;
    }
  };

/***/ },
/* 63 */
/***/ function(module, exports) {

  module.exports = require("redis");

/***/ },
/* 64 */
/***/ function(module, exports) {

  module.exports = require("underscore");

/***/ },
/* 65 */
/***/ function(module, exports) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  var logan_en = {
    messages: {
      MEET_ME: 'Project Logan®',
      KEY_IN_YOUR_TOPIC: 'Key in your topic',
      START_MEETING: 'Start Meeting',
      INVITE_PARTICIPANTS: 'Invite Participants',
      MICROPHONE: 'Microphone',
      CAMERA: 'Camera',
      REALDEVICE: 'Real Device',
      FAKEDEVICE: 'Fake Device',
      SCREEN: 'Screen',
      APPLICATION: 'Application',
      WINDOW: 'Window',
      MEETME_INVITATION_SUBJECT: 'Video Chat Invite: {0}',
      MEETME_INVITATION_BODY: 'Hi There,<br/>{0} is inviting you to join a Video Chat<br/><br/>Click the following link…<br/>{1}<br/><br/><br/> ** Created using  Project Logan @ OnEsna®',
      MEETING_TOPIC_CANNOT_BE_BLANK: 'Don\'t forget to key in the topic!',
      INVITATION_SENT_SUCCESSFULLY: 'A video chat invitation is sent to all parties.',
      NO_PARTIES_ADDED: 'No Parties Added!',
      PLEASE_INVITE_OTHER_TO_JOIN: 'Please invite others to join.',
      YOUR_RECENT_MEETINGS: 'Your Recent Meetings',
      MEETING_PARTIES: 'Meeting Parties',
      ENTER_YOUR_NAME: 'Your Name',
      ENTER_YOUR_EMAIL: 'Your Email',
      JOIN_MEETING: 'Join Meeting',
      NAME_IS_REQUIRED: 'Don\'t forget to proivde your name',
      PICTURE_IS_REQUIRED: 'Please provide a photo snapshot!',
      THIS_ROOM_IS_NOT_OPEN_TO_PUBLIC: 'This room is not open to public',
      ACCESS_DENIED: 'Access Denied!',
      MEETING_HISTORY: 'Ιστορικό συναντήσεων',
      IDEA_BOARD: 'Idea Board',
      MEMBERS: 'Members',
      STICKY_DOCS: 'Sticky Docs',
      WORK_SPACE: 'Work Space',
      TO_DO: 'To-Do',
      TASK_TITLE: 'Task Title',
      TASK_DESCRIPTION: 'Task Description',
      TASK_DUE_DATE: 'Task Due Date',
      TASK_ASSIGN_TO: 'Assign To',
      ASSIGN: 'Assign',
      PLEASE_PROVIDE_A_TITLE_FOR_THIS_TASK: 'Please provide a title for this task',
      ATTENDEES: 'Attendees',
      REPLY: 'reply',
      CONNECTING_TO_VIDEO_CONFERENCE: 'Connecting to Video Conference',
      TASK: 'Task',
      DRAG_AND_DROP_IMAGES_OR_PDF_TO_UPLOAD: 'Drag Images or PDF files to upload',
      SHARE_YOUR_IDEA: 'Share Your Idea',
      POSTED_AN_IDEA: 'Posted An Idea',
      MUTE_AUDIO: 'Mute Audio',
      HANGUP: 'Hangup',
      RECENT_TOPICS: 'Recent Topics',
      TRENDING_TOPICS: 'Trending Meetings',
      START_A_MEETING: 'Start A Meeting',
      NEW_IDEA_SHARED: 'New Idea Shared',
      SHARE_SCREEN: 'Share Screen',
      VIDEO_SETTINGS: 'Video Settings',
      TEXT_WITH_HTML: "Top<br />Bottom"
    }
  
  };
  
  exports['default'] = logan_en;
  module.exports = exports['default'];

/***/ },
/* 66 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var util = __webpack_require__(12),
      EventEmitter = process.EventEmitter,
      instance;
  
  function AnonymousEvent() {
      EventEmitter.call(this);
  }
  
  util.inherits(AnonymousEvent, EventEmitter);
  
  AnonymousEvent.prototype.emitAnonymousUpdated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('anonymousUpdated');
      this.emit.apply(this, args);
  };
  
  AnonymousEvent.prototype.onAnonymousUpdated = function (callback) {
      this.on('anonymousUpdated', callback);
  };
  
  AnonymousEvent.prototype.emitAnonymousCreated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('anonymousCreated');
      this.emit.apply(this, args);
  };
  
  AnonymousEvent.prototype.onAnonymousCreated = function (callback) {
      this.on('anonymousCreated', callback);
  };
  
  AnonymousEvent.prototype.emitAnonymousDeleted = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('anonymousDeleted');
      this.emit.apply(this, args);
  };
  
  AnonymousEvent.prototype.onAnonymousDeleted = function (callback) {
      this.on('anonymousDeleted', callback);
  };
  
  var exportMe = {
      getInstance: function getInstance() {
          return instance || (instance = new AnonymousEvent());
      }
  };
  
  module.exports = exportMe.getInstance();

/***/ },
/* 67 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5),
      Schema = mongoose.Schema;
  
  var CompanySchema = new Schema({
    ndbid: String,
    name: String,
    description: String,
    created: Date,
    lastupdatetime: Date,
    settings: {
      onesna_subdomain: String,
      auth: {
        default_auth_type: Number
      }
    },
    domains: [{
      _id: false,
      domain: String,
      primary: Boolean
    }]
  });
  
  /**
   * Indexes
   */
  CompanySchema.index({ ndbid: 1 });
  
  /**
   * Virtuals
   */
  
  module.exports = mongoose.model('Company', CompanySchema);

/***/ },
/* 68 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var util = __webpack_require__(12),
      EventEmitter = process.EventEmitter,
      instance;
  
  function EnrollEvent() {
      EventEmitter.call(this);
  }
  
  util.inherits(EnrollEvent, EventEmitter);
  
  EnrollEvent.prototype.emitEnrollUpdated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('enrollUpdated');
      this.emit.apply(this, args);
  };
  
  EnrollEvent.prototype.onEnrollUpdated = function (callback) {
      this.on('enrollUpdated', callback);
  };
  
  EnrollEvent.prototype.emitEnrollCreated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('enrollCreated');
      this.emit.apply(this, args);
  };
  
  EnrollEvent.prototype.onEnrollCreated = function (callback) {
      this.on('enrollCreated', callback);
  };
  
  EnrollEvent.prototype.emitEnrollApproved = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('enrollApproved');
      this.emit.apply(this, args);
  };
  
  EnrollEvent.prototype.onEnrollApproved = function (callback) {
      this.on('enrollApproved', callback);
  };
  
  var exportMe = {
      getInstance: function getInstance() {
          return instance || (instance = new EnrollEvent());
      }
  };
  module.exports = exportMe.getInstance();

/***/ },
/* 69 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5),
      Schema = mongoose.Schema;
  
  var EnrollSchema = new Schema({
    name: String,
    email: String,
    status: { type: String, "enum": ['approved', 'awaiting'], 'default': 'awaiting' },
    created: { type: Date, 'default': Date.now },
    modified: { type: Date, 'default': Date.now },
    user: Schema.Types.Mixed
  });
  
  /**
   * Indexes
   */
  // CompanySchema.index({ndbid: 1});
  
  /**
   * Virtuals
   */
  EnrollSchema.index({ email: 1 }, { unique: true });
  
  module.exports = mongoose.model('Enroll', EnrollSchema);

/***/ },
/* 70 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * author: Eric Ding
   */
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  var _notifyEvent = __webpack_require__(56);
  
  var _notifyEvent2 = _interopRequireDefault(_notifyEvent);
  
  var _topicuserModel = __webpack_require__(46);
  
  var _topicuserModel2 = _interopRequireDefault(_topicuserModel);
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var _fluxConstantsMeetingConstants = __webpack_require__(39);
  
  var _fluxConstantsMeetingConstants2 = _interopRequireDefault(_fluxConstantsMeetingConstants);
  
  var _relationRelationBackend = __webpack_require__(57);
  
  var _relationRelationBackend2 = _interopRequireDefault(_relationRelationBackend);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _topicuserBackend = __webpack_require__(119);
  
  var _topicuserBackend2 = _interopRequireDefault(_topicuserBackend);
  
  var UserAccessed = function UserAccessed(src, data, cb) {
    var user = data.user,
        target = data.target,
        time = Date.now();
  
    var getUserRole = function getUserRole(user, topic, callback) {
      var isMember = _lodash2['default'].find(topic.members, { member: user._id.toString() });
      if (isMember) {
        _modulesLoggerIndex2['default'].info(src.id, 'This is already a member/admin ', isMember);
        return callback(isMember.role);
      } else {
        return callback(_fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.GUEST.type);
      }
    };
  
    getUserRole(user, target, function (result) {
      var accessObj = {
        userId: user._id,
        userType: user.aType,
        targetId: target._id,
        lastAccess: time,
        role: result,
        targetType: target.type || _utilsServerConstants2['default'].TypeTopic,
        title: target.title
      };
      //var userTags = util.getTagsByType(user, user.aType);
      //var targetTags = util.getTagsByType(target, accessObj.targetType);
      //accessObj.tags = _.concat(userTags, targetTags);
      return updateTopicUser(src, accessObj, cb);
    });
  };
  
  var UserJoinInvite = function UserJoinInvite(src, data, cb) {
    var user = data.user,
        target = data.target,
        role = data.role;
  
    var accessObj = {
      userId: user._id,
      userType: user.aType,
      targetId: target._id,
      role: role,
      targetType: target.type || _utilsServerConstants2['default'].TypeTopic,
      title: target.title
    };
    //var userTags = util.getTagsByType(user, user.aType);
    //var targetTags = util.getTagsByType(target, accessObj.targetType);
    //accessObj.tags = _.concat(userTags, targetTags);
    return updateTopicUser(src, accessObj, cb);
  };
  
  var UserCreateTopic = function UserCreateTopic(src, data, cb) {
    var user = data.user,
        target = data.target,
        role = data.role;
  
    var accessObj = {
      userId: user._id,
      userType: user.aType,
      targetId: target._id,
      role: role,
      targetType: target.type || _utilsServerConstants2['default'].TypeTopic,
      title: target.title
    };
    //var userTags = util.getTagsByType(user, user.aType);
    //var targetTags = util.getTagsByType(target, accessObj.targetType);
    //accessObj.tags = _.concat(userTags, targetTags);
    return updateTopicUser(src, accessObj, cb);
  };
  
  var updateTopicUser = function updateTopicUser(src, accessObj, cb) {
    _utilsDbwrapper2['default'].execute(_topicuserModel2['default'], _topicuserModel2['default'].findOneAndUpdate, src.id, { userId: accessObj.userId, targetId: accessObj.targetId, userType: accessObj.userType }, accessObj, { upsert: true, 'new': true }, function (err, result) {
      if (err) {
        return cb(err);
      }
      _modulesLoggerIndex2['default'].info(src.id, 'User TopicUserTable updated !', result);
      return cb(null, result);
    });
  };
  
  _notifyEvent2['default'].onUserAccessed(function (src, data) {
    _modulesLoggerIndex2['default'].info(src.id, 'new user access captured !');
    UserAccessed(src, data, function (err, result) {
      if (err) {
        _modulesLoggerIndex2['default'].error(src.id, 'user access capture failed', err);
      }
    });
  });
  
  _notifyEvent2['default'].onUserJoinInvite(function (src, data) {
    _modulesLoggerIndex2['default'].info(src.id, 'user join invite captured !');
    UserJoinInvite(src, data, function (err, result) {
      if (err) {
        _modulesLoggerIndex2['default'].error(src.id, 'user access capture failed', err);
      }
    });
  });
  
  _notifyEvent2['default'].onUserCreateTopic(function (src, data) {
    _modulesLoggerIndex2['default'].info(src.id, 'user create topic captured !');
    UserCreateTopic(src, data, function (err, result) {
      if (err) {
        _modulesLoggerIndex2['default'].error(src.id, 'user access capture failed', err);
      }
    });
  });
  
  //NotifyEvent.onUserJoinInvite(function (src, data) {
  //  logger.info(src.id,'new user join topic captured will add relationship table!');
  //  var user = data.user,
  //  target = data.target,
  //  time = Date.now();
  //  let newRelation = {
  //      target_id: user.id,
  //      target_type: user.aType,
  //      initiator_id: target._id,
  //      initiator_type: cst.TypeTopic,
  //      relation_type: data.role
  //  };
  //  newRelation.relationdef_id = user.aType + '_' + user.id + '_' + cst.TypeTopic + '_'+ target._id + '_' + data.role;
  //  return relationbk.addRelations(src, [newRelation], (err, result) => {
  //    if (result.length > 0){
  //      logger.warn(src.id, 'Add relation about topic failed');
  //    }
  //    else{
  //      logger.info(src.id, 'Add relation about topic ok');
  //    }
  //  }); 
  // 
  //});
  //
  //NotifyEvent.onUserCreateTopic(function (src, data) {
  //  logger.info(src.id,'user create topic captured will add relation table!');
  //  var user = data.user,
  //  target = data.target,
  //  role = data.role;
  //
  //  let newRelation = {
  //      target_id: user.id,
  //      target_type: user.aType,
  //      initiator_id: target.id,
  //      initiator_type: cst.TypeTopic,
  //      relation_type: role
  //  };
  //  newRelation.relationdef_id = user.aType + '_' + user.id + '_' + cst.TypeTopic + '_'+ target.id + '_' + role;
  //  return relationbk.addRelations(src, [newRelation], (err, result) => {
  //    if (result.length > 0){
  //      logger.warn(src.id, 'Add relation about topic failed');
  //    }
  //    else{
  //      logger.info(src.id, 'Add relation about topic ok');
  //    }
  //  });
  //});

/***/ },
/* 71 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * author: Eric Ding
   * This model store all relationship between two two objects
   */
  
  'use strict';
  
  var mongoose = __webpack_require__(5);
  var Schema = mongoose.Schema;
  
  var RelationSchema = new Schema({
    relationdef_id: { type: String, index: { unique: true } },
    target_id: { type: String, index: true },
    target_type: String,
    initiator_id: { type: String, index: true },
    initiator_type: String,
    relation_type: { type: String, index: true },
    created: { type: Date, 'default': Date.now, index: true }
  });
  
  module.exports = mongoose.model('Relation', RelationSchema);

/***/ },
/* 72 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * author: Eric Ding
   *
   */
  
  'use strict';
  
  var mongoose = __webpack_require__(5);
  var Schema = mongoose.Schema;
  
  var RelationGraphSchema = new Schema({
    destinationId: { type: String, index: true },
    destinationType: { type: String, index: true },
    tags: [{ type: String, index: true, lowercase: true }],
    data: {
      username: { type: String },
      displayname: { type: String },
      name: { type: String }
    },
    relation_graphs: [{
      relationdef_id: String,
      initiator_id: String,
      initiator_type: String,
      relation_type: String
    }]
  });
  RelationGraphSchema.index({ destinationId: 1, destinationType: 1 }, { unique: true });
  module.exports = mongoose.model('RelationGraph', RelationGraphSchema);

/***/ },
/* 73 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Backend non api functions
   */
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var _userUserModel = __webpack_require__(14);
  
  var _userUserModel2 = _interopRequireDefault(_userUserModel);
  
  var _topicTopicModel = __webpack_require__(18);
  
  var _topicTopicModel2 = _interopRequireDefault(_topicTopicModel);
  
  var _companyCompanyModel = __webpack_require__(67);
  
  var _companyCompanyModel2 = _interopRequireDefault(_companyCompanyModel);
  
  var _modulesUtils = __webpack_require__(40);
  
  var _modulesUtils2 = _interopRequireDefault(_modulesUtils);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _inviteInviteBackend = __webpack_require__(55);
  
  var _inviteInviteBackend2 = _interopRequireDefault(_inviteInviteBackend);
  
  var _userUserEvent = __webpack_require__(31);
  
  var _userUserEvent2 = _interopRequireDefault(_userUserEvent);
  
  var _companyCompanyEvent = __webpack_require__(95);
  
  var _companyCompanyEvent2 = _interopRequireDefault(_companyCompanyEvent);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _request = __webpack_require__(19);
  
  var _request2 = _interopRequireDefault(_request);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var ObjectId = _mongoose2['default'].Schema.Types.ObjectId;
  // Only test git operation
  
  var syncOneUser = exports.syncOneUser = function (src, data, cb) {
  	var fn = src.fn + '[syncOneUser]';
  	if (data.operate_type === _utilsServerConstants2['default'].SyncOperateDelete) {
  		_utilsDbwrapper2['default'].execute(_userUserModel2['default'], _userUserModel2['default'].findOneAndRemove, src.id, { ndbid: data.id }, function (err, deletedUser) {
  			if (err) {
  				return cb(err);
  			}
  			if (deletedUser) {
  				_modulesLoggerIndex2['default'].sync(src.id, fn + 'user deleted on logan ' + deletedUser._id + ' with ndbid: ' + data.id);
  				_userUserEvent2['default'].emitUserDeleted(src, deletedUser);
  			} else {
  				_modulesLoggerIndex2['default'].sync(src.id, fn + ' user not found on logan with ndbid: ' + data.id);
  			}
  			return cb(null, deletedUser);
  		});
  	} else {
  		_utilsDbwrapper2['default'].execute(_userUserModel2['default'], _userUserModel2['default'].findOne, src.id, { ndbid: data.id }, function (err, user) {
  			if (err) {
  				return cb(err);
  			}
  			if (!user || user.lastupdatetime.getTime() < new Date(data.lastupdatetime).getTime()) {
  				_modulesLoggerIndex2['default'].sync(src.id, fn + 'User needs update');
  				data.ndbid = data.id;
  				data.secret = data.security_token;
  				delete data.id;
  				_utilsDbwrapper2['default'].execute(_userUserModel2['default'], _userUserModel2['default'].findOneAndUpdate, src.id, { ndbid: data.ndbid }, data, { upsert: true, 'new': true }, function (err, newUser) {
  					if (err) {
  						return cb(err);
  					}
  					_modulesLoggerIndex2['default'].sync(src.id, fn + 'new user updated with logan id :' + newUser._id);
  					_modulesLoggerIndex2['default'].sync(src.id, fn + 'this is new User', newUser.toJSON());
  					_userUserEvent2['default'].emitUserUpdated(src, newUser, user);
  					return cb(null, newUser);
  				});
  			} else {
  				_modulesLoggerIndex2['default'].sync(src.id, fn + 'This user is already up to date');
  				return cb(null, user);
  			}
  		});
  	}
  };
  
  var syncOneCompany = exports.syncOneCompany = function (src, data, cb) {
  	var fn = src.fn + '[syncOneCompany]';
  	if (data.operate_type === _utilsServerConstants2['default'].SyncOperateDelete) {
  		_utilsDbwrapper2['default'].execute(_companyCompanyModel2['default'], _companyCompanyModel2['default'].findOneAndRemove, src.id, { ndbid: data.id }, function (err, deletedCompany) {
  			if (err) {
  				return cb(err);
  			}
  			if (deletedCompany) {
  				_modulesLoggerIndex2['default'].sync(src.id, fn + 'company deleted on logan ' + deletedCompany._id + ' with ndbid: ' + data.id);
  				_companyCompanyEvent2['default'].emitCompanyDeleted(src, deletedCompany);
  			} else {
  				_modulesLoggerIndex2['default'].sync(src.id, fn + ' company not found on logan with ndbid: ' + data.id);
  			}
  			return cb(null, deletedCompany);
  		});
  	} else {
  		_utilsDbwrapper2['default'].execute(_companyCompanyModel2['default'], _companyCompanyModel2['default'].findOne, src.id, { ndbid: data.id }, function (err, company) {
  			if (err) {
  				return cb(err);
  			}
  
  			if (!company || company.lastupdatetime.getTime() < new Date(data.lastupdatetime).getTime()) {
  				_modulesLoggerIndex2['default'].sync(src.id, fn + 'Company needs update');
  				data.ndbid = data.id;
  				delete data.id;
  				_utilsDbwrapper2['default'].execute(_companyCompanyModel2['default'], _companyCompanyModel2['default'].findOneAndUpdate, src.id, { ndbid: data.ndbid }, data, { upsert: true, 'new': true }, function (err, newCompany) {
  					if (err) {
  						return cb(err);
  					}
  					_modulesLoggerIndex2['default'].sync(src.id, fn + 'new company updated with logan id :' + newCompany._id);
  					_modulesLoggerIndex2['default'].sync(src.id, fn + 'this is new Company', newCompany.toJSON());
  					_companyCompanyEvent2['default'].emitCompanyUpdated(src, newCompany);
  					return cb(null, newCompany);
  				});
  			} else {
  				_modulesLoggerIndex2['default'].sync(src.id, fn + 'This company is already up to date');
  				return cb(null, company);
  			}
  		});
  	}
  };
  
  exports.syncUsers = function (src, data, cb) {
  	var fn = src.fn + '[syncUsers]';
  	var processUsers = function processUsers(index, ul, resultList, callback) {
  		if (!ul) {
  			return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
  		}
  
  		var cur_user = ul[index];
  		if (!cur_user) {
  			return callback(null, resultList);
  		} else {
  			_modulesLoggerIndex2['default'].sync(src.id, fn + 'processing user number ' + index + ' with user Id: ' + cur_user.id + ' with username: ' + cur_user.username);
  			syncOneUser(src, cur_user, function (err, result) {
  				if (err) {
  					_modulesLoggerIndex2['default'].error(src.id, fn + 'Error sync user number ' + index + ' with user Id: ' + cur_user.id + ' with username: ' + cur_user.username);
  					resultList.push({ id: cur_user.id, index: index, status: 'fail', error: err });
  					return processUsers(index + 1, ul, resultList, callback);
  				} else {
  					resultList.push({ id: cur_user.id, index: index, status: 'success' });
  					return processUsers(index + 1, ul, resultList, callback);
  				}
  			});
  		}
  	};
  
  	processUsers(0, data.users, [], function (err, processResult) {
  		if (err) {
  			_modulesLoggerIndex2['default'].error(src.id, fn + 'Error while syncing users ', err);
  			return cb(err);
  		}
  
  		return cb(null, processResult);
  	});
  };
  //future change
  exports.syncCompanies = function (src, data, cb) {
  	var fn = src.fn + '[syncCompanies]';
  	var processCompanies = function processCompanies(index, ul, resultList, callback) {
  		if (!ul) {
  			return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
  		}
  
  		var cur_company = ul[index];
  		if (!cur_company) {
  			return callback(null, resultList);
  		} else {
  			_modulesLoggerIndex2['default'].sync(src.id, fn + 'processing company number ' + index + ' with company Id: ' + cur_company.id + ' with name: ' + cur_company.name);
  			syncOneCompany(src, cur_company, function (err, result) {
  				if (err) {
  					_modulesLoggerIndex2['default'].error(src.id, fn + 'Error sync company number ' + index + ' with company Id: ' + cur_company.id + ' with name: ' + cur_company.name);
  					resultList.push({ id: cur_company.id, index: index, status: 'fail', error: err });
  					return processCompanies(index + 1, ul, resultList, callback);
  				} else {
  					resultList.push({ id: cur_company.id, index: index, status: 'success' });
  					return processCompanies(index + 1, ul, resultList, callback);
  				}
  			});
  		}
  	};
  
  	processCompanies(0, data.companies, [], function (err, processResult) {
  		if (err) {
  			_modulesLoggerIndex2['default'].error(src.id, fn + 'Error while syncing companies ', err);
  			return cb(err);
  		}
  
  		return cb(null, processResult);
  	});
  };
  
  var getCompanyOnesna = function getCompanyOnesna(src, data, cb) {
  	var fn = src.fn + '[getCompanyOnesna]';
  	var url = _config2['default'].getEsnaLink(src.domain) + '/api/1.0/companies/' + data.companyId + '/logan/';
  	var token = _config2['default'].ESNA_API_KEY;
  	var options = {
  		url: url,
  		headers: {
  			'Authorization': 'API_KEY ' + token
  		},
  		accept: '*/*'
  	};
  	_modulesLoggerIndex2['default'].sync(src.id, fn + 'Access esna grabbing company by url: ' + url);
  	_request2['default'].get(options, function (err, response) {
  		if (err) {
  			_modulesLoggerIndex2['default'].error(src.id, fn + 'from ' + url + ' Wrong response!: ', err.message);
  			return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AccessOnesnaHappenError));
  		}
  		if (response.statusCode !== 200) {
  			_modulesLoggerIndex2['default'].error(src.id, fn + 'from ' + url + ' Wrong response!: ', response.body);
  			return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AccessOnesnaHappenError));
  		}
  		return cb(null, response.body);
  	});
  };
  
  var updateUserCompanies = function updateUserCompanies(src, data, cb) {
  	var fn = src.fn + '[updateUserCompanies]';
  	var processData = function processData(index, ul, callback) {
  		if (!ul) {
  			return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
  		}
  
  		var cur_company = ul[index];
  		if (!cur_company) {
  			return callback(null, ul);
  		} else {
  			_utilsDbwrapper2['default'].execute(_companyCompanyModel2['default'], _companyCompanyModel2['default'].findOne, src.id, { ndbid: cur_company.initiator_id }, function (err, company) {
  				var logCompanyId = cur_company.initiator_id.toString();
  				if (err) {
  					_modulesLoggerIndex2['default'].error(src.id, fn + 'Error finding company with ndbid: ' + logCompanyId);
  					return processData(index + 1, ul, callback);
  				}
  				if (company) {
  					_modulesLoggerIndex2['default'].sync(src.id, fn + 'Found company on logan updated user with ndbid: ' + logCompanyId);
  					ul[index].initiator_id = company._id;
  					return processData(index + 1, ul, callback);
  				} else {
  					_modulesLoggerIndex2['default'].sync(src.id, fn + 'Company not found with ndbid: ' + logCompanyId);
  					getCompanyOnesna(src, { companyId: cur_company.initiator_id }, function (err, result) {
  						if (err) {
  							return processData(index + 1, ul, callback);
  						}
  						var thisCompany = JSON.parse(result);
  						thisCompany.ndbid = thisCompany.id;
  						delete thisCompany.id;
  						_modulesLoggerIndex2['default'].sync(src.id, fn + 'Company grabbed from onesna :', thisCompany);
  						_utilsDbwrapper2['default'].execute(_companyCompanyModel2['default'], _companyCompanyModel2['default'].findOneAndUpdate, src.id, { ndbid: thisCompany.ndbid }, thisCompany, { upsert: true, 'new': true }, function (err, newCompany) {
  							if (err) {
  								_modulesLoggerIndex2['default'].error(src.id, fn + 'Error update company with company ndbid: ' + thisCompany.ndbid + ' with name: ' + thisCompany.name);
  								return processData(index + 1, ul, callback);
  							}
  							_modulesLoggerIndex2['default'].sync(src.id, fn + 'Company update successfully with: ' + newCompany._id + ' with name: ' + newCompany.name);
  							_companyCompanyEvent2['default'].emitCompanyUpdated(src, newCompany);
  							ul[index].initiator_id = newCompany._id;
  							return processData(index + 1, ul, callback);
  						});
  					});
  				}
  			});
  		}
  	};
  
  	processData(0, data, function (err, processResult) {
  		if (err) {
  			_modulesLoggerIndex2['default'].error(src.id, err);
  			return cb(err);
  		}
  
  		return cb(null, processResult);
  	});
  };
  
  var updateCompanyDeletedForUser = function updateCompanyDeletedForUser(src, data, cb) {
  	var fn = src.fn + '[updateCompanyDeletedForUser]';
  	_utilsDbwrapper2['default'].execute(_userUserModel2['default'], _userUserModel2['default'].update, src.id, { "relation_graphs.initiator_id": data._id }, { $pull: { relation_graphs: { initiator_id: data._id } } }, function (err, updatedUsers) {
  		if (err) {
  			_modulesLoggerIndex2['default'].error(src.id, fn + 'Error delete company in user relation_graphs with company', data);
  			return cb(err);
  		}
  		_modulesLoggerIndex2['default'].sync(src.id, fn + ' Updatedusers :' + updatedUsers.nModified);
  		return cb(null);
  	});
  };
  
  var updateCompanyAddedForUser = function updateCompanyAddedForUser(src, data, cb) {
  	var fn = src.fn + '[updateCompanAddedForUser]';
  	_utilsDbwrapper2['default'].execute(_userUserModel2['default'], _userUserModel2['default'].update, src.id, { "relation_graphs.initiator_id": data.ndbid }, { $set: { 'relation_graphs.$.initiator_id': data._id } }, function (err, updatedUsers) {
  		if (err) {
  			_modulesLoggerIndex2['default'].error(src.id, fn + 'Error update company in user relation_graphs with company', data);
  			return cb(err);
  		}
  		_modulesLoggerIndex2['default'].sync(src.id, fn + ' Updatedusers :' + updatedUsers.nModified);
  		return cb(null);
  	});
  };
  //
  var userUpdated = function userUpdated(src, data, cb) {
  	_modulesLoggerIndex2['default'].sync(src.id, src.fn + 'New User updated! Checking data...');
  	updateUserCompanies(src, data.relation_graphs, cb);
  };
  
  var companyUpdated = function companyUpdated(src, data, cb) {
  	_modulesLoggerIndex2['default'].sync(src.id, src.fn + 'New Company updated! Checking data...');
  	updateCompanyAddedForUser(src, data, cb);
  };
  
  var companyDeleted = function companyDeleted(src, data, cb) {
  	_modulesLoggerIndex2['default'].sync(src.id, src.fn + 'Onesna Company deleted! Checking data...');
  	updateCompanyDeletedForUser(src, data, cb);
  };
  
  _userUserEvent2['default'].onUserUpdated(function (src, user) {
  	var fn = src.fn + '[userEvent.onUserUpdated]';
  	userUpdated(src, user, function (err, result) {
  		if (err) {
  			_modulesLoggerIndex2['default'].error(src.id, fn + 'User relation graph update failed');
  		} else {
  			_modulesLoggerIndex2['default'].sync(src.id, fn + 'User relation table updated ' + user._id);
  			_utilsDbwrapper2['default'].execute(_userUserModel2['default'], _userUserModel2['default'].findOneAndUpdate, src.id, { _id: user._id }, {
  				$set: {
  					relation_graphs: result
  				}
  			}, { 'new': true }, function (err, newUser) {
  				if (err) {
  					_modulesLoggerIndex2['default'].error(src.id, fn + 'Error updating User relation graph', err);
  				}
  				_modulesLoggerIndex2['default'].sync(src.id, fn + 'User relation graph update successfully for user with id: ' + newUser._id);
  			});
  		}
  	});
  });
  _companyCompanyEvent2['default'].onCompanyUpdated(function (src, company) {
  	var fn = src.fn + '[companyEvent.onCompanyUpdated]';
  	companyUpdated(src, company, function (err, result) {
  		if (err) {
  			_modulesLoggerIndex2['default'].error(fn + 'Update 1 company with ' + company._id + ' for all user relation graph failed');
  		} else {
  			_modulesLoggerIndex2['default'].sync(fn + 'Update 1 company ' + company._id + ' for all user relation graph finished');
  		}
  	});
  });
  _companyCompanyEvent2['default'].onCompanyDeleted(function (src, company) {
  	var fn = src.fn + '[companyEvent.onCompanyDeleted]';
  	companyDeleted(src, company, function (err, result) {
  		if (err) {
  			_modulesLoggerIndex2['default'].error(fn + 'Delete company with ' + company._id + ' from all user relation graph failed');
  		} else {
  			_modulesLoggerIndex2['default'].sync(fn + 'Delete company with ' + company._id + ' from all user relation graph finished');
  		}
  	});
  });

/***/ },
/* 74 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  //Version 1.0
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _topicController = __webpack_require__(127);
  
  var _topicController2 = _interopRequireDefault(_topicController);
  
  var _authAuthService = __webpack_require__(15);
  
  var _authAuthService2 = _interopRequireDefault(_authAuthService);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var router = new _express.Router();
  
  router.get('/', (0, _viewBaseViewBase.asView)(_topicController2['default'].index));
  router.post('/invite', (0, _viewBaseViewBase.asView)(_topicController2['default'].newTopic));
  router.get('/invites/:inviteId/join', (0, _viewBaseViewBase.asView)(_topicController2['default'].joinTopicFromInvite));
  router.get('/invites/:inviteId', (0, _viewBaseViewBase.asView)(_topicController2['default'].getInvite));
  router.post('/invites/:inviteId', (0, _viewBaseViewBase.asView)(_topicController2['default'].updateInvite));
  router['delete']('/invites/:inviteId', (0, _viewBaseViewBase.asView)(_topicController2['default'].deleteInvite));
  router.post('/:topicId/invite', (0, _viewBaseViewBase.asView)(_topicController2['default'].addToTopic));
  router.get('/:topicId/members', (0, _viewBaseViewBase.asView)(_topicController2['default'].getMembersOfTopic));
  //router.get('/search', asView(controller.searchTopics));
  router.get('/:topicId/join', (0, _viewBaseViewBase.asView)(_topicController2['default'].join));
  router.get('/:topicId', (0, _viewBaseViewBase.asView)(_topicController2['default'].show));
  router.post('/', (0, _viewBaseViewBase.asView)(_topicController2['default'].create));
  router.post('/:topicId', (0, _viewBaseViewBase.asView)(_topicController2['default'].update));
  //router.patch('/:topicId', asView(controller.update));
  
  router.get('/:topicId/messages/byref', (0, _viewBaseViewBase.asView)(_topicController2['default'].ListMessageByRefView));
  router.get('/:topicId/tasks', (0, _viewBaseViewBase.asView)(_topicController2['default'].ListOfTopicTasksView));
  router.post('/:topicId/tasks', (0, _viewBaseViewBase.asView)(_topicController2['default'].addTaskView));
  router.get('/:topicId/ideas', (0, _viewBaseViewBase.asView)(_topicController2['default'].ListOfTopicIdeasView));
  router.post('/:topicId/ideas', (0, _viewBaseViewBase.asView)(_topicController2['default'].addIdeaView));
  
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 75 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Backend non api functions
   */
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
  	value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _modulesEmailTemplater = __webpack_require__(61);
  
  var _modulesEmailTemplater2 = _interopRequireDefault(_modulesEmailTemplater);
  
  var _fluxConstantsMeetingConstants = __webpack_require__(39);
  
  var _fluxConstantsMeetingConstants2 = _interopRequireDefault(_fluxConstantsMeetingConstants);
  
  var _notifyNotifyEvent = __webpack_require__(56);
  
  var _notifyNotifyEvent2 = _interopRequireDefault(_notifyNotifyEvent);
  
  var _notifyNotifyBackend = __webpack_require__(70);
  
  var _notifyNotifyBackend2 = _interopRequireDefault(_notifyNotifyBackend);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _authPermissionConfig = __webpack_require__(78);
  
  var _authPermissionConfig2 = _interopRequireDefault(_authPermissionConfig);
  
  var _topicEvent = __webpack_require__(76);
  
  var _topicEvent2 = _interopRequireDefault(_topicEvent);
  
  var _util = __webpack_require__(12);
  
  var _util2 = _interopRequireDefault(_util);
  
  var _userUserModel = __webpack_require__(14);
  
  var _userUserModel2 = _interopRequireDefault(_userUserModel);
  
  var _taskqueueTaskqueueBackend = __webpack_require__(22);
  
  var _taskqueueTaskqueueBackend2 = _interopRequireDefault(_taskqueueTaskqueueBackend);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  /**
   * CRUD
   */
  var _ = __webpack_require__(11),
      Topic = __webpack_require__(18),
      utils = __webpack_require__(40),
      logger = __webpack_require__(1),
      inviteBusiness = __webpack_require__(55),
      userBusiness = __webpack_require__(23),
      TopicInvite = __webpack_require__(58);
  
  exports['default'] = {
  	create: function create(topic, cb) {
  		_utilsDbwrapper2['default'].execute(Topic, Topic.create, null, topic, function (err, data) {
  			if (err) {
  				return cb(err);
  			}
  
  			if (!data) {
  				return cb('not retrieving created topic');
  			} else {
  				return cb(null, data);
  			}
  		});
  	},
  	hasTopicAccess: function hasTopicAccess(params, cb) {
  		Topic.findById({
  			_id: params.topicId
  		}, function (err, resultTopic) {
  			if (err) {
  				return cb(err);
  			}
  			if (!resultTopic) {
  				return cb('Can not find topic with id: ' + params.topicId);
  			}
  
  			var topicAccess = {};
  			topicAccess.topic = resultTopic;
  			if (!params.user || !params.user._id) {
  				topicAccess.role = _fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.GUEST.type;
  				return cb(null, topicAccess);
  			} else {
  				var isMember = _.find(resultTopic.members, { member: params.user._id.toString() });
  				if (isMember) {
  					topicAccess.role = isMember.role;
  					return cb(null, topicAccess);
  				} else {
  					topicAccess.role = _fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.GUEST.type;
  					return cb(null, topicAccess);
  				}
  			}
  		});
  	},
  	quitTopic: function quitTopic(data, cb) {
  		var quitId;
  		if (!data.topic) {
  			return cb('no topic');
  		}
  		if (data.user) {
  			quitId = data.user._id;
  		}
  		if (data.anonymous) {
  			quitId = data.anonymous._id;
  		}
  		if (data.quitId) {
  			quitId = data.quitId;
  		}
  		quitTopicById(quitId, topic, cb);
  	},
  
  	quitTopicById: function quitTopicById(id, topic, cb) {
  		Topic.findOneAndUpdate({
  			_id: topic._id,
  			'members._id': id
  		}, {
  			$pull: {
  				'members._id': id
  			}
  		}, { 'new': true }, function (err, updatedTopic) {
  			if (err) {
  				return cb('Error query topic quitTopicById');
  			}
  			if (!updatedTopic) {
  				return cb('Can not find topic');
  			}
  			return cb(null, updatedTopic);
  		});
  	},
  
  	quitTopicByObj: function quitTopicByObj(obj, topic, cb) {
  		if (!obj || !obj.id) {
  			return cb('No obj passed');
  		}
  		this.quitTopicById(obj.id, topic, cb);
  	},
  	userQuitTopic: function userQuitTopic(user, topic, cb) {
  		this.quitTopicByObj(user, topic, cb);
  	},
  	anonymousQuitTopic: function anonymousQuitTopic(anony, topic, cb) {
  		this.quitTopicByObj(anony, topic, cb);
  	},
  	/**
    * First Layer
    */
  
  	checkList: function checkList(tlist, cb) {
  		var processTopics = function processTopics(index, tl, callback) {
  			if (!tl) {
  				return callback('ERROR: No input list');
  			}
  
  			var cur_t = tl[index];
  			if (!cur_t) {
  				return callback(null, tl);
  			}
  
  			if (cur_t.id) {
  				processTopics(index + 1, tl, callback);
  			} else {
  				Topic.create(cur_t, function (err, newTopic) {
  					if (err) {
  						return callback(err);
  					}
  					tl[index] = newTopic;
  					processTopics(index + 1, tl, callback);
  				});
  			}
  		};
  
  		processTopics(0, tlist, function (err, resultList) {
  			if (err) {
  				return cb(err);
  			}
  
  			return cb(null, resultList);
  		});
  	},
  	updateInvite: function updateInvite(src, data, cb) {
  		_utilsDbwrapper2['default'].execute(TopicInvite, TopicInvite.findOneAndUpdate, src.id, { _id: data.oldInvite._id }, data.newInvite, { 'new': true, runValidators: true }, function (err, updatedInvite) {
  			if (err) {
  				logger.error(src.id, new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].DBError));
  				return cb(err);
  			}
  			logger.info(src.id, 'new topic invite updated! with id ' + updatedInvite._id);
  			if (data.informChannel !== 'server') {
  				logger.info(src.id, 'Not sending notification');
  				var contentData = {
  					link: updatedInvite.makeInviteUrl(src.domain),
  					title: data.topic.title
  				};
  				return cb(null, {
  					data: [updatedInvite],
  					inviteContent: {
  						text: _modulesEmailTemplater2['default'].inviteUser.inviteContentText(contentData),
  						html: _modulesEmailTemplater2['default'].inviteUser.inviteContentHtml(contentData)
  					}
  				});
  			} else {
  				logger.info(src.id, 'Update Invite checking invitee list, server inform channel');
  				data.topicInvite = updatedInvite;
  				var oldContactList = data.oldInvite.invitees.map(function (invitee) {
  					return invitee.invitee;
  				});
  				var newInvitees = _.filter(updatedInvite.invitees, function (invitee) {
  					return oldContactList.indexOf(invitee.invitee) < 0;
  				});
  
  				if (!newInvitees || newInvitees.length === 0) {
  					logger.info('No new invitees found');
  					return cb(null, { data: [updatedInvite] });
  				}
  				data.invitees = newInvitees;
  				userBusiness.inviteUsers(src, data, function (err) {
  					if (err) {
  						logger.error(src.id, 'Error sendinng notification to Users', err);
  						return cb(err);
  					}
  					return cb(null, { data: [updatedInvite] });
  				});
  			}
  		});
  	},
  	newInvite: function newInvite(src, data, cb) {
  		var newInvite = {
  			invitees: data.invitees,
  			topicId: data.topic._id,
  			startDateTime: data.startDateTime,
  			endDateTime: data.endDateTime
  		};
  		_utilsDbwrapper2['default'].execute(TopicInvite, TopicInvite.create, src.id, newInvite, function (err, createdInvite) {
  			if (err) {
  				logger.error(src.id, new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].DBError));
  				return cb(err);
  			}
  			logger.info(src.id, 'new topic invite created! with id' + createdInvite._id, createdInvite.toJSON());
  			if (data.informChannel !== 'server') {
  				logger.info(src.id, 'Not sending notification');
  				var contentData = {
  					link: createdInvite.makeInviteUrl(src.domain),
  					title: data.topic.title
  				};
  				return cb(null, {
  					data: [createdInvite],
  					inviteContent: {
  						text: _modulesEmailTemplater2['default'].inviteUser.inviteContentText(contentData),
  						html: _modulesEmailTemplater2['default'].inviteUser.inviteContentHtml(contentData)
  					}
  				});
  			} else {
  				logger.info(src.id, 'Sending notification');
  				data.topicInvite = createdInvite;
  				userBusiness.inviteUsers(src, data, function (err) {
  					if (err) {
  						logger.error(src.id, 'Error sendinng notification to Users', err);
  						return cb(err);
  					}
  					return cb(null, { data: [createdInvite] });
  				});
  			}
  		});
  	},
  	entryInfo: function entryInfo(inviteInfo, topicInfo) {
  		var entry = {};
  		entry.inviteInfo = inviteInfo;
  		entry.topic = topicInfo;
  		return function (accessInfo, actionInfo) {
  			entry.attendeeInfo = { type: accessInfo };
  			if (entry.attendeeInfo === _fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.GUEST.type) {
  				var s = inviteInfo.startDateTime;
  				var e = inviteInfo.endDateTime;
  				var n = new Date();
  				if (s && e && n <= e && n >= s) {
  					entry.requiredAction = 'join';
  				} else {
  					entry.requiredAction = 'knock';
  				}
  			} else {
  				entry.requiredAction = actionInfo;
  			}
  			return entry;
  		};
  	},
  
  	joinTopic: function joinTopic(src, data, cb) {
  		var self = this;
  		Topic.findById(data.topicId, function (err, topic) {
  			if (err) {
  				logger.error(src.id, 'Error finding topic', err);
  				return cb(err);
  			}
  			if (!topic) {
  				return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
  			}
  			if (src.relPermChecker) {
  				src.relPermChecker.checkRelation(src, topic, _utilsServerConstants2['default'].TypeTopic, function (err) {
  					if (err) {
  						return cb(err);
  					}
  					var entry = self.entryInfo(undefined, topic);
  					var isMember = _.find(topic.members, { member: data.user._id.toString() });
  					self.getUsersOfTopic(src, topic, function (err, topic) {
  						if (isMember) {
  							logger.info(src.id, 'This is already a member/admin ', isMember);
  							_notifyNotifyEvent2['default'].emitUserAccessed(src.id, { user: data.user, target: topic });
  							return cb(null, entry(isMember.role, 'join'));
  						} else {
  							_notifyNotifyEvent2['default'].emitUserAccessed(src.id, { user: data.user, target: topic });
  							return cb(null, entry(_fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.GUEST.type));
  						}
  					});
  				});
  			}
  		});
  	},
  
  	accessTopic: function accessTopic(src, data, cb) {
  		var self = this;
  		Topic.findById(data.topicId, function (err, topic) {
  			if (err) {
  				logger.error(src.id, 'Error finding topic', err);
  				return cb(err);
  			}
  			if (!topic) {
  				return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
  			}
  			if (src.relPermChecker) {
  				src.relPermChecker.checkRelation(src, topic, _utilsServerConstants2['default'].TypeTopic, function (err) {
  					if (err) {
  						return cb(err);
  					}
  					var entry = self.entryInfo(undefined, topic);
  					var isMember = _.find(topic.members, { member: data.user._id.toString() });
  					if (isMember) {
  						logger.info(src.id, 'This is already a member/admin ', isMember);
  						_notifyNotifyEvent2['default'].emitUserAccessed(src.id, { user: data.user, target: topic });
  						return cb(null, entry(isMember.role, 'join'));
  					} else {
  						_notifyNotifyEvent2['default'].emitUserAccessed(src.id, { user: data.user, target: topic });
  						return cb(null, entry(_fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.GUEST.type));
  					}
  				});
  			}
  		});
  	},
  
  	joinTopicFromInvite: function joinTopicFromInvite(src, data, cb) {
  		var topicInfo,
  		    inviteInfo,
  		    self = this;
  		TopicInvite.findById(data.inviteId, function (err, resultInvite) {
  			if (err) {
  				return cb(err);
  			}
  
  			if (!resultInvite) {
  				return cb('Can not find the invite :' + data.inviteId);
  			}
  			inviteInfo = { startDateTime: resultInvite.startDateTime, endDateTime: resultInvite.endDateTime };
  			Topic.findById({
  				_id: resultInvite.topicId
  			}, function (err, resultTopic) {
  				if (err) {
  					return cb(err);
  				}
  				if (!resultTopic) {
  					return cb('Can not find topic with id: ' + resultInvite.topicId);
  				}
  				logger.info(src.id, 'Found the topic to join, Start Joining the Topic');
  				topicInfo = { _id: resultTopic._id, title: resultTopic.title };
  				var entry = self.entryInfo(inviteInfo, topicInfo);
  				if (data.user) {
  					var isMember = _.find(resultTopic.members, { member: data.user._id.toString() });
  					if (isMember) {
  						logger.info(src.id, 'This is already a member/admin ', isMember);
  						_notifyNotifyEvent2['default'].emitUserJoinInvite(src, { user: data.user, target: topicInfo, role: isMember.role });
  						return cb(null, entry(isMember.role, 'join'));
  					} else {
  						logger.info(src.id, 'This is not a member/admin yet ', data.user._id.toString());
  						var isInvited = _.find(resultInvite.invitees, function (invitee) {
  							if (!invitee.role || [_fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.ADMIN.type, _fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.MEMBER.type].indexOf(invitee.role) > -1) {
  								if (invitee.inviteeType === 'email' && invitee.invitee === data.user.username) {
  									return true;
  								} else if (invitee.inviteeType === 'userId' && invitee.invitee === data.user._id.toString()) {
  									return true;
  								} else {
  									return false;
  								}
  							} else {
  								return false;
  							}
  						});
  						if (isInvited) {
  							logger.info(src.id, 'This is invited ', isInvited);
  							var memberRole = isInvited.role || _fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.MEMBER.type;
  							Topic.findOneAndUpdate({
  								_id: topicInfo._id
  							}, {
  								$push: {
  									'members': {
  										member: data.user._id,
  										memberType: 'userId', //  userId
  										role: memberRole, //admin | member
  										joinTime: new Date(),
  										username: data.user.username,
  										displayname: data.user.displayname,
  										picture_url: data.user.picture_url
  									}
  								}
  							}, function (err, updatedTopic) {
  								if (err) {
  									logger.error(src.id, 'Error adding user to topic member list with userid : ' + data.user._id + ' and topic id: ' + topicInfo._id);
  									return cb(err);
  								}
  								_notifyNotifyEvent2['default'].emitUserJoinInvite(src, { user: data.user, target: topicInfo, role: memberRole });
  								logger.info(src.id, 'New invited user joined topic : ' + topicInfo._id + ' and with a role : ' + memberRole);
  								return cb(null, entry(memberRole, 'join'));
  							});
  						} else {
  							_notifyNotifyEvent2['default'].emitUserJoinInvite(src, { user: data.user, target: topicInfo, role: _fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.GUEST.type });
  							return cb(null, entry(_fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.GUEST.type));
  						}
  					}
  				} else {
  					return cb(HttpErrorStatus);
  				}
  			});
  		});
  	},
  
  	addToTopic: function addToTopic(src, data, cb) {
  		this.newInvite(src, data, cb);
  	},
  
  	getUsersOfTopic: function getUsersOfTopic(src, data, cb) {
  		var functionName = '[getUsersOfTopic]';
  		_async2['default'].waterfall([function (interCallback) {
  			logger.info(src.id, _util2['default'].format('%s Query members from topic', functionName), data);
  			if (data._id) {
  				return interCallback(null, data);
  			}
  			var exeobj = Topic.findById(data.topicId).slice('members', [data.pagination.skip, data.pagination.limit]).select('members').lean();
  			_utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, topicObj) {
  				if (err) {
  					logger.error(src.id, _util2['default'].format('%s Query members happen error', functionName), err);
  					return interCallback(err);
  				}
  				return interCallback(null, topicObj);
  			});
  		}, function (topicObj, interCallback) {
  			var needUserInfoSet = new Set();
  			var _iteratorNormalCompletion = true;
  			var _didIteratorError = false;
  			var _iteratorError = undefined;
  
  			try {
  				for (var _iterator = topicObj.members[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
  					var memberItem = _step.value;
  
  					if (memberItem.memberType == 'userId' && (!memberItem.username || !memberItem.displayname || !memberItem.picture_url)) {
  						needUserInfoSet.add(memberItem);
  					}
  				}
  			} catch (err) {
  				_didIteratorError = true;
  				_iteratorError = err;
  			} finally {
  				try {
  					if (!_iteratorNormalCompletion && _iterator['return']) {
  						_iterator['return']();
  					}
  				} finally {
  					if (_didIteratorError) {
  						throw _iteratorError;
  					}
  				}
  			}
  
  			if (needUserInfoSet.size > 0) {
  				var membersArray = (function () {
  					var _membersArray = [];
  					var _iteratorNormalCompletion2 = true;
  					var _didIteratorError2 = false;
  					var _iteratorError2 = undefined;
  
  					try {
  						for (var _iterator2 = needUserInfoSet[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
  							var memberItem = _step2.value;
  
  							_membersArray.push(memberItem.member);
  						}
  					} catch (err) {
  						_didIteratorError2 = true;
  						_iteratorError2 = err;
  					} finally {
  						try {
  							if (!_iteratorNormalCompletion2 && _iterator2['return']) {
  								_iterator2['return']();
  							}
  						} finally {
  							if (_didIteratorError2) {
  								throw _iteratorError2;
  							}
  						}
  					}
  
  					return _membersArray;
  				})();
  				var exeobj = _userUserModel2['default'].find({ '_id': { '$in': membersArray } }, { "username": 1, "displayname": 1, "picturefile": 1 });
  				logger.info(src.id, _util2['default'].format('%s Query users information from user table', functionName));
  				_utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, userList) {
  					if (err) {
  						logger.error(src.id, _util2['default'].format('%s Query users happen error', functionName), err);
  						return interCallback(null, topicObj, {}, needUserInfoSet);
  					}
  					var userMap = new Map();
  					var _iteratorNormalCompletion3 = true;
  					var _didIteratorError3 = false;
  					var _iteratorError3 = undefined;
  
  					try {
  						for (var _iterator3 = userList[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
  							var userItem = _step3.value;
  
  							userMap.set(userItem._id.toString(), userItem);
  						}
  					} catch (err) {
  						_didIteratorError3 = true;
  						_iteratorError3 = err;
  					} finally {
  						try {
  							if (!_iteratorNormalCompletion3 && _iterator3['return']) {
  								_iterator3['return']();
  							}
  						} finally {
  							if (_didIteratorError3) {
  								throw _iteratorError3;
  							}
  						}
  					}
  
  					return interCallback(null, topicObj, userMap, needUserInfoSet);
  				});
  			} else {
  				return interCallback(null, topicObj, {}, needUserInfoSet);
  			}
  		}, function (topicObj, userMap, needUserInfoSet, interCallback) {
  			if (userMap.size > 0 && needUserInfoSet.size > 0) {
  				logger.info(src.id, _util2['default'].format('%s Fill userinformation into member manully', functionName));
  				var _iteratorNormalCompletion4 = true;
  				var _didIteratorError4 = false;
  				var _iteratorError4 = undefined;
  
  				try {
  					var _loop = function () {
  						var memberItem = _step4.value;
  
  						if (userMap.has(memberItem.member.toString())) {
  							(function () {
  								var userInfo = userMap.get(memberItem.member);
  								_.extend(memberItem, { 'username': userInfo.username, 'displayname': userInfo.displayname, 'picture_url': userInfo.picture_url });
  								setTimeout(function () {
  									syncTopicMemberTrigger(src, userInfo, memberItem), 1000;
  								});
  							})();
  						}
  					};
  
  					for (var _iterator4 = needUserInfoSet[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
  						_loop();
  					}
  				} catch (err) {
  					_didIteratorError4 = true;
  					_iteratorError4 = err;
  				} finally {
  					try {
  						if (!_iteratorNormalCompletion4 && _iterator4['return']) {
  							_iterator4['return']();
  						}
  					} finally {
  						if (_didIteratorError4) {
  							throw _iteratorError4;
  						}
  					}
  				}
  
  				return interCallback(null, topicObj);
  			} else {
  				return interCallback(null, topicObj);
  			}
  		}], function (err, topicObj) {
  			if (err) {
  				return cb(null, { data: [] });
  			}
  			topicObj.data = topicObj.members;
  			return cb(err, topicObj);
  		});
  	},
  	//		  if (err) {
  	//				logger.error(src.id, err);
  	//				return cb(err);
  	//			}
  	//			if (!topic) {
  	//				return cb(new esErr.ESErrors(esErr.DBError));
  	//			}
  	//			var userIds = topic.members.map(function (member) {
  	//				return member.member;
  	//			});
  	//			
  	//			userBusiness.listUsersById(src, {userIds: userIds, pagination: data.pagination, search: data.search}, function (err, userList) {
  	//				if (err) {
  	//					logger.error(src.id, 'Error listing users by id', err);
  	//					return cb(err);
  	//				}
  	//				userList.data = userList.data.map(function (user) {
  	//			      var member = _.find(topic.members, {member: user._id.toString()});
  	//			      if (member) {
  	//			       return _.assign(user.profile, {
  	//			          member: member.member,
  	//			          joinTime: member.joinTime,
  	//			          role: member.role,
  	//			          memberType: member.memberType
  	//			        });
  	//			      }
  	//			    });
  	//				return cb(null, userList);
  	//			});
  
  	//});
  	//	},
  
  	newTopic: function newTopic(src, data, cb) {
  		var self = this;
  		data.members.push({
  			member: data.creator._id,
  			memberType: 'userId', //admin | member
  			role: _fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.ADMIN.type,
  			joinTime: data.now
  		});
  
  		var newTopic = {
  			cid: data.creator._id,
  			members: data.members,
  			title: data.topic.title,
  			description: data.topic.description
  		};
  
  		this.create(newTopic, function (err, createdTopic) {
  			if (err) {
  				logger.error(src.id, err);
  				return cb(err);
  			}
  			_notifyNotifyEvent2['default'].emitUserCreateTopic(src, { user: data.creator, target: createdTopic, role: _fluxConstantsMeetingConstants2['default'].ATTENDEE_TYPES.ADMIN.type });
  			logger.info(src.id, 'new topic created!');
  			data.topic = createdTopic;
  			self.newInvite(src, data, cb);
  		});
  	},
  
  	canSupportAccessWithoutRelation: function canSupportAccessWithoutRelation(src, topicId, cb) {
  		_utilsDbwrapper2['default'].execute(Topic, Topic.findOne, src.id, { _id: topicId }, function (err, topicObj) {
  			if (topicObj && topicObj.settings.accessLimRel == _utilsServerConstants2['default'].JoinTopicNoLimit) {
  				return cb(null, true, topicObj);
  			}
  			return cb(null, false, topicObj);
  		});
  	},
  
  	convertTopicRestrictToStringList: function convertTopicRestrictToStringList(src, topicObj) {
  		var retStringList = [];
  		var restrictArrayVal = _utilsServerConstants2['default'].defaultRestrictValue;
  		if (topicObj.restrict.length > 0) {
  			restrictArrayVal = _.clone(topicObj.restrict);
  		}
  		for (var restrictItemPos in restrictArrayVal) {
  			var bitCnt = 0;
  			var restrictItemVal = restrictArrayVal[restrictItemPos];
  			while (restrictItemVal != 0) {
  				if (restrictItemVal & 1 == 1) {
  					var indexString = _authPermissionConfig2['default'].getStringIndex(restrictItemPos, bitCnt);
  					if (indexString < _authPermissionConfig2['default'].restrictStringList.length) {
  						var stringCfg = _authPermissionConfig2['default'].restrictStringList[indexString];
  						retStringList.push(stringCfg);
  					}
  				}
  				restrictItemVal = restrictItemVal >>> 1;
  				++bitCnt;
  			}
  		}
  		return retStringList;
  	}
  };
  
  function syncTopicMemberTrigger(src, userInfo, memberInfo) {
  	var functionName = '[syncTopicMemberTrigger]';
  	var syncData = {
  		member: memberInfo.member,
  		memberType: memberInfo.memberType,
  		memberData: {
  			"members.$.username": userInfo.username,
  			"members.$.displayname": userInfo.displayname,
  			"members.$.picture_url": userInfo.picture_url
  		}
  	};
  	_taskqueueTaskqueueBackend2['default'].launchDefer(src, 'syncTopicMemberDefer', syncData, { defferOption: true,
  		backoff_seconds: 300,
  		attempts: 3,
  		callback: function callback(err, result) {
  			if (!err) {
  				logger.info(src.id, _util2['default'].format('%s Tigger a task to sync member information information successfully', functionName));
  			} else {
  				logger.info(src.id, _util2['default'].format('%s Tigger a task to sync member information information failed', functionName), syncData);
  			}
  		}
  	});
  }
  
  function syncTopicMemberDefer(src, data, cb) {
  	var functionName = '[syncTopicMemberDefer] ';
  	logger.info(src.id, _util2['default'].format('%s sync topic member info.', functionName), data);
  	var member = data.member;
  	var memberType = data.memberType;
  	var memberData = data.memberData;
  	//  Topic.find({"members": {"$elemMatch":{"member":member, "memberType": memberType}}}, (err, result)=>{
  	//    console.log("======================>>>", result)
  	//  })
  	//  return cb(null)
  	_utilsDbwrapper2['default'].execute(Topic, Topic.update, src.id, { "members": { "$elemMatch": { "member": member, "memberType": memberType } } }, { '$set': memberData }, { 'multi': true }, function (err, result) {
  		if (err) {
  			logger.error(src.id, _util2['default'].format('%s sync topic member info failed.', functionName), err);
  			return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SyncMessageSenderFailed));
  		} else {
  			logger.info(src.id, _util2['default'].format('%s sync topic member info successfully.', functionName));
  			return cb(null);
  		}
  	});
  }
  _taskqueueTaskqueueBackend2['default'].registerDeferHandle('syncTopicMemberDefer', syncTopicMemberDefer);
  
  _topicEvent2['default'].onTopicUpdated = function (src, updatedTopic, oriTopic) {
  	var functionName = '[onTopicUpdated] Update TopicUser topic cached info ';
  	var updatedTitle = updatedTopic.title;
  	var oriTitle = oriTopic.title;
  	logger.info(src.id, _util2['default'].format('%s with updatedTitle=%s oriTitle=%s', functionName, updatedTitle, oriTitle));
  	if (updatedTitle == oriTitle) {
  		logger.info(src.id, _util2['default'].format('%s canceled for no difference with title and description', functionName));
  		return;
  	} else {
  		var updateData = {
  			cachedObjId: updatedTopic._id.toString(),
  			cachedObjType: _utilsServerConstants2['default'].TypeTopic,
  			cachedObjCompareData: updatedTitle
  		};
  		_taskqueueTaskqueueBackend2['default'].launchDefer(src, 'cacheTopicToTopicUserDefer', updateData, { defferOption: true,
  			backoff_seconds: 300,
  			attempts: 3,
  			//Delay 10s to execute the task, let different task with same topic can end itself. 
  			delay: 10,
  			callback: function callback(err, result) {
  				if (!err) {
  					logger.info(src.id, _util2['default'].format('%s trigger a task to do cache work successfuly', functionName));
  				} else {
  					logger.error(src.id, _util2['default'].format('%s trigger a task to do cache work failed', functionName), err);
  				}
  			}
  		});
  	}
  };
  module.exports = exports['default'];

/***/ },
/* 76 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var util = __webpack_require__(12),
      EventEmitter = process.EventEmitter,
      instance;
  
  function TopicEvent() {
      EventEmitter.call(this);
  }
  
  util.inherits(TopicEvent, EventEmitter);
  
  TopicEvent.prototype.emitTopicUpdated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('topicUpdated');
      this.emit.apply(this, args);
  };
  
  TopicEvent.prototype.onTopicUpdated = function (callback) {
      this.on('topicUpdated', callback);
  };
  
  TopicEvent.prototype.emitTopicCreated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('topicCreated');
      this.emit.apply(this, args);
  };
  
  TopicEvent.prototype.onTopicCreated = function (callback) {
      this.on('topicCreated', callback);
  };
  
  TopicEvent.prototype.emitTopicDeleted = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('topicDeleted');
      this.emit.apply(this, args);
  };
  
  TopicEvent.prototype.onTopicDeleted = function (callback) {
      this.on('topicDeleted', callback);
  };
  
  TopicEvent.prototype.emitTopicInvited = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('topicInvited');
      this.emit.apply(this, args);
  };
  
  TopicEvent.prototype.onTopicInvited = function (callback) {
      this.on('topicInvited', callback);
  };
  
  var exportMe = {
      getInstance: function getInstance() {
          return instance || (instance = new TopicEvent());
      }
  };
  
  module.exports = exportMe.getInstance();

/***/ },
/* 77 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _lruCache = __webpack_require__(183);
  
  var _lruCache2 = _interopRequireDefault(_lruCache);
  
  var options = {
    max: 100000,
    maxAge: 1000 * 5 };
  
  var apiCache = (0, _lruCache2['default'])(options); // sets just the max size
  var userCache = (0, _lruCache2['default'])(options);
  var socketCache = (0, _lruCache2['default'])(options);
  exports['default'] = { apiCache: apiCache, userCache: userCache, socketCache: socketCache };
  module.exports = exports['default'];

/***/ },
/* 78 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _fluxConstantsMessageConstants = __webpack_require__(17);
  
  var _fluxConstantsMessageConstants2 = _interopRequireDefault(_fluxConstantsMessageConstants);
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  exports.PermissionDefs = {};
  
  exports.pm = {};
  exports.restrict = {};
  
  var strictStringMap = {};
  var DENY_GUEST_ACCESS_TOPIC = exports.restrict.DENY_GUEST_ACCESS_TOPIC = [0, 0];
  strictStringMap.DENY_GUEST_ACCESS_TOPIC = 'deny_guest_access_topic';
  //This configuration only can be set by itadmin or superuser
  //Other's only can view it
  var DENY_ADMIN_DELETE_TOPIC = exports.restrict.DENY_ADMIN_DELETE_TOPIC = [0, 1];
  strictStringMap.DENY_ADMIN_DELETE_TOPIC = 'deny_admin_delete_topic';
  //var DENY_MEMBER_DELETE_TOPIC = exports.restrict.DENY_MEMBER_DELETE_TOPIC = [0, 2];
  //strictStringMap.DENY_MEMBER_DELETE_TOPIC = 'deny_member_delete_topic';
  //var DENY_GUEST_READ_IDEA = exports.restrict.DENY_GUEST_READ_IDEA= [0, 3];
  //strictStringMap.DENY_GUEST_READ_IDEA = 'deny_guest_read_idea';
  //var DENY_GUEST_READ_TASK = exports.restrict.DENY_GUEST_READ_TASK= [0, 4];
  //strictStringMap.DENY_GUEST_READ_TASK = 'deny_guest_read_task';
  
  var USERSELF_PREFIX = 'userself.';
  var SPECIFIC_PREFIX = 'specific.';
  var SITEADMIN_PREFIX = _utilsServerConstants2['default'].relationAny + '.';
  var ADMIN_PREFIX = _utilsServerConstants2['default'].relationAdmin + '.';
  var EMPLOYEE_PREFIX = _utilsServerConstants2['default'].relationMember + '.';
  
  var RELATION_LIST = [_utilsServerConstants2['default'].relationAdmin, _utilsServerConstants2['default'].relationMember];
  
  var PERM_TOPIC_CREATE = exports.pm.PERM_TOPIC_CREATE = 'topic.create';
  var PERM_TOPIC_READ = exports.pm.PERM_TOPIC_READ = 'topic.read';
  var PERM_TOPIC_IDEA_READ = exports.pm.PERM_TOPIC_IDEA_READ = 'topic.idea.read';
  var PERM_TOPIC_TASK_READ = exports.pm.PERM_TOPIC_TASK_READ = 'topic.task.read';
  var PERM_TOPIC_UPDATE = exports.pm.PERM_TOPIC_UPDATE = 'topic.update';
  var PERM_TOPIC_DELETE = exports.pm.PERM_TOPIC_DELETE = 'topic.delete';
  
  var objectTypeModelMap = {};
  objectTypeModelMap[_utilsServerConstants2['default'].TypeTopic] = __webpack_require__(18);
  
  exports.getStringIndex = function (intPos, bitPos) {
    return intPos * 32 + bitPos;
  };
  
  function createRestrictStringList() {
    var retVal = [];
    for (var restrictKey in exports.restrict) {
      var restrictVal = exports.restrict[restrictKey];
      var indexString = exports.getStringIndex(restrictVal[0], restrictVal[1]);
      if (retVal.length - 1 < indexString) {
        var extendLength = indexString - retVal.length + 1;
        for (var extendCnt = 0; extendCnt < extendLength; ++extendCnt) {
          retVal.push('');
        }
      }
      retVal[indexString] = strictStringMap[restrictKey];
    }
    return retVal;
  }
  exports.restrictStringList = createRestrictStringList();
  
  var getObjWhenId = function getObjWhenId(src, obj, objectType, cb) {
  
    if (typeof obj === 'string' || _mongoose2['default'].Types.ObjectId.isValid(obj.toString())) {
      var model = objectTypeModelMap[objectType];
      if (!model) {
        return cb(null, null);
      }
  
      var proj = undefined;
      if (objectType == _utilsServerConstants2['default'].TypeTopic) {
        proj = { 'restrict': 1, 'parents.parentid': 1, 'parents.parent_type': 1, 'members.member': 1, 'members.memberType': 1, 'members.role': 1 };
      }
      model.findOne({ _id: obj }, proj).exec(function (err, ObjRes) {
        if (err || !ObjRes) {
          return cb(null, null);
        }
        return cb(null, ObjRes);
      });
    } else {
      return cb(null, obj);
    }
  };
  
  function hasNoRestrict(restrictArray, checkVal) {
    var posInt = checkVal[0];
    if (restrictArray.length - 1 < posInt) {
      return true;
    }
    var intval = restrictArray[posInt];
    var shitfedVal = 1 << checkVal[1];
    if ((intval & shitfedVal) == 0) {
      return true;
    }
    return false;
  }
  
  var checkUserTopicPersmission = function checkUserTopicPersmission(src, userObj, topicObj, askPermission) {
    if (askPermission.endsWith(PERM_TOPIC_READ)) {
      if (hasNoRestrict(topicObj.restrict, DENY_GUEST_ACCESS_TOPIC)) {
        return true;
      }
    }
    if (askPermission.startsWith('admin.')) {
      var _iteratorNormalCompletion = true;
      var _didIteratorError = false;
      var _iteratorError = undefined;
  
      try {
        for (var _iterator = topicObj.parents[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
          var parentItem = _step.value;
          var _iteratorNormalCompletion2 = true;
          var _didIteratorError2 = false;
          var _iteratorError2 = undefined;
  
          try {
            for (var _iterator2 = userObj.relation_graphs[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
              var rel = _step2.value;
  
              if (rel.relation_type == 'admin' && rel.initiator_type == parentItem.parent_type && rel.initiator_id == parentItem.parentid) {
                return true;
              }
            }
          } catch (err) {
            _didIteratorError2 = true;
            _iteratorError2 = err;
          } finally {
            try {
              if (!_iteratorNormalCompletion2 && _iterator2['return']) {
                _iterator2['return']();
              }
            } finally {
              if (_didIteratorError2) {
                throw _iteratorError2;
              }
            }
          }
        }
      } catch (err) {
        _didIteratorError = true;
        _iteratorError = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion && _iterator['return']) {
            _iterator['return']();
          }
        } finally {
          if (_didIteratorError) {
            throw _iteratorError;
          }
        }
      }
    }
  
    var _iteratorNormalCompletion3 = true;
    var _didIteratorError3 = false;
    var _iteratorError3 = undefined;
  
    try {
      for (var _iterator3 = topicObj.members[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
        var memberItem = _step3.value;
  
        var memberType = memberItem.memberType;
        if (memberType === 'userId') {
          memberType = _utilsServerConstants2['default'].TypeUser;
        }
        if (memberItem.member == userObj._id && memberType == userObj.aType) {
          if (askPermission.endsWith(PERM_TOPIC_DELETE)) {
            if (memberItem.role == _utilsServerConstants2['default'].relationAdmin && hasNoRestrict(topicObj.restrict, DENY_ADMIN_DELETE_TOPIC)) {
              return true;
            }
          } else {
            return true;
          }
        }
      }
    } catch (err) {
      _didIteratorError3 = true;
      _iteratorError3 = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion3 && _iterator3['return']) {
          _iterator3['return']();
        }
      } finally {
        if (_didIteratorError3) {
          throw _iteratorError3;
        }
      }
    }
  
    return false;
  };
  
  function checkUserSelfPermission(src, userObj, obj, objType, askPermission) {
    var extendPermissions = userObj.extendPermissions || [{ content_type: 'userself.topic.read', object_id: '', object_type: '' }];
    var _iteratorNormalCompletion4 = true;
    var _didIteratorError4 = false;
    var _iteratorError4 = undefined;
  
    try {
      for (var _iterator4 = extendPermissions[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
        var permItem = _step4.value;
  
        if (permItem.content_type == USERSELF_PREFIX + askPermission) {
          if (userObj._id == obj._id && objType == _utilsServerConstants2['default'].TypeUser) {
            return true;
          }
        }
      }
    } catch (err) {
      _didIteratorError4 = true;
      _iteratorError4 = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion4 && _iterator4['return']) {
          _iterator4['return']();
        }
      } finally {
        if (_didIteratorError4) {
          throw _iteratorError4;
        }
      }
    }
  
    return false;
  }
  
  function checkSpecificPersmission(self, userObj, obj, objType, askPermission) {
    var extendPermissions = userObj.extendPermissions || [{ content_type: 'userself.topic.read', object_id: '', object_type: '' }];
    var _iteratorNormalCompletion5 = true;
    var _didIteratorError5 = false;
    var _iteratorError5 = undefined;
  
    try {
      for (var _iterator5 = extendPermissions[Symbol.iterator](), _step5; !(_iteratorNormalCompletion5 = (_step5 = _iterator5.next()).done); _iteratorNormalCompletion5 = true) {
        var permItem = _step5.value;
  
        if (permItem.content_type == SPECIFIC_PREFIX + askPermission) {
          if (permItem.object_id == obj._id && permItem.object_type == _utilsServerConstants2['default'].TypeUser) {
            return true;
          }
        }
      }
    } catch (err) {
      _didIteratorError5 = true;
      _iteratorError5 = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion5 && _iterator5['return']) {
          _iterator5['return']();
        }
      } finally {
        if (_didIteratorError5) {
          throw _iteratorError5;
        }
      }
    }
  
    return false;
  }
  
  function checkUserUserPersmission(src, userObj, otherUserObj, objType, askPermission) {
    if (userObj._id == otherUserObj._id) {
      return true;
    }
    return false;
  }
  
  function checkRelationlistPermission(src, userObj, obj, objType, askPermission) {
    var extendPermissions = userObj.extendPermissions || [{ content_type: 'userself.topic.read', object_id: '', object_type: '' }];
    var _iteratorNormalCompletion6 = true;
    var _didIteratorError6 = false;
    var _iteratorError6 = undefined;
  
    try {
      for (var _iterator6 = RELATION_LIST[Symbol.iterator](), _step6; !(_iteratorNormalCompletion6 = (_step6 = _iterator6.next()).done); _iteratorNormalCompletion6 = true) {
        var r_item = _step6.value;
        var _iteratorNormalCompletion7 = true;
        var _didIteratorError7 = false;
        var _iteratorError7 = undefined;
  
        try {
          for (var _iterator7 = extendPermissions[Symbol.iterator](), _step7; !(_iteratorNormalCompletion7 = (_step7 = _iterator7.next()).done); _iteratorNormalCompletion7 = true) {
            var permItem = _step7.value;
  
            if (permItem.content_type == r_item + '.' + askPermission) {
              var _iteratorNormalCompletion8 = true;
              var _didIteratorError8 = false;
              var _iteratorError8 = undefined;
  
              try {
                for (var _iterator8 = userObj.relation_graphs[Symbol.iterator](), _step8; !(_iteratorNormalCompletion8 = (_step8 = _iterator8.next()).done); _iteratorNormalCompletion8 = true) {
                  var rel = _step8.value;
  
                  if (rel.relation_type == r_item && rel.initiator_id == obj._id && rel.initiator_type == objType) {
                    return true;
                  }
                }
              } catch (err) {
                _didIteratorError8 = true;
                _iteratorError8 = err;
              } finally {
                try {
                  if (!_iteratorNormalCompletion8 && _iterator8['return']) {
                    _iterator8['return']();
                  }
                } finally {
                  if (_didIteratorError8) {
                    throw _iteratorError8;
                  }
                }
              }
            }
          }
        } catch (err) {
          _didIteratorError7 = true;
          _iteratorError7 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion7 && _iterator7['return']) {
              _iterator7['return']();
            }
          } finally {
            if (_didIteratorError7) {
              throw _iteratorError7;
            }
          }
        }
      }
    } catch (err) {
      _didIteratorError6 = true;
      _iteratorError6 = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion6 && _iterator6['return']) {
          _iterator6['return']();
        }
      } finally {
        if (_didIteratorError6) {
          throw _iteratorError6;
        }
      }
    }
  
    return false;
  }
  
  var objectTypeCheckHandles = {};
  objectTypeCheckHandles[_utilsServerConstants2['default'].TypeTopic] = checkUserTopicPersmission;
  objectTypeCheckHandles[_utilsServerConstants2['default'].TypeUser] = checkUserUserPersmission;
  
  var otherCheckHandle = function otherCheckHandle(src, userObj, obj, objType, askPermission) {
    var check_list = [checkUserSelfPermission, checkSpecificPersmission, checkRelationlistPermission];
    if (askPermission.startsWith(USERSELF_PREFIX)) {
      return check_list[0](userObj, obj, objType, askPermission.replace(USERSELF_PREFIX, ''));
    } else if (askPermission.startsWith(SPECIFIC_PREFIX)) {
      return check_list[1](userObj, obj, objType, askPermission.replace(SPECIFIC_PREFIX, ''));
    } else if (askPermission.startsWith(ADMIN_PREFIX)) {
      return check_list[2](userObj, obj, objType, askPermission.replace(ADMIN_PREFIX, ''));
    } else if (askPermission.startsWith(EMPLOYEE_PREFIX)) {
      return check_list[2](userObj, obj, objType, askPermission.replace(EMPLOYEE_PREFIX, ''));
    } else {
      var _iteratorNormalCompletion9 = true;
      var _didIteratorError9 = false;
      var _iteratorError9 = undefined;
  
      try {
        for (var _iterator9 = check_list[Symbol.iterator](), _step9; !(_iteratorNormalCompletion9 = (_step9 = _iterator9.next()).done); _iteratorNormalCompletion9 = true) {
          var funItem = _step9.value;
  
          if (funItem(userObj, obj, objType, askPermission)) {
            return true;
          }
        }
      } catch (err) {
        _didIteratorError9 = true;
        _iteratorError9 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion9 && _iterator9['return']) {
            _iterator9['return']();
          }
        } finally {
          if (_didIteratorError9) {
            throw _iteratorError9;
          }
        }
      }
    }
    return false;
  };
  
  function hasPermWithNoObj(src, askPermission, userObj, cb) {
    var extendPermissions = userObj.extendPermissions || [{ content_type: 'userself.topic.read', object_id: '', object_type: '' }];
    var _iteratorNormalCompletion10 = true;
    var _didIteratorError10 = false;
    var _iteratorError10 = undefined;
  
    try {
      for (var _iterator10 = extendPermissions[Symbol.iterator](), _step10; !(_iteratorNormalCompletion10 = (_step10 = _iterator10.next()).done); _iteratorNormalCompletion10 = true) {
        var permItem = _step10.value;
  
        if (permItem.content_type.endsWith(askPermission)) {
          return cb(null, true);
        }
      }
    } catch (err) {
      _didIteratorError10 = true;
      _iteratorError10 = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion10 && _iterator10['return']) {
          _iterator10['return']();
        }
      } finally {
        if (_didIteratorError10) {
          throw _iteratorError10;
        }
      }
    }
  
    if (userObj.aType == _utilsServerConstants2['default'].TypeUser && askPermission.indexOf('topic.') >= 0 || userObj.aType == _utilsServerConstants2['default'].TypeAnonymous && askPermission.indexOf(PERM_TOPIC_READ) >= 0) {
      return cb(null, true);
    }
    return cb(null, false);
  }
  
  function hasPermWithObj(src, askPermission, userObj, obj, objType, cb) {
    var extendPermissions = userObj.extendPermissions || [{ content_type: 'userself.topic.read', object_id: '', object_type: '' }];
    var _iteratorNormalCompletion11 = true;
    var _didIteratorError11 = false;
    var _iteratorError11 = undefined;
  
    try {
      for (var _iterator11 = extendPermissions[Symbol.iterator](), _step11; !(_iteratorNormalCompletion11 = (_step11 = _iterator11.next()).done); _iteratorNormalCompletion11 = true) {
        var permItem = _step11.value;
  
        if (permItem.content_type.endsWith(askPermission)) {
          if (permItem.content_type.startsWith('any.')) {
            return cb(null, true);
          } else {
            if (objType in objectTypeCheckHandles) {
              var result = objectTypeCheckHandles[objType](src, userObj, obj, askPermission);
              if (result) {
                return cb(null, result);
              }
            } else {
              var result = otherCheckHandle(src, userObj, obj, objType, askPermission);
              if (result) {
                return cb(null, result);
              }
            }
          }
        }
      }
    } catch (err) {
      _didIteratorError11 = true;
      _iteratorError11 = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion11 && _iterator11['return']) {
          _iterator11['return']();
        }
      } finally {
        if (_didIteratorError11) {
          throw _iteratorError11;
        }
      }
    }
  
    if (askPermission.indexOf('topic.') >= 0) {
      if (objType in objectTypeCheckHandles) {
        var result = objectTypeCheckHandles[objType](src, userObj, obj, askPermission);
        if (result) {
          return cb(null, result);
        }
      }
    }
    return cb(null, false);
  }
  
  exports.hasPerm = function (src, askPermission, userObj, obj, objType, cb) {
    if (obj) {
      getObjWhenId(src, obj, objType, function (err, obj) {
        hasPermWithObj(src, askPermission, userObj, obj, objType, cb);
      });
    } else {
      hasPermWithNoObj(src, askPermission, userObj, cb);
    }
  };

/***/ },
/* 79 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5);
  var Schema = mongoose.Schema;
  
  var PermissionGroupSchema = new Schema({
    permission_name: { type: String, unique: true },
    ndbid: String,
    name: String,
    description: String,
    type: String,
    permissions: [{ _id: false,
      content_type: String,
      ndbid: String,
      object_id: String,
      object_type: String }]
  });
  
  module.exports = mongoose.model('PermissionGroup', PermissionGroupSchema);

/***/ },
/* 80 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5),
      Schema = mongoose.Schema;
  
  var EnrollAdminSchema = new Schema({
    group: { type: String, "enum": ['developers', 'enrollAdmins'], 'default': 'developers' },
    emails: [String]
  });
  
  /**
   * Indexes
   */
  EnrollAdminSchema.index({ group: 1 }, { unique: true });
  /**
   * Virtuals
   */
  
  module.exports = mongoose.model('EnrollAdmin', EnrollAdminSchema);

/***/ },
/* 81 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
  	value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror = __webpack_require__(41);
  
  var _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror2 = _interopRequireDefault(_node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror);
  
  var _componentsTranslate = __webpack_require__(47);
  
  var _componentsTranslate2 = _interopRequireDefault(_componentsTranslate);
  
  var ns = '[MessageConstants]';
  var TaskConstants = {};
  
  TaskConstants.TASK_STATUS_TYPES = {
  	PENDING: {
  		status: 'pending',
  		label: _componentsTranslate2['default'].get('PENDING')
  	},
  	COMPLETED: {
  		status: 'completed',
  		label: _componentsTranslate2['default'].get('COMPLETED')
  	},
  	APPROVED: {
  		status: 'approved',
  		label: _componentsTranslate2['default'].get('APPROVED')
  	},
  	REJECTED: {
  		status: 'rejected',
  		label: _componentsTranslate2['default'].get('REJECTED')
  	},
  	TESTING: {
  		status: 'testing',
  		label: _componentsTranslate2['default'].get('TESTING')
  	}
  };
  
  TaskConstants.TASK_DEFAULT_DATA = {
  	bodyText: '',
  	description: '',
  	data: [],
  	assignees: [],
  	status: TaskConstants.TASK_STATUS_TYPES.PENDING.status,
  	dueDate: new Date().toISOString()
  };
  
  TaskConstants.ACTIONS = (0, _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror2['default'])({
  	EDIT_TASK: null,
  	CREATE_TASK: null,
  	ARRIVED_TASK: null,
  	UPDATED_TASK: null
  });
  
  TaskConstants.API = {
  	TOPIC_TASK_ADD: '/api/topics/:topicId/tasks',
  	TASK_UPDATE: '/api/messages/:msgId',
  	TASK_MESSAGES: '/api/tasks/:taskId/messages'
  };
  
  exports['default'] = TaskConstants;
  module.exports = exports['default'];

/***/ },
/* 82 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _q = __webpack_require__(89);
  
  var _q2 = _interopRequireDefault(_q);
  
  var _moment = __webpack_require__(87);
  
  var _moment2 = _interopRequireDefault(_moment);
  
  var _templater = __webpack_require__(61);
  
  var _templater2 = _interopRequireDefault(_templater);
  
  var _sendgrid = __webpack_require__(83);
  
  var _sendgrid2 = _interopRequireDefault(_sendgrid);
  
  var _apiUserUserModel = __webpack_require__(14);
  
  var _apiUserUserModel2 = _interopRequireDefault(_apiUserUserModel);
  
  var _logger = __webpack_require__(1);
  
  var _logger2 = _interopRequireDefault(_logger);
  
  var _apiUserUserEvent = __webpack_require__(31);
  
  var _apiUserUserEvent2 = _interopRequireDefault(_apiUserUserEvent);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _apiEnrollEnrollEvent = __webpack_require__(68);
  
  var _apiEnrollEnrollEvent2 = _interopRequireDefault(_apiEnrollEnrollEvent);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _analyticsGoogle = __webpack_require__(33);
  
  var _analyticsGoogle2 = _interopRequireDefault(_analyticsGoogle);
  
  var _analyticsGoogleConstants = __webpack_require__(32);
  
  var _analyticsGoogleConstants2 = _interopRequireDefault(_analyticsGoogleConstants);
  
  _apiUserUserEvent2['default'].onUserInvited(function (src, data) {
      _logger2['default'].info(src.id, '1 User is invited! Event received!', data.user);
      if (!data.user) {
          _logger2['default'].error(src.id, 'error, undefined user', data);
      }
      if (!data.invite) {
          _logger2['default'].error(src.id, 'error, undefined invite', data);
      }
  
      var link = data.invite.makeInviteUrl(src.domain);
      var sender = data.sender.displayname || data.sender.username;
      var linkRef = new Buffer(JSON.stringify({
          spaceName: data.title,
          inviterName: data.sender.displayname,
          inviterEmail: data.sender.username
      })).toString('base64');
  
      if (linkRef) {
          link += "?inviteInfo=" + linkRef;
      }
  
      _sendgrid2['default'].sendInviteEmail({
          sender: data.sender,
          name: data.user.name || data.user.email,
          email: data.user.email,
          link: link,
          title: data.title,
          emailType: data.user.emailType
      }).then(function () {
          _analyticsGoogle2['default'].postEvent({ category: _analyticsGoogleConstants2['default'].c_Email, action: _analyticsGoogleConstants2['default'].a_newInviteEmail, label: data.invite._id });
          _logger2['default'].info(src.id, 'Invitation email successfully sent !!! ' + data.user.email);
      })['catch'](function (err) {
          _logger2['default'].error(src.id, 'Error sending invite to ' + data.user.email, err);
      });
  });
  
  _apiEnrollEnrollEvent2['default'].onEnrollCreated(function (src, enroll) {
      _logger2['default'].info(src.id, '1 User is requesting enrollAdmin! Event received!', enroll);
      enroll.link = _config2['default'].getLink(src.domain) + "/spaces/enrollrequests/" + enroll._id + "/approval";
      _utilsServerHelper2['default'].getEnrollAdminEmails(function (emails) {
          _async2['default'].each(emails, function (email, callback) {
              enroll.to = email;
              _sendgrid2['default'].sendRequestControlEmail(enroll).then(function () {
                  _analyticsGoogle2['default'].postEvent({ category: _analyticsGoogleConstants2['default'].c_Email, action: _analyticsGoogleConstants2['default'].a_newEnrollEmail, label: "" });
                  _logger2['default'].info(src.id, 'requesting email for ' + enroll.email + ' successfully sent to !!! ' + email);
                  callback();
              })['catch'](function (err) {
                  _logger2['default'].error(src.id, 'Error sending requests to ' + email, err);
                  callback();
              });
          }, function (err, result) {
              _logger2['default'].info(src.id, "done sending request emails");
          });
      });
  });
  
  _apiEnrollEnrollEvent2['default'].onEnrollApproved(function (src, enroll) {
      _logger2['default'].info(src.id, 'Enroll request is approved! Event received!', enroll);
      enroll.link = _config2['default'].getLink(src.domain) + "/spaces/invite";
      _sendgrid2['default'].sendRequestApprovedEmail(enroll).then(function () {
          _analyticsGoogle2['default'].postEvent({ category: _analyticsGoogleConstants2['default'].c_Email, action: _analyticsGoogleConstants2['default'].a_EnrollApprovedEmail, label: "" });
          _logger2['default'].info(src.id, 'Approved congratulation email successfully sent !!! ' + enroll.email);
      })['catch'](function (err) {
          _logger2['default'].error(src.id, 'Error sending congratulation email to ' + enroll.email, err);
      });
  });

/***/ },
/* 83 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var config = __webpack_require__(4),
      q = __webpack_require__(89),
      moment = __webpack_require__(87),
      templater = __webpack_require__(61),
      logger = __webpack_require__(1),
      cst = __webpack_require__(2),
      util = __webpack_require__(6),
      sendgrid = __webpack_require__(190)(config.sendgrid.username, config.sendgrid.password);
  
  exports.sendRequestControlEmail = function (to) {
      var defer = q.defer();
  
      var email = new sendgrid.Email({
          fromname: to.name + ' (via Zang Spaces)'
      });
  
      email.to = to.to;
      email.from = 'enroll@zang.io';
      email.setSubject(' ');
      email.setHtml('<html><body></body></html>');
  
      email.setSubstitutions({
          '-name-': [to.name],
          '-email-': [to.email],
          '-link-': [to.link]
      });
  
      email.setCategories(['Logan Native Request Controll Email']);
  
      email.setFilters({
          'templates': {
              'settings': {
                  'enable': 1,
                  'template_id': templater.requestControll.templateId
              }
          }
      });
  
      sendgrid.send(email, function (err, json) {
          if (err) {
              logger.error('sendgrid error ', err);
              return defer.reject(err);
          } else {
              return defer.resolve(json);
          }
      });
      return defer.promise;
  };
  
  exports.sendRequestApprovedEmail = function (to) {
      var defer = q.defer();
  
      var email = new sendgrid.Email({
          fromname: 'Zang Spaces'
      });
  
      email.addTo(to.email);
      email.from = config.noreplyEmail;
      email.setSubject(' ');
      email.setHtml('<html><body></body></html>');
  
      email.setSubstitutions({
          '-link-': [to.link]
      });
  
      email.setCategories(['Logan Native Request Approved Email']);
  
      email.setFilters({
          'templates': {
              'settings': {
                  'enable': 1,
                  'template_id': templater.requestApproved.templateId
              }
          }
      });
  
      sendgrid.send(email, function (err, json) {
          if (err) {
              logger.error('sendgrid error ', err);
              return defer.reject(err);
          } else {
              return defer.resolve(json);
          }
      });
      return defer.promise;
  };
  
  exports.sendInviteEmail = function (to) {
      var defer = q.defer();
      var sender = to.sender.displayname || to.sender.username;
      var meetingTime;
      var getTip = function getTip(emailType) {
          var tipList = templater.inviteUser.tips[emailType];
          var item = tipList[Math.floor(Math.random() * tipList.length)];
          return item;
      };
  
      var email = new sendgrid.Email({
          fromname: sender + ' (via Zang Spaces)'
      });
  
      email.setSubject(' ');
      email.setHtml('<html><body></body></html>');
      email.addTo(to.email);
      email.from = config.noreplyEmail;
      email.replyto = to.sender.username;
      email.setSubstitutions({
          '-title-': [to.title],
          '-name-': [to.name || to.email],
          '-sender-': [sender],
          '-support-': [config.supportLink],
          '-inviteLink-': [to.link],
          '-MeetingTime-': [meetingTime || ''],
          '-tip-': [getTip(to.emailType)]
      });
  
      email.setCategories(['Logan Native Topic Invite Email']);
  
      email.setFilters({
          'templates': {
              'settings': {
                  'enable': 1,
                  'template_id': templater.inviteUser.templateId
              }
          }
      });
  
      sendgrid.send(email, function (err, json) {
          if (err) {
              logger.error('sendgrid error ', err);
              return defer.reject(err);
          } else {
              return defer.resolve(json);
          }
      });
      return defer.promise;
  };

/***/ },
/* 84 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var gcloud = __webpack_require__(176);
  var logger = __webpack_require__(1);
  var uuid = __webpack_require__(50);
  var esErr = __webpack_require__(3);
  
  // Authenticating on a per-API-basis. You don't need to do this if you auth on a
  // global basis (see Authentication section above).
  var gcloudConfig = __webpack_require__(34);
  var gcs = gcloud.storage(gcloudConfig.credential);
  var bucket = gcs.bucket(gcloudConfig.bucket);
  var tempExtneralBucket = gcs.bucket(gcloudConfig.tempExtneralBucket);
  var buckesMap = {};
  buckesMap[gcloudConfig.bucket] = bucket;
  buckesMap[gcloudConfig.tempExtneralBucket] = tempExtneralBucket;
  
  var DEFAULT_UPLOAD_URL_DURATION = 10 * 60 * 1000;
  var DEFAULT_DOWNLOAD_URL_DURATION = 10 * 60 * 1000;
  exports.getUploadPublicUrl = function (src, data, cb) {
    var file = data.file;
    var gcsObj = bucket.file(file.fileKey);
    gcsObj.getSignedUrl({
      action: 'write',
      expires: Date.now() + 10 * 60 * 1000, // 5 mins
      contentType: file['Content-Type'],
      responseDisposition: file['responseDisposition'] || undefined,
      extensionHeaders: 'x-goog-acl:public-read\n'
    }, function (err, url) {
      if (err) {
        logger.error(src.id, err);
        return cb(err);
      }
      return cb(null, url);
    });
  };
  
  exports.getUploadSignedUrl = function (src, data, cb) {
    var expiration = arguments.length <= 3 || arguments[3] === undefined ? Date.now() + DEFAULT_UPLOAD_URL_DURATION : arguments[3];
  
    var file = data.file;
    var gcsObj = bucket.file('logan/' + file.fileKey);
    gcsObj.getSignedUrl({
      action: 'write',
      expires: expiration, // 5 mins
      contentType: file['Content-Type'],
      responseDisposition: file['responseDisposition'] || undefined
    }, function (err, url) {
      if (err) {
        logger.error(src.id, err);
        return cb(err);
      }
      return cb(null, url);
    });
  };
  
  function startWorker() {
    var child_process = __webpack_require__(162);
    var process = __webpack_require__(21);
    var workerfile = __dirname + '/gcs.service.worker.js';
    //  if (__filename.endsWith('gcs.service.js')){
    //    workerfile = __dirname + '/gcs.service.worker.js';
    //  }
    if (process.execArgv.toString().indexOf('--debug') !== -1) {
      process.execArgv.push('--debug=' + 5859);
    }
    var childProcess = child_process.fork(workerfile, [JSON.stringify(gcloudConfig)], { env: process.env });
    console.log("create gcs sign worker successfully");
  
    childProcess.on('message', function (fileData) {
      var cb = signedUrlKeyMap.get(fileData.commKey);
      setTimeout(function () {
        signedUrlKeyMap['delete'](fileData.commKey);
      }, 10);
      return cb(null, fileData.url);
    });
  
    return childProcess;
  }
  
  var gcsSignWorker = startWorker();
  var signedUrlKeyMap = new Map();
  var keyCnt = 0;
  function sendToWorkder(fileKey, expiration, responseDisposition, cb) {
    var commKey = fileKey + '_' + (++keyCnt).toString();
    signedUrlKeyMap.set(commKey, cb);
    gcsSignWorker.send({ key: fileKey, expiration: expiration, responseDisposition: responseDisposition, commKey: commKey });
  }
  
  exports.getDownloadSignedUrl = function (src, data, cb) {
    var expiration = arguments.length <= 3 || arguments[3] === undefined ? Date.now() + DEFAULT_DOWNLOAD_URL_DURATION : arguments[3];
  
    sendToWorkder(data.key, expiration, data['name'] || undefined, cb);
    //  var file = bucket.file('logan/'+data.key); 
    //  file.getSignedUrl({
    //		action:'read',
    //		expires: expiration,
    //		responseDisposition: data['name'] || undefined
    //	}, function (err, url) {
    //		// body...	
    //		if (err) {
    //			logger.error(src.id, err);
    //			return cb(err);
    //		}		
    //		return cb(null, url);
    //	})
  };
  
  exports.getDownloadPublicUrl = function (src, data, cb) {
    var file = bucket.file('logan/' + data.key);
    file.makePublic(function (err, resp) {
      // body...	
      if (err) {
        logger.error(src.id, err);
        return cb(err);
      }
      return cb(null, url);
    });
  };
  
  exports.copyFile = function (src, data, cb) {
    var functionName = '[file.copyFile ]';
    var loganFolder = 'logan/';
    var destFileName = loganFolder + data.destFileName;
    var destBucketName = data.destBucketName;
    var srcFileName = loganFolder + data.srcFileName;
    var srcBucketName = data.srcBucketName;
    logger.info(src.id, functionName + 'Copy file from bucket=' + srcBucketName + ' file=' + srcFileName + ' to bucket=' + destBucketName + ' file=' + destFileName);
    var srcBucket = buckesMap[srcBucketName] || null;
    var dstBucket = buckesMap[destBucketName] || null;
    var dstAcl = data.dstAcl || null;
  
    if (dstBucket && srcBucket) {
      var srcFile = srcBucket.file(srcFileName);
      var dstFile = dstBucket.file(destFileName);
      if (dstAcl) {
        dstFile.acl.add(dstAcl);
      }
      srcFile.copy(dstFile, function (err, newFile) {
        if (err) {
          logger.error(src.id, functionName + 'Copy file from bucket=' + srcBucketName + ' file=' + srcFileName + ' to bucket=' + destBucketName + ' file=' + destFileName + ' failed.' + err);
          return cb(new esErr.ESErrors(esErr.FileCopyFailed));
        } else {
          logger.info(src.id, functionName + 'Copy file from bucket=' + srcBucketName + ' file=' + srcFileName + ' to bucket=' + destBucketName + ' file=' + destFileName + ' successfully.');
          return cb(null, newFile);
        }
      });
    } else {
      logger.warn(src.id, functionName + 'Copy file from bucket=' + srcBucketName + ' file=' + srcFileName + ' to bucket=' + destBucketName + ' file=' + destFileName + ' failed. For srcbucket or dstbucket is invalid!');
      return cb(new esErr.ESErrors(esErr.FileCopyFailed));
    }
  };
  
  exports.listFiles = function (src, data, cb) {
    var functionName = '[file.listFiles ]';
    var loganFolder = 'logan/';
    var bucketName = data.bucketName;
    var query = {};
    query.autoPaginate = data.autoPaginate || false;
    query.delimiter = data.delimiter;
    query.prefix = loganFolder + data.prefix;
    logger.info(src.id, functionName + 'List files by bucket=' + bucketName + ' query=' + JSON.stringify(query));
    if (bucketName && bucketName in buckesMap) {
      var _bucket = buckesMap[bucketName];
      _bucket.getFiles(query, function (err, files) {
        if (err) {
          logger.warn(src.id, functionName + 'List files by bucket=' + bucketName + ' query=' + JSON.stringify(query) + ' failed', err);
          return cb(null, []);
        }
        logger.info(src.id, functionName + 'List files by bucket=' + bucketName + ' query=' + JSON.stringify(query) + ' successfully');
        return cb(null, files);
      });
    } else {
      logger.warn(src.id, functionName + 'List files by bucket=' + bucketName + ' query=' + JSON.stringify(query) + ' failed, for bucket in invalid');
      return cb(null, []);
    }
  };
  
  exports.createFileObj = function (src, data, cb) {
    var functionName = '[file.createFileObj ]';
    var loganFolder = 'logan/';
    var bucketName = data.bucketName;
    var path = data.path;
    logger.info(src.id, functionName + 'Create file object by bucketName=' + bucketName + ' path=' + path);
    if (bucketName && bucketName in buckesMap) {
      var _bucket2 = buckesMap[bucketName];
      path = loganFolder + path;
      logger.info(src.id, functionName + 'Create file object by bucketName=' + bucketName + ' path=' + path + ' successfully!');
      return cb(null, _bucket2.file(path));
    } else {
      logger.info(src.id, functionName + 'Create file object by bucketName=' + bucketName + ' path=' + path + ' failed! For invalid bucketname');
      return cb(new esErr.ESErrors(esErr.FileCreateObjectFailed));
    }
  };
  
  exports.deleteFiles = function (src, data, cb) {
    var functionName = '[file.deleteFiles ]';
    var loganFolder = 'logan/';
    var bucketName = data.bucketName;
    var query = {};
    query.force = true;
    query.delimiter = data.delimiter;
    query.prefix = loganFolder + data.prefix;
    logger.info(src.id, functionName + 'Delete files by bucket=' + bucketName + ' query=' + JSON.stringify(query));
  
    if (bucketName && bucketName in buckesMap) {
      var _bucket3 = buckesMap[bucketName];
      _bucket3.deleteFiles(query, function (err, result) {
        if (err) {
          return cb(new esErr.ESErrors(esErr.FileDeleteFailed));
        } else {
          return cb(null);
        }
      });
    } else {
      logger.info(src.id, functionName + 'Delete files by bucket=' + bucketName + ' query=' + JSON.stringify(query) + ' failed! invalid bucketname');
      return cb(new esErr.ESErrors(esErr.FileDeleteFailed));
    }
  };

/***/ },
/* 85 */
/***/ function(module, exports, __webpack_require__) {

  
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _pmx = __webpack_require__(52);
  
  var _pmx2 = _interopRequireDefault(_pmx);
  
  module.exports = function (app) {
  	app.use('/content', __webpack_require__(145));
  	app.use('/api/users', __webpack_require__(128));
  	app.use('/api/messages', __webpack_require__(112)); //messages belong to room with id.
  	app.use('/api/companies', __webpack_require__(96));
  	app.use('/api/topics', __webpack_require__(74));
  	app.use('/api/spaces', __webpack_require__(74));
  	app.use('/api/tasks', __webpack_require__(122));
  	app.use('/api/ideas', __webpack_require__(110));
  	app.use('/api/ams', __webpack_require__(91));
  	app.use('/api/anonymous', __webpack_require__(93));
  	app.use('/api/files', __webpack_require__(100));
  	app.use('/api/sync', __webpack_require__(120));
  	app.use('/api/taskqueue', __webpack_require__(125));
  	app.use('/api/migrate', __webpack_require__(115));
  	app.use('/api/enrolls', __webpack_require__(98));
  	app.use('/auth', __webpack_require__(130));
  	app.use('/api/fileviewer', __webpack_require__(107));
  
  	//
  	// Register Database connection
  	// -----------------------------------------------------------------------------
  
  	//
  	// Statis Index.html
  	// -----------------------------------------------------------------------------
  	app.route('/*').get(function (req, res) {
  		res.sendFile(app.get('appPath') + '/public/index.html');
  		// res.redirect('/');
  	});
  
  	// if (config.env && config.env !== 'development') {
  	app.use(_pmx2['default'].expressErrorHandler());
  	// }
  };

/***/ },
/* 86 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Created by andreasi on 1/26/2016.
   */
  
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _Is = __webpack_require__(62);
  
  var _Is2 = _interopRequireDefault(_Is);
  
  exports['default'] = {
    clone: function clone(obj) {
      return !_Is2['default'].$object(obj) || obj === null ? null : JSON.parse(JSON.stringify(obj));
    },
    GUID: function GUID() {
      var d = new Date().getTime();
      var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = (d + Math.random() * 16) % 16 | 0;
        d = Math.floor(d / 16);
        return (c == 'x' ? r : r & 0x7 | 0x8).toString(16);
      });
      return uuid;
    },
    findBy: function findBy(items, field, value) {
      return items.filter(function (item) {
        return item[field] === value;
      });
    },
    getSecondsFromNow: function getSecondsFromNow(sec) {
      return new Date(Date.now() + sec * 1000);
    },
    stringify: function stringify(obj) {
      return JSON.stringify(obj);
    },
    tryParse: function tryParse(str) {
      try {
        return JSON.parse(str);
      } catch (e) {
        return str;
      }
    },
    urlify: function urlify(text, target, className) {
      var urlRegex = /(https?:\/\/[^\s]+)/g;
      target = target || '_self';
      return text.replace(urlRegex, function (url) {
        return '<a href="' + url + '" target="' + target + '">' + url + '</a>';
      });
      // or alternatively
      // return text.replace(urlRegex, '<a href="$1">$1</a>')
    },
    stringExtractUrls: function stringExtractUrls(text) {
      var urlRegex = /(https?:\/\/(?:www\.|(?!www))[^\s\.]+\.[^\s]{2,}|www\.[^\s]+\.[^\s]{2,})/g;
      var links = [];
      var findStr = text;
      findStr.replace(urlRegex, function (url) {
        links.push(url);
        return url;
      });
  
      return links;
      // or alternatively
      // return text.replace(urlRegex, '<a href="$1">$1</a>')
    },
    stripHTMLTags: function stripHTMLTags(html) {
      var tmp = document.createElement('DIV');
      tmp.innerHTML = html;
      return tmp.textContent || tmp.innerText || "";
    },
    includesHTMLTags: function includesHTMLTags(text) {
      return (/<[a-z][\s\S]*>/i.test(text)
      );
      //return text.includes('<') || text.includes('>');
    }
  };
  module.exports = exports['default'];

/***/ },
/* 87 */
/***/ function(module, exports) {

  module.exports = require("moment");

/***/ },
/* 88 */
/***/ function(module, exports) {

  module.exports = require("morgan");

/***/ },
/* 89 */
/***/ function(module, exports) {

  module.exports = require("q");

/***/ },
/* 90 */
/***/ function(module, exports) {

  module.exports = require("react");

/***/ },
/* 91 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Created by andreasi on 11/18/2015.
   */
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _request = __webpack_require__(19);
  
  var _request2 = _interopRequireDefault(_request);
  
  var _jquery = __webpack_require__(182);
  
  var _jquery2 = _interopRequireDefault(_jquery);
  
  var router = new _express.Router();
  
  //const AMS_IP = "http://54.208.80.119:7150"; //demo
  var AMS_IP = "http://146.148.71.203:7150"; //gae
  var AMS_URL = AMS_IP + "/mediacontrol/";
  var LOGAN_NS = "default";
  
  router.post("/", function (req, res) {
    "use strict";
  
    var options = {
      method: "POST",
      url: AMS_URL + LOGAN_NS + req.query.sub,
      headers: {
        "Content-Type": "application/xml"
      },
      body: req.body.xmldoc
    };
    console.log("OPTIONS:", options);
  
    (0, _request2['default'])(options, function (error, response, body) {
      console.log("AMS status code:", response.statusCode);
  
      //console.log("RESPONSE:", response);
      //console.log("ERROR:", error);
      //console.log("BODY:", body);
      res.set("Content-Type", "text/xml").status(response.statusCode).send(body);
    });
  });
  
  router.get("/", function (req, res) {
    "use strict";
  
    var options = {
      method: "GET",
      url: AMS_URL + LOGAN_NS + req.query.sub,
      headers: {
        "Content-Type": "application/xml"
      }
    };
    //console.log("OPTIONS:", options);
  
    (0, _request2['default'])(options, function (error, response, body) {
      console.log("AMS status code:", response.statusCode);
      //console.log("ERROR:", error);
      //console.log("BODY:", body);
      res.set("Content-Type", "text/xml").status(response.statusCode).send(body);
    });
  });
  
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 92 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var _anonymousModel = __webpack_require__(30);
  
  var _anonymousModel2 = _interopRequireDefault(_anonymousModel);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _jsonwebtoken = __webpack_require__(29);
  
  var _jsonwebtoken2 = _interopRequireDefault(_jsonwebtoken);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _viewBaseViewBase2 = _interopRequireDefault(_viewBaseViewBase);
  
  var _authAuthService = __webpack_require__(15);
  
  var _authAuthService2 = _interopRequireDefault(_authAuthService);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _anonymousEvent = __webpack_require__(66);
  
  var _anonymousEvent2 = _interopRequireDefault(_anonymousEvent);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  exports.create = (function (_vw$ViewBase) {
      _inherits(create, _vw$ViewBase);
  
      function create() {
          _classCallCheck(this, create);
  
          _get(Object.getPrototypeOf(create.prototype), 'constructor', this).apply(this, arguments);
      }
  
      _createClass(create, [{
          key: 'handle',
          value: function handle(req, res, cb) {
              var newAnonymousUser = new _anonymousModel2['default'](req.body);
  
              newAnonymousUser.save(function (err, user) {
                  if (err) return validationError(res, err);
                  var parts = req.esDomain.split('.');
                  var issval = req.esDomain;
                  if (parts.length >= 3) {
                      issval = parts.slice(parts.length - 2);
                      issval = issval;
                  }
                  var token = _jsonwebtoken2['default'].sign({ anonymous_id: user._id, product_type: _utilsServerConstants2['default'].ES_PRODUCT_ONESNA, iss: issval }, user.secret, { expiresInSeconds: 60 * 60 * 24 });
                  // res.cookie('AUTH_TOKEN', token);
                  _anonymousEvent2['default'].emitAnonymousCreated(req, user);
                  res.json({ token: token });
              });
          }
      }], [{
          key: 'AUTHENTICATORS',
          value: [],
          enumerable: true
      }]);
  
      return create;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.me = (function (_vw$ViewBase2) {
      _inherits(me, _vw$ViewBase2);
  
      function me() {
          _classCallCheck(this, me);
  
          _get(Object.getPrototypeOf(me.prototype), 'constructor', this).apply(this, arguments);
      }
  
      _createClass(me, [{
          key: 'handle',
          value: function handle(req, res, cb) {
              var userId = req.anonymousUser._id;
              _anonymousModel2['default'].findOne({
                  _id: userId
              }, function (err, user) {
                  // don't ever give out the password or salt
                  if (err) {
                      return next(err);
                  };
                  if (!user) {
                      return res.status(_utilsServerConstants2['default'].HttpUnauthorizedAnonymousStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateErrorAnony4001JWT));
                  }
                  user.secret = undefined;
                  return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send(user);
              });
          }
      }], [{
          key: 'AUTHENTICATORS',
          value: [_authAuthService2['default'].AnonymousAuthenticator],
          enumerable: true
      }]);
  
      return me;
  })(_viewBaseViewBase2['default'].ViewBase);

/***/ },
/* 93 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  //Version 1.0
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _anonymousController = __webpack_require__(92);
  
  var _anonymousController2 = _interopRequireDefault(_anonymousController);
  
  var _authAuthService = __webpack_require__(15);
  
  var _authAuthService2 = _interopRequireDefault(_authAuthService);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var router = new _express.Router();
  
  router.post('/auth', (0, _viewBaseViewBase.asView)(_anonymousController2['default'].create));
  router.get('/me', (0, _viewBaseViewBase.asView)(_anonymousController2['default'].me));
  
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 94 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Using Rails-like standard naming convention for endpoints.
   * GET     /company              ->  index
   * POST    /company              ->  create
   * GET     /company/:id          ->  show
   * PUT     /company/:id          ->  update
   * DELETE  /company/:id          ->  destroy
   */
  
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  // Get list of companies
  var _ = __webpack_require__(11);
  var Company = __webpack_require__(67);
  var logger = __webpack_require__(1);
  exports.index = function (req, res) {
    Company.find(function (err, companies) {
  
      if (err) {
        return handleError(res, err);
      }
      return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(companies);
    });
  };
  
  // Get a single Company
  exports.show = function (req, res) {
    Company.findById(req.params.id, function (err, company) {
      if (err) {
        return handleError(res, err);
      }
      if (!company) {
        return res.status(404).send('Not Found');
      }
      return res.json(company);
    });
  };
  
  // Creates a new Company in the DB.
  exports.create = function (req, res) {
    Company.create(req.body, function (err, company) {
      if (err) {
        return handleError(res, err);
      }
      return res.status(201).json(company);
    });
  };
  
  // Updates an existing Company in the DB.
  exports.update = function (req, res) {
    if (req.body._id) {
      delete req.body._id;
    }
    Company.findById(req.params.id, function (err, company) {
      if (err) {
        return handleError(res, err);
      }
      if (!company) {
        return res.status(404).send('Not Found');
      }
      var updated = _.merge(company, req.body);
      updated.save(function (err) {
        if (err) {
          return handleError(res, err);
        }
        return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(company);
      });
    });
  };
  
  // Deletes a Company from the DB.
  exports.destroy = function (req, res) {
    Company.findById(req.params.id, function (err, company) {
      if (err) {
        return handleError(res, err);
      }
      if (!company) {
        return res.status(404).send('Not Found');
      }
      Company.remove(function (err) {
        if (err) {
          return handleError(res, err);
        }
        return res.status(204).send('No Content');
      });
    });
  };
  
  function handleError(res, err) {
    return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(err);
  }

/***/ },
/* 95 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var util = __webpack_require__(12),
      EventEmitter = process.EventEmitter,
      instance;
  
  function CompanyEvent() {
      EventEmitter.call(this);
  }
  
  util.inherits(CompanyEvent, EventEmitter);
  
  CompanyEvent.prototype.emitCompanyUpdated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('companyUpdated');
      this.emit.apply(this, args);
  };
  
  CompanyEvent.prototype.onCompanyUpdated = function (callback) {
      this.on('companyUpdated', callback);
  };
  
  CompanyEvent.prototype.emitCompanyCreated = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('companyCreated');
      this.emit.apply(this, args);
  };
  
  CompanyEvent.prototype.onCompanyCreated = function (callback) {
      this.on('companyCreated', callback);
  };
  
  CompanyEvent.prototype.emitCompanyDeleted = function () {
      var args = Array.prototype.slice.call(arguments, 0);
      args.unshift('companyDeleted');
      this.emit.apply(this, args);
  };
  
  CompanyEvent.prototype.onCompanyDeleted = function (callback) {
      this.on('companyDeleted', callback);
  };
  
  var exportMe = {
      getInstance: function getInstance() {
          return instance || (instance = new CompanyEvent());
      }
  };
  
  module.exports = exportMe.getInstance();

/***/ },
/* 96 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  //Version 1.0
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _companyController = __webpack_require__(94);
  
  var _companyController2 = _interopRequireDefault(_companyController);
  
  var router = new _express.Router();
  
  router.get('/', _companyController2['default'].index);
  router.get('/:id', _companyController2['default'].show);
  router.post('/', _companyController2['default'].create);
  router.put('/:id', _companyController2['default'].update);
  router.patch('/:id', _companyController2['default'].update);
  router['delete']('/:id', _companyController2['default'].destroy);
  
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 97 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _viewBaseViewBase2 = _interopRequireDefault(_viewBaseViewBase);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _enrollModel = __webpack_require__(69);
  
  var _enrollModel2 = _interopRequireDefault(_enrollModel);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _escapeStringRegexp = __webpack_require__(42);
  
  var _escapeStringRegexp2 = _interopRequireDefault(_escapeStringRegexp);
  
  var _authAuthorizers = __webpack_require__(24);
  
  var _authAuthorizers2 = _interopRequireDefault(_authAuthorizers);
  
  var _enrollEvent = __webpack_require__(68);
  
  var _enrollEvent2 = _interopRequireDefault(_enrollEvent);
  
  var _userUserModel = __webpack_require__(14);
  
  var _userUserModel2 = _interopRequireDefault(_userUserModel);
  
  var _enrollAdminModel = __webpack_require__(80);
  
  var _enrollAdminModel2 = _interopRequireDefault(_enrollAdminModel);
  
  var _modulesAnalyticsGoogle = __webpack_require__(33);
  
  var _modulesAnalyticsGoogle2 = _interopRequireDefault(_modulesAnalyticsGoogle);
  
  var _modulesAnalyticsGoogleConstants = __webpack_require__(32);
  
  var _modulesAnalyticsGoogleConstants2 = _interopRequireDefault(_modulesAnalyticsGoogleConstants);
  
  exports.create = (function (_vw$ViewBase) {
    _inherits(create, _vw$ViewBase);
  
    function create() {
      _classCallCheck(this, create);
  
      _get(Object.getPrototypeOf(create.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(create, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var enrollment = {
          name: req.body.name,
          email: req.body.email
        };
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        function createEnroll(enrollment) {
          _enrollModel2['default'].create(enrollment, function (err, enroll) {
            if (err) {
              if (err.code === 11000) {
                _modulesLogger2['default'].warn(src.id, "An enrollment email/request has already been created", err);
                _enrollModel2['default'].findOne({ email: req.body.email }, function (error, dupEnroll) {
                  if (dupEnroll) {
                    return res.status(400).send({ error: "duplicate key", email: dupEnroll.email, status: dupEnroll.status });
                  } else {
                    _modulesLogger2['default'].error(src.id, "can not get original operation from duplicate error", err);
                    return res.status(400).send({ error: "duplicate key" });
                  }
                });
              } else {
                _modulesLogger2['default'].error(src.id, "Error happends creating enrollment", err);
                return res.status(400).send(err);
              }
            } else {
              if (!enroll) {
                return res.status(400).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
              }
  
              _enrollEvent2['default'].emitEnrollCreated(src, enroll);
              // ga.postEvent({category: gaCst.c_Enroll, action: gaCst.a_newEnroll, label: enroll._id});
              return res.status(200).send(enroll);
            }
          });
        }
  
        if (req.body.email) {
          _enrollModel2['default'].findOne({ "user.emails.value": req.body.email }, function (err, existEnroll) {
            if (err) {
              _modulesLogger2['default'].error(src.id, "Error happends finding enrollment", err);
              return res.status(400).send(err);
            }
            if (!existEnroll) {
              _userUserModel2['default'].findOne({ 'emails.value': req.body.email }, function (err, user) {
                if (err) {
                  _modulesLogger2['default'].error(src.id, "Error happends finding enrollment", err);
                  return res.status(400).send(err);
                }
                if (user) {
                  enrollment.user = user.profile;
                  enrollment.user._id = user._id;
                  enrollment.user.emails = user.emails;
                }
                return createEnroll(enrollment);
              });
            } else {
              return res.status(400).send({ error: "duplicate key", status: existEnroll.status });
            }
          });
        } else {
          return createEnroll(enrollment);
        }
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [],
      enumerable: true
    }, {
      key: 'AUTHENTICATORS',
      value: [],
      enumerable: true
    }]);
  
    return create;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.adminCreateEnroll = (function (_vw$ViewBase2) {
    _inherits(adminCreateEnroll, _vw$ViewBase2);
  
    function adminCreateEnroll() {
      _classCallCheck(this, adminCreateEnroll);
  
      _get(Object.getPrototypeOf(adminCreateEnroll.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(adminCreateEnroll, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var enrollment = {
          name: req.body.name,
          email: req.body.email,
          status: "approved"
        };
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        function createEnroll(enrollment) {
          _enrollModel2['default'].create(enrollment, function (err, enroll) {
            if (err) {
              if (err.code === 11000) {
                _modulesLogger2['default'].warn(src.id, "An enrollment email/request has already been created", enrollment);
                _enrollModel2['default'].findOne({ email: req.body.email }, function (error, dupEnroll) {
                  if (error) {
                    _modulesLogger2['default'].error("Error find enroll", error);
                    return res.status(400).send(error);
                  }
                  if (dupEnroll) {
                    return res.status(400).send({ error: "duplicate key", email: dupEnroll.email, status: dupEnroll.status });
                  } else {
                    _modulesLogger2['default'].error(src.id, "can not get original operation from duplicate error", err);
                    return res.status(400).send({ error: "duplicate key" });
                  }
                });
              } else {
                _modulesLogger2['default'].error(src.id, "Error happends creating enrollment", err);
                return res.status(400).send(err);
              }
            } else if (!enroll) {
              return res.status(400).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
            } else {
              if (enroll.status === "approved") {
                _enrollEvent2['default'].emitEnrollApproved(src, enroll);
              } else {
                _enrollEvent2['default'].emitEnrollCreated(src, enroll);
              }
              return res.status(200).send(enroll);
            }
          });
        }
  
        if (req.body.email) {
          _enrollModel2['default'].findOne({ "user.emails.value": req.body.email }, function (err, existEnroll) {
            if (err) {
              _modulesLogger2['default'].error(src.id, "Error happends finding enrollment", err);
              return res.status(400).send(err);
            }
            if (!existEnroll) {
              _userUserModel2['default'].findOne({ 'emails.value': req.body.email }, function (err, user) {
                if (err) {
                  _modulesLogger2['default'].error(src.id, "Error happends finding enrollment", err);
                  return res.status(400).send(err);
                }
                if (user) {
                  enrollment.user = user.profile;
                  enrollment.user._id = user._id;
                  enrollment.user.emails = user.emails;
                }
                return createEnroll(enrollment);
              });
            } else {
              return res.status(400).send({ error: "duplicate key", email: existEnroll.email, user: existEnroll.user, status: existEnroll.status });
            }
          });
        } else {
          return createEnroll(enrollment);
        }
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [_authAuthorizers2['default'].EnrollAdminAuthorizer],
      enumerable: true
    }]);
  
    return adminCreateEnroll;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.get = (function (_vw$ViewBase3) {
    _inherits(get, _vw$ViewBase3);
  
    function get() {
      _classCallCheck(this, get);
  
      _get(Object.getPrototypeOf(get.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(get, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        _enrollModel2['default'].findById(req.params.enrollId, function (err, enroll) {
          if (err) {
            return res.status(400).send(err);
          }
          if (!enroll) {
            return res.status(400).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          }
          return res.json(enroll);
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [_authAuthorizers2['default'].EnrollAdminAuthorizer],
      enumerable: true
    }]);
  
    return get;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.check = (function (_vw$ViewBase4) {
    _inherits(check, _vw$ViewBase4);
  
    function check() {
      _classCallCheck(this, check);
  
      _get(Object.getPrototypeOf(check.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(check, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        var user = req.user;
        if (!user) {
          //return res.status(400).send(new esErr.ESErrors(esErr.NotExsistedError));
          return res.status(200).send({ hasPermissionToCreateSpace: false });
        }
        _userUserModel2['default'].findOne({ _id: user._id }, { emails: 1 }, function (err, user) {
          var emails = user.emails.map(function (email) {
            return email.value;
          });
          _async2['default'].series([function (callback) {
            _utilsServerHelper2['default'].getDeveloperAdmins(function (admins) {
              if (admins.length > 0) {
                _async2['default'].eachSeries(emails, function (email, cb) {
                  if (_utilsServerHelper2['default'].checkItemInList(email, admins)) {
                    return res.status(200).send({ hasPermissionToCreateSpace: true, hasPermissionToApproveEnrolls: true });
                  }
                  return cb();
                }, function (err) {
                  return callback();
                });
              } else {
                return callback();
              }
            });
          }, function (callback) {
            _utilsServerHelper2['default'].getEnrollAdminEmails(function (enrollAdmins) {
              if (enrollAdmins.length > 0) {
                _async2['default'].eachSeries(emails, function (email, callback) {
                  if (_utilsServerHelper2['default'].checkItemInList(email, enrollAdmins)) {
                    return res.status(200).send({ hasPermissionToCreateSpace: true, hasPermissionToApproveEnrolls: true });
                  }
                  return callback();
                }, function (err, result) {
                  return callback();
                });
              } else {
                return callback();
              }
            });
          }, function (callback) {
            _async2['default'].eachSeries(emails, function (email, cb) {
              if (_utilsServerHelper2['default'].checkZangUser(email)) {
                return res.status(200).send({ hasPermissionToCreateSpace: true });
              }
              return cb();
            }, function (err) {
              return callback();
            });
          }, function (callback) {
            _enrollModel2['default'].findOne({ email: { $in: emails } }, function (err, enroll) {
              if (err) {
                return res.status(400).send(err);
              }
              //if(!enroll) { return res.status(400).send(new esErr.ESErrors(esErr.NotExsistedError)); }
              if (!enroll) {
                return res.status(200).send({ hasPermissionToCreateSpace: false });
              }
              return res.json({ hasPermissionToCreateSpace: enroll.status === 'approved' });
            });
          }], function (err, results) {});
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [],
      enumerable: true
    }]);
  
    return check;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.search = (function (_vw$ViewBase5) {
    _inherits(search, _vw$ViewBase5);
  
    function search() {
      _classCallCheck(this, search);
  
      _get(Object.getPrototypeOf(search.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(search, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        var page = Number(req.query.page) || 1,
            size = Number(req.query.size) || 10,
            size = size > 30 ? 30 : size,
            str,
            status,
            skip = (page - 1) * size,
            limit = size + 1,
            query = {},
            src = _utilsServerHelper2['default'].getSrcFromRequest(req),
            apiRoute = '/api/enrolls/search';
  
        if (req.query) {
          str = req.query.search;
          status = req.query.status;
          if (str || status) {
            query.$and = [];
          }
        }
        if (str) {
          str = (0, _escapeStringRegexp2['default'])(str);
          query.$and.push({
            $or: [{ 'name': { $regex: str, $options: 'i' } }, { 'email': { $regex: str, $options: 'i' } }, { 'user.username': { $regex: str, $options: 'i' } }, { 'user.emails.value': { $regex: str, $options: 'i' } }, { 'user.displayname': { $regex: str, $options: 'i' } }]
          });
        }
        if (status) {
          query.$and.push({ status: status });
        }
  
        _enrollModel2['default'].find(query, {}, { skip: skip, limit: limit, sort: { _id: -1 } }).lean().exec(function (err, enrolls) {
          if (err) {
            return res.status(400).send(err);
          }
          var returnData = {};
          _enrollModel2['default'].count(query, function (err, count) {
            if (enrolls.length === limit) {
              returnData.data = enrolls.slice(0, -1);
              returnData.hasNext = true;
            } else {
              returnData.data = enrolls;
              returnData.hasNext = false;
            }
            if (enrolls.length === 0) {
              returnData.from = (page - 1) * size;
            } else {
              returnData.from = (page - 1) * size + 1;
            }
            returnData.to = (page - 1) * size + returnData.data.length;
  
            if (returnData.hasNext) {
              returnData.nextPageUrl = apiRoute + '?page=' + (page + 1) + '&size=' + size;
              if (str) {
                returnData.nextPageUrl += '&search=' + str;
              }
              if (status) {
                returnData.nextPageUrl += '&status=' + status;
              }
            }
            if (page > 1) {
              returnData.previousPageUrl = apiRoute + '?page=' + (page - 1) + '&size=' + size;
              if (str) {
                returnData.previousPageUrl += '&search=' + str;
              }
              if (status) {
                returnData.previousPageUrl += '&status=' + status;
              }
            }
            returnData.total = count;
            if (req.query.totalCount) {
              _enrollModel2['default'].count({ status: "approved" }, function (err, appCount) {
                _enrollModel2['default'].count({ status: "awaiting" }, function (err, waitCount) {
                  if (appCount) {
                    returnData.totalApproved = appCount;
                  }
                  if (waitCount) {
                    returnData.totalAwaiting = waitCount;
                  }
                  return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(returnData);
                });
              });
            } else {
              return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(returnData);
            }
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [_authAuthorizers2['default'].EnrollAdminAuthorizer],
      enumerable: true
    }]);
  
    return search;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.remove = (function (_vw$ViewBase6) {
    _inherits(remove, _vw$ViewBase6);
  
    function remove() {
      _classCallCheck(this, remove);
  
      _get(Object.getPrototypeOf(remove.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(remove, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        _enrollModel2['default'].findOneAndRemove({ _id: req.params.enrollId }, function (err, enroll) {
          if (err) {
            return res.status(400).send(err);
          }
          if (!enroll) {
            return res.status(200).send();
          }
          return res.status(200).send();
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [_authAuthorizers2['default'].EnrollAdminAuthorizer],
      enumerable: true
    }]);
  
    return remove;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.updateStatus = (function (_vw$ViewBase7) {
    _inherits(updateStatus, _vw$ViewBase7);
  
    function updateStatus() {
      _classCallCheck(this, updateStatus);
  
      _get(Object.getPrototypeOf(updateStatus.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(updateStatus, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        _enrollModel2['default'].findOneAndUpdate({ _id: req.params.enrollId }, req.body, { 'new': true }, function (err, enroll) {
          if (err) {
            return handleError(res, err);
          }
          if (!enroll) {
            return res.status(400).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          }
  
          if (enroll.user) {
            _enrollModel2['default'].update({ "user._id": enroll.user._id }, { $set: { status: enroll.status } }, { multi: true }).lean().exec(function (err, enrolls) {
              if (err) {
                _modulesLogger2['default'].error("update existing enrollments", err);
                return res.status(400).send(err);
              }
              if (enroll.status === "approved") {
                _enrollEvent2['default'].emitEnrollApproved(src, enroll);
              }
              return res.status(200).send(enroll);
            });
          } else {
            if (enroll.status === "approved") {
              _enrollEvent2['default'].emitEnrollApproved(src, enroll);
            }
            return res.status(200).send(enroll);
          }
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [_authAuthorizers2['default'].EnrollAdminAuthorizer],
      enumerable: true
    }]);
  
    return updateStatus;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.addEnrollAdmins = (function (_vw$ViewBase8) {
    _inherits(addEnrollAdmins, _vw$ViewBase8);
  
    function addEnrollAdmins() {
      _classCallCheck(this, addEnrollAdmins);
  
      _get(Object.getPrototypeOf(addEnrollAdmins.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(addEnrollAdmins, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        _enrollAdminModel2['default'].findOneAndUpdate({ group: "enrollAdmins" }, { $addToSet: { emails: req.body.email } }, { 'new': true }, function (err, newList) {
          if (err) {
            return res.status(400).send(err);
          }
          return res.status(200).send(newList);
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [_authAuthorizers2['default'].EnrollAdminAuthorizer],
      enumerable: true
    }]);
  
    return addEnrollAdmins;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.deleteEnrollAdmins = (function (_vw$ViewBase9) {
    _inherits(deleteEnrollAdmins, _vw$ViewBase9);
  
    function deleteEnrollAdmins() {
      _classCallCheck(this, deleteEnrollAdmins);
  
      _get(Object.getPrototypeOf(deleteEnrollAdmins.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(deleteEnrollAdmins, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        _enrollAdminModel2['default'].findOneAndUpdate({ group: "enrollAdmins" }, { $pull: { emails: req.body.email } }, { 'new': true }, function (err, newList) {
          if (err) {
            return res.status(400).send(err);
          }
          return res.status(200).send(newList);
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [_authAuthorizers2['default'].EnrollAdminAuthorizer],
      enumerable: true
    }]);
  
    return deleteEnrollAdmins;
  })(_viewBaseViewBase2['default'].ViewBase);

/***/ },
/* 98 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _enrollController = __webpack_require__(97);
  
  var _enrollController2 = _interopRequireDefault(_enrollController);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var router = new _express.Router();
  
  router.get('/check', (0, _viewBaseViewBase.asView)(_enrollController2['default'].check));
  router.get('/search', (0, _viewBaseViewBase.asView)(_enrollController2['default'].search));
  router.post('/admins/create', (0, _viewBaseViewBase.asView)(_enrollController2['default'].adminCreateEnroll));
  
  router.post('/admins/delete', (0, _viewBaseViewBase.asView)(_enrollController2['default'].deleteEnrollAdmins));
  router.post('/admins/', (0, _viewBaseViewBase.asView)(_enrollController2['default'].addEnrollAdmins));
  
  router.get('/:enrollId', (0, _viewBaseViewBase.asView)(_enrollController2['default'].get));
  router.post('/:enrollId', (0, _viewBaseViewBase.asView)(_enrollController2['default'].updateStatus));
  
  router.post('/', (0, _viewBaseViewBase.asView)(_enrollController2['default'].create));
  
  router['delete']('/:enrollId', (0, _viewBaseViewBase.asView)(_enrollController2['default'].remove));
  
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 99 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _viewBaseViewBase2 = _interopRequireDefault(_viewBaseViewBase);
  
  var _fileBackend = __webpack_require__(54);
  
  var _fileBackend2 = _interopRequireDefault(_fileBackend);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _nodeUuid = __webpack_require__(50);
  
  var _nodeUuid2 = _interopRequireDefault(_nodeUuid);
  
  var _jsonwebtoken = __webpack_require__(29);
  
  var _jsonwebtoken2 = _interopRequireDefault(_jsonwebtoken);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _messageMessageBackend = __webpack_require__(26);
  
  var _messageMessageBackend2 = _interopRequireDefault(_messageMessageBackend);
  
  exports.getUploadUrl = (function (_vw$anyCallView) {
    _inherits(getUploadUrl, _vw$anyCallView);
  
    function getUploadUrl() {
      _classCallCheck(this, getUploadUrl);
  
      _get(Object.getPrototypeOf(getUploadUrl.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(getUploadUrl, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
  
        if (!req.body || !req.body.files) {
          _modulesLogger2['default'].error(src.id, 'Bad request error ');
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
        var data = { files: req.body.files };
        for (var i in data) {
          data[i].fileKey = _nodeUuid2['default'].v4(); //enforce key;
        }
        _fileBackend2['default'].getUploadUrls(src, data, function (err, results) {
          if (err) {
            _modulesLogger2['default'].error(src.id, 'getUploadUrl happen error ', err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].UploadUrlCreateFailed));
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send({ data: results });
        });
      }
    }]);
  
    return getUploadUrl;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  exports.getProfileImageUploadUrl = (function (_vw$anyCallView2) {
    _inherits(getProfileImageUploadUrl, _vw$anyCallView2);
  
    function getProfileImageUploadUrl() {
      _classCallCheck(this, getProfileImageUploadUrl);
  
      _get(Object.getPrototypeOf(getProfileImageUploadUrl.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(getProfileImageUploadUrl, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
  
        if (!req.body || !req.body.files) {
          _modulesLogger2['default'].error(src.id, 'Bad request error ');
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
        var data = { files: req.body.files };
        if (req.anonymousUser) {
          data.user = req.anonymousUser;
        } else if (req.user) {
          data.user = req.user;
        }
  
        _fileBackend2['default'].getProfileImageUploadUrl(src, data, function (err, results) {
          if (err) {
            _modulesLogger2['default'].error(src.id, 'getUploadUrl happen error ', err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].UploadUrlCreateFailed));
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send({ data: results });
        });
      }
    }], [{
      key: 'USECACHE',
      value: false,
      enumerable: true
    }]);
  
    return getProfileImageUploadUrl;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  exports.getDownloadUrl = (function (_vw$anyCallView3) {
    _inherits(getDownloadUrl, _vw$anyCallView3);
  
    function getDownloadUrl() {
      _classCallCheck(this, getDownloadUrl);
  
      _get(Object.getPrototypeOf(getDownloadUrl.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(getDownloadUrl, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
  
        if (!req.body || !req.body.fileKeys) {
          _modulesLogger2['default'].error(src.id, 'getUploadUrl happen error ');
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
        var data = req.body;
        _fileBackend2['default'].getDownloadUrls(src, data, function (err, results) {
          if (err) {
            _modulesLogger2['default'].error(src.id, 'getDownloadUrl happen error ', err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].UploadUrlCreateFailed));
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send({ data: results });
        });
      }
    }]);
  
    return getDownloadUrl;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  exports.getDownloadUrlPublic = (function (_vw$anyCallView4) {
    _inherits(getDownloadUrlPublic, _vw$anyCallView4);
  
    function getDownloadUrlPublic() {
      _classCallCheck(this, getDownloadUrlPublic);
  
      _get(Object.getPrototypeOf(getDownloadUrlPublic.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(getDownloadUrlPublic, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
  
        if (!req.body || !req.body.fileKeys) {
          _modulesLogger2['default'].error(src.id, 'getUploadUrl happen error ');
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
        var data = req.body;
        _fileBackend2['default'].getDownloadUrlsPublic(src, data, function (err, results) {
          if (err) {
            _modulesLogger2['default'].error(src.id, 'getDownloadUrl happen error ', err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].UploadUrlCreateFailed));
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send({ data: results });
        });
      }
    }]);
  
    return getDownloadUrlPublic;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  var verifyTokenPreviewFileUrl = function verifyTokenPreviewFileUrl(src, data, cb) {
    var functionName = '[verifyTokenPreviewFileUrl] ';
    _modulesLogger2['default'].info(src.id, functionName + 'Verify token for preview file Url token=' + data);
    _jsonwebtoken2['default'].verify(data, _config2['default'].secrets.session, function (err, payload) {
      if (err) {
        _modulesLogger2['default'].error(src.id, functionName + 'Verify token for preview file Url token=' + data + ' failed!', err);
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].VerifyJWTFailed));
      } else {
        _modulesLogger2['default'].info(src.id, functionName + 'Verify token for preview file Url token=' + data + ' successfully!');
        return cb(null, payload);
      }
    });
  };
  
  exports.getviewUrls = (function (_vw$ViewBase) {
    _inherits(getviewUrls, _vw$ViewBase);
  
    function getviewUrls() {
      _classCallCheck(this, getviewUrls);
  
      _get(Object.getPrototypeOf(getviewUrls.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(getviewUrls, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var maxlistSize = 50;
        var functionName = '[getviewUrls.handle] ';
        var token = req.params.token;
        var size = _utilsServerHelper2['default'].getListOfItemCaps(req.query.size);
        var offset = parseInt(req.query.offset || 0);
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        _modulesLogger2['default'].info(src.id, functionName + 'Get view urls by token=' + token + ' size=' + size + ' offset=' + offset);
        verifyTokenPreviewFileUrl(src, token, function (err, jwtPlaylod) {
          if (err) {
            _modulesLogger2['default'].warn(src.id, functionName + 'Verify token for preview file Url token=' + token + ' failed!', err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].GetviewUrlsFailed));
          } else {
            jwtPlaylod.offset = offset;
            jwtPlaylod.size = size;
            _messageMessageBackend2['default'].getViewUrls(src, jwtPlaylod, function (err, result) {
              if (err) {
                _modulesLogger2['default'].info(src.id, functionName + 'Get view urls by token=' + token + ' size=' + size + ' offset=' + offset + ' failed!', err);
                return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].GetviewUrlsFailed));
              } else {
                var nextUrl = '';
                var prevUrl = '';
                if (size > 0) {
                  if (result.data.length + jwtPlaylod.offset < result.totalPages) {
                    nextUrl = '/api/files/viewUrls/' + token + '?size=' + size + '&offset=' + (result.data.length + jwtPlaylod.offset);
                  }
                  if (jwtPlaylod.offset > 0) {
                    if (jwtPlaylod.offset - size > 0) {
                      prevUrl = '/api/files/viewUrls/' + token + '?size=' + size + '&offset=' + (jwtPlaylod.offset - size);
                    } else {
                      prevUrl = '/api/files/viewUrls/' + token + '?size=' + size;
                    }
                  }
                }
                result.nextUrl = nextUrl;
                result.prevUrl = prevUrl;
                return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(result);
              }
            });
          }
        });
      }
    }], [{
      key: 'AUTHENTICATORS',
      value: [],
      enumerable: true
    }, {
      key: 'AUTHORIZERS',
      value: [],
      enumerable: true
    }]);
  
    return getviewUrls;
  })(_viewBaseViewBase2['default'].ViewBase);

/***/ },
/* 100 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _fileController = __webpack_require__(99);
  
  var _fileController2 = _interopRequireDefault(_fileController);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var router = new _express.Router();
  
  router.post('/getuploadurl', (0, _viewBaseViewBase.asView)(_fileController2['default'].getUploadUrl));
  router.post('/getProfileImageUploadUrl', (0, _viewBaseViewBase.asView)(_fileController2['default'].getProfileImageUploadUrl));
  router.post('/getdownloadurl', (0, _viewBaseViewBase.asView)(_fileController2['default'].getDownloadUrl));
  router.post('/getdownloadurlPublic', (0, _viewBaseViewBase.asView)(_fileController2['default'].getDownloadUrlPublic));
  router.get('/viewUrls/:token', (0, _viewBaseViewBase.asView)(_fileController2['default'].getviewUrls));
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 101 */
/***/ function(module, exports, __webpack_require__) {

  /**
   *  To provide this backend is because aspose is very good at converting documents to pdf (for example page size process)
   *  But aspose is very expensive to split pdf to svg files and cloudconvert is relatively cheap to split pdf to svg file.
   *  So this backend apply the advantages of these two providers aspose converts documents to pdf.
   *  cloudconvert split pdf to svg files
   */
  
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _fileviewCommon = __webpack_require__(37);
  
  var _fileviewCommon2 = _interopRequireDefault(_fileviewCommon);
  
  var _modulesFile = __webpack_require__(28);
  
  var _modulesFile2 = _interopRequireDefault(_modulesFile);
  
  var _gcloudLibStorage = __webpack_require__(44);
  
  var _gcloudLibStorage2 = _interopRequireDefault(_gcloudLibStorage);
  
  var _modulesFileGcsConfigJs = __webpack_require__(34);
  
  var _modulesFileGcsConfigJs2 = _interopRequireDefault(_modulesFileGcsConfigJs);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _process = __webpack_require__(21);
  
  var _process2 = _interopRequireDefault(_process);
  
  var _request = __webpack_require__(19);
  
  var _request2 = _interopRequireDefault(_request);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _util = __webpack_require__(12);
  
  var _util2 = _interopRequireDefault(_util);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _crypto = __webpack_require__(35);
  
  var _crypto2 = _interopRequireDefault(_crypto);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _messageMessageEvent = __webpack_require__(16);
  
  var _messageMessageEvent2 = _interopRequireDefault(_messageMessageEvent);
  
  var _converter_helper = __webpack_require__(36);
  
  var _converter_helper2 = _interopRequireDefault(_converter_helper);
  
  var excelToSvgFileView = (function (_crtHelp$cloudConvertToSvgFileView) {
    _inherits(excelToSvgFileView, _crtHelp$cloudConvertToSvgFileView);
  
    function excelToSvgFileView() {
      _classCallCheck(this, excelToSvgFileView);
  
      _get(Object.getPrototypeOf(excelToSvgFileView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(excelToSvgFileView, [{
      key: 'toPdf',
      value: function toPdf(inData, cb) {
        var functionName = '[excelToSvgFileView.toPdf] ';
        var fileObj = inData.fileObj;
        var self = this;
        var oriDocument = inData.oriDocument || 'oridocument';
        if (fileObj.pages) {
          _modulesLogger2['default'].info(self.src.id, functionName + 'The slides file already get page number before. pages=' + fileObj.pages);
          return cb(null, fileObj);
        }
        var url = _converter_helper2['default'].getAsposeApiBaseUrl() + 'cells/' + encodeURI(oriDocument + '.' + self.informat) + '/saveAs?' + 'storage=' + encodeURI(_converter_helper2['default'].asposeStorageName) + '&newfilename=' + encodeURI(oriDocument + '.pdf') + '&folder=' + encodeURI('logan/' + self.fileId + '_convert');
        try {
          url = _converter_helper2['default'].asposSign(self.src, url);
        } catch (err) {
          _modulesLogger2['default'].error(self.src.id, functionName + 'When sign aspose url happen error, no retry any more', err);
          self.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusFailed, function () {
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
          });
        }
        var postXmlData = "<PdfSaveOptions><SaveFormat>Pdf</SaveFormat><OnePagePerSheet>True</OnePagePerSheet></PdfSaveOptions>";
        _modulesLogger2['default'].info(self.src.id, functionName + 'Query slides pages by url' + url + " with post xml data" + postXmlData);
        var options = { url: url,
          headers: { "Content-Type": "application/xml" },
          body: postXmlData
        };
        _request2['default'].post(options, function (err, response, body) {
          if (!err && response.statusCode == 200) {
            _modulesLogger2['default'].info(self.src.id, functionName + 'Convert excel to pdf successfully');
            return cb(null, fileObj);
          } else {
            _modulesLogger2['default'].warn(self.src.id, functionName + 'Convert excel to pdf faild', err, response.statusCode, body);
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
          }
        });
      }
    }]);
  
    return excelToSvgFileView;
  })(_converter_helper2['default'].cloudConvertToSvgFileView);
  
  exports['default'] = {
    excelToSvgFileView: excelToSvgFileView
  };
  module.exports = exports['default'];

/***/ },
/* 102 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _fileviewCommon = __webpack_require__(37);
  
  var _fileviewCommon2 = _interopRequireDefault(_fileviewCommon);
  
  var _modulesFile = __webpack_require__(28);
  
  var _modulesFile2 = _interopRequireDefault(_modulesFile);
  
  var _gcloudLibStorage = __webpack_require__(44);
  
  var _gcloudLibStorage2 = _interopRequireDefault(_gcloudLibStorage);
  
  var _modulesFileGcsConfigJs = __webpack_require__(34);
  
  var _modulesFileGcsConfigJs2 = _interopRequireDefault(_modulesFileGcsConfigJs);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _process = __webpack_require__(21);
  
  var _process2 = _interopRequireDefault(_process);
  
  var _request = __webpack_require__(19);
  
  var _request2 = _interopRequireDefault(_request);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _util = __webpack_require__(12);
  
  var _util2 = _interopRequireDefault(_util);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _crypto = __webpack_require__(35);
  
  var _crypto2 = _interopRequireDefault(_crypto);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _messageMessageEvent = __webpack_require__(16);
  
  var _messageMessageEvent2 = _interopRequireDefault(_messageMessageEvent);
  
  var _converter_helper = __webpack_require__(36);
  
  var _converter_helper2 = _interopRequireDefault(_converter_helper);
  
  var PdfToSvgFileView = (function (_fileViewCommon$FileViewer) {
    _inherits(PdfToSvgFileView, _fileViewCommon$FileViewer);
  
    function PdfToSvgFileView() {
      _classCallCheck(this, PdfToSvgFileView);
  
      _get(Object.getPrototypeOf(PdfToSvgFileView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(PdfToSvgFileView, [{
      key: 'cleanWork',
      value: function cleanWork(cb) {
        var functionName = '[PdfToSvgFileView.cleanWork] ';
        _modulesLogger2['default'].info(this.src.id, functionName + 'Begin do clean work');
        var self = this;
        _async2['default'].waterfall([function (interCallback) {
          if (self.convertedFileObj) {
            (function () {
              var convertStatus = self.convertedFileObj.convertStatus || 0;
              if (convertStatus == _utilsServerConstants2['default'].ConvertStatusSuccess || convertStatus == _utilsServerConstants2['default'].ConvertStatusFailed) {
                _modulesLogger2['default'].info(self.src.id, functionName + 'Update all files in topic message with fileId=' + self.fileId + ' with status=' + convertStatus);
                _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].update, self.src.id, { 'content.data.fileId': self.fileId }, { '$set': { 'content.data.$.metaData': { pages: self.convertedFileObj.pages },
                    'content.data.$.convertStatus': convertStatus,
                    'content.data.$.thumbnailFile': self.fileId + '_convert/page_1.svg',
                    'modified': Date.now() } }, { multi: true, 'new': true }, function (err, updateResults) {
                  if (err) {
                    _modulesLogger2['default'].error(self.src.id, functionName + 'Update all files with same fileId failed', err);
                    return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ConvertFileCleanWorkFailed));
                  } else {
                    if (convertStatus == _utilsServerConstants2['default'].ConvertStatusSuccess) {
                      _converter_helper2['default'].notifyClientsMessageUpdate(self.src, self);
                    }
                  }
                });
              }
            })();
          }
          return interCallback(null);
        }, function (interCallback) {
          _converter_helper2['default'].removeTempfolder(self.src, self, function (err) {
            if (err) {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Remove temp folder failed', err);
            } else {
              _modulesLogger2['default'].info(self.src.id, functionName + 'Remove temp folder failed successfully');
            }
            return cb(err);
          });
        }], function (err, result) {});
      }
    }, {
      key: 'convert',
      value: function convert(cb) {
        var self = this;
        var functionName = '[PdfToSvgFileView.convert] ';
        var endRequestForRequestEndSoon = false;
        _async2['default'].waterfall([
        //Query file information from database
        function (interCallback) {
          _modulesLogger2['default'].info(self.src.id, functionName + 'Get file object from message by messageId=' + self.messageId + ' fileId=' + self.fileId + '.');
          _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].findOne, self.src.id, { '_id': self.messageId,
            'content.data.fileId': self.fileId }, { "content.data.$": 1 }, function (err, msgObj) {
            if (!err && msgObj) {
              _modulesLogger2['default'].info(self.src.id, functionName + 'Get file object from message by messageId=' + self.messageId + ' fileId=' + self.fileId + ' successfully.');
              return interCallback(err, msgObj.content.data[0].toJSON());
            }
            _modulesLogger2['default'].info(self.src.id, functionName + 'Get file object from message by messageId=' + self.messageId + ' fileId=' + self.fileId + ' failed.', err);
            return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
          });
        },
        //copy the file to that folder
        function (fileObj, interCallback) {
          self.convertedFileObj = fileObj;
          if (fileObj.metaData && fileObj.metaData.paging) {
            _modulesLogger2['default'].info(self.src.id, functionName + 'The file already converted ' + fileObj.metaData.paging + ' pages');
            return interCallback(null, fileObj);
          }
          _modulesLogger2['default'].info(self.src.id, functionName + 'Copy file to temp convert folder with bucket=' + _modulesFileGcsConfigJs2['default'].tempExtneralBucket + ' Folder=logan/' + self.fileId + '_convert/');
          _modulesFile2['default'].copyFile(self.src, {
            srcBucketName: _modulesFileGcsConfigJs2['default'].bucket,
            srcFileName: self.fileId,
            destBucketName: _modulesFileGcsConfigJs2['default'].tempExtneralBucket,
            destFileName: self.fileId + '_convert/' + self.fileId
          }, function (err, result) {
            if (err) {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Copy file failed', err);
            } else {
              _modulesLogger2['default'].info(self.src.id, functionName + 'Copy file successfully');
            }
            return interCallback(err, fileObj);
          });
        },
        //get the page number of the pdf
        function (fileObj, interCallback) {
          if (fileObj.pages) {
            _modulesLogger2['default'].info(self.src.id, functionName + 'The pdf file already get page number before. pages=' + fileObj.pages);
            return interCallback(null, fileObj);
          }
          var url = _converter_helper2['default'].getAsposeApiBaseUrl() + 'pdf/' + encodeURI(self.fileId) + '/pages?' + 'folder=' + encodeURI('logan/' + self.fileId + '_convert') + '&storage=' + encodeURI(_converter_helper2['default'].asposeStorageName);
          try {
            url = _converter_helper2['default'].asposSign(self.src, url);
          } catch (err) {
            _modulesLogger2['default'].error(self.src.id, functionName + 'When sign aspose url happen error, no retry any more', err);
            self.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusFailed, function () {
              return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
            });
          }
          _modulesLogger2['default'].info(self.src.id, functionName + 'Query pdf pages by url' + url);
          var options = { url: url, json: true };
          _request2['default'].get(options, function (err, response, body) {
            if (!err && response.statusCode == 200) {
              (function () {
                var pages = 0;
                if (body && body.Pages && body.Pages.List) {
                  pages = body.Pages.List.length;
                }
                _modulesLogger2['default'].info(self.src.id, functionName + 'Query pdf pages by url' + url + ' successfully with data:', body);
                _converter_helper2['default'].setPagesToMetaData(self.src, self.messageId, self.fileId, pages, function (err, result) {
                  if (err) {
                    _modulesLogger2['default'].error(self.src.id, functionName + 'Set page to file failed', err);
                    return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                  } else {
                    _modulesLogger2['default'].info(self.src.id, functionName + 'Set page to file successfully');
                    fileObj.pages = pages;
                    return interCallback(null, fileObj);
                  }
                });
              })();
            } else {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Query pdf pages by url' + url + ' faild', err, response.statusCode, body);
              return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
            }
          });
        },
        //use aspose api split document into doc for every 5 pages
        function (fileObj, interCallback) {
          var currentPage = fileObj.metaData.paging || 0;
          var pages = fileObj.pages;
          var stepPage = 5;
          _async2['default'].whilst(function () {
            _converter_helper2['default'].setPagingToMetaData(self.src, self.messageId, self.fileId, currentPage, function (err) {
              if (err) {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'Set paging of convert progress failed', err);
              }
            });
            if (_utilsServerHelper2['default'].requestWillEndSoon(self.src)) {
              _modulesLogger2['default'].info(self.src.id, 'This request will end soon, create another taskqueue to continue working');
              endRequestForRequestEndSoon = true;
              return false;
            }
            return currentPage + 1 <= pages;
          }, function (interCallback2) {
            var startPage = currentPage + 1;
            if (startPage > pages) {
              return interCallback2(null, currentPage);
            }
            var endPage = currentPage + stepPage;
            if (endPage > pages) {
              endPage = pages;
            }
            currentPage = endPage;
            var url = _converter_helper2['default'].getAsposeApiBaseUrl() + 'pdf/' + encodeURI(self.fileId) + '/split?' + 'format=' + encodeURI('doc') + '&from=' + startPage + '&to=' + endPage + '&folder=' + encodeURI('logan/' + self.fileId + '_convert') + '&storage=' + encodeURI(_converter_helper2['default'].asposeStorageName);
            try {
              url = _converter_helper2['default'].asposSign(self.src, url);
            } catch (err) {
              _modulesLogger2['default'].error(self.src.id, functionName + 'When sign aspose url happen error, no retry any more', err);
              self.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusFailed, function () {
                return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
              });
            }
            _modulesLogger2['default'].info(self.src.id, functionName + 'Split pdf into docs by url' + url);
            var options = { url: url, json: true };
            _request2['default'].post(options, function (err, response, body) {
              if (!err && response.statusCode == 200) {
                _modulesLogger2['default'].info(self.src.id, functionName + 'Split pdf document into docs by url' + url + ' successfully', body);
                //use aspose api convert doc page to svg
                var docsToSvgUrls = [];
                if (body.Result && body.Result.Documents) {
                  for (var docIdx in body.Result.Documents) {
                    var docItem = body.Result.Documents[docIdx];
                    var href = docItem.Href;
                    var cutPos = href.lastIndexOf('/');
                    var docfileName = href.substring(cutPos + 1);
                    var docfileNamePage = 'page_' + (parseInt(startPage) + parseInt(docIdx)).toString() + '.svg';
                    var _url = _converter_helper2['default'].getAsposeApiBaseUrl() + 'words/' + encodeURI(docfileName) + '?format=svg' + '&folder=' + encodeURI('logan/' + self.fileId + '_convert') + '&storage=' + encodeURI(_converter_helper2['default'].asposeStorageName) + '&outPath=' + encodeURI('logan/' + self.fileId + '_convert/' + docfileNamePage);
                    try {
                      _url = _converter_helper2['default'].asposSign(self.src, _url);
                    } catch (err) {
                      _modulesLogger2['default'].error(self.src.id, functionName + 'When sign aspose url happen error, no retry any more', err);
                      self.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusFailed, function () {
                        return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
                      });
                    }
                    docsToSvgUrls.push(_url);
                  }
                }
                //convert docs to svgs
                _async2['default'].forEachOf(docsToSvgUrls, function (url, key, interCallback3) {
                  var options = { url: url, json: true };
                  _modulesLogger2['default'].info(self.src.id, functionName + 'Convert doc to svg by url' + url);
                  _request2['default'].get(options, function (err, response, body) {
                    if (!err && response.statusCode == 200) {
                      _modulesLogger2['default'].info(self.src.id, functionName + 'Convert doc to svg by url' + url + ' successfully!');
                      return interCallback3(null);
                    } else {
                      _modulesLogger2['default'].error(self.src.id, functionName + 'Convert doc to svg by url' + url + ' faild!', err, response.statusCode, body);
                      return interCallback3(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                    }
                  });
                }, function (err) {
                  if (err) {
                    _modulesLogger2['default'].warn(self.src.id, functionName + 'Convert docs to svgs failed');
                    return interCallback2(err);
                  } else {
                    _modulesLogger2['default'].info(self.src.id, functionName + 'Convert docs to svgs success');
                    return interCallback2(null, endPage);
                  }
                });
              } else {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'Split pdf document into docs by url' + url + ' faild', err, response.statusCode, body);
                return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
              }
            });
          }, function (err, n) {
            if (err) {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Convert to svg page by page happen error', err);
            }
            return interCallback(err, fileObj);
          });
        },
        //Copy converted folder back to real official folder
        function (fileObj, interCallback) {
          _modulesLogger2['default'].info(self.src.id, functionName + 'List all svg files from converted folder');
          _modulesFile2['default'].listFiles(self.src, { bucketName: _modulesFileGcsConfigJs2['default'].tempExtneralBucket,
            prefix: self.fileId + '_convert/page_'
          }, function (err, results) {
            _modulesLogger2['default'].info(self.src.id, functionName + 'List all svg files from converted folder with files number=' + results.length);
            if (results.length < fileObj.pages) {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Happen some errors for list pages. pagenumber should be ' + fileObj.pages);
              return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
            }
            _async2['default'].forEachOf(results, function (aSrcFile, idx, interCallback2) {
              var cutPosString = 'logan/';
              var cutPos = aSrcFile.metadata.name.indexOf(cutPosString);
              var path = null;
              if (cutPos >= 0) {
                path = aSrcFile.metadata.name.substring(cutPos + cutPosString.length);
              } else {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'Failed to get path from name=' + aSrcFile.metadata.name);
              }
              if (path) {
                _modulesLogger2['default'].info(self.src.id, functionName + 'Will copy file to bucket=' + _modulesFileGcsConfigJs2['default'].bucket + ' path=' + path);
                _modulesFile2['default'].createFileObj(self.src, { bucketName: _modulesFileGcsConfigJs2['default'].bucket,
                  path: path
                }, function (err, destFileObj) {
                  aSrcFile.copy(destFileObj, function (err, result) {
                    if (err) {
                      _modulesLogger2['default'].warn(self.src.id, functionName + 'Copy file failed', err);
                      return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                    }
                    result.setMetadata({ contentType: 'image/svg+xml' }, function (err, apiResponse) {
                      if (err) {
                        _modulesLogger2['default'].error(self.src.id, functionName + 'Set mimetype image/svg+xml failed', err);
                        return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                      } else {
                        return interCallback2(null);
                      }
                    });
                  });
                });
              } else {
                return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
              }
            }, function (err) {
              if (err) {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'Copy converted file back to real folder happen error', err);
              } else {
                _modulesLogger2['default'].info(self.src.id, functionName + 'Copy converted file back to real folder successfully');
              }
              return interCallback(err, fileObj);
            });
          });
        }], function (err, result) {
          if (endRequestForRequestEndSoon) {
            _fileviewCommon2['default'].endRequestAndLauchAnotherDefer(self.src, self, function (err) {
              return cb(err);
            });
          } else {
            return cb(err, result);
          }
        });
      }
    }]);
  
    return PdfToSvgFileView;
  })(_fileviewCommon2['default'].FileViewer);
  
  var pptToSvgFileView = (function (_fileViewCommon$FileViewer2) {
    _inherits(pptToSvgFileView, _fileViewCommon$FileViewer2);
  
    function pptToSvgFileView() {
      _classCallCheck(this, pptToSvgFileView);
  
      _get(Object.getPrototypeOf(pptToSvgFileView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(pptToSvgFileView, [{
      key: 'cleanWork',
      value: function cleanWork(cb) {
        var functionName = '[pptToSvgFileView.cleanWork] ';
        _modulesLogger2['default'].info(this.src.id, functionName + 'Begin do clean work');
        var self = this;
        _async2['default'].waterfall([function (interCallback) {
          if (self.convertedFileObj) {
            (function () {
              var convertStatus = self.convertedFileObj.convertStatus || 0;
              if (convertStatus == _utilsServerConstants2['default'].ConvertStatusSuccess || convertStatus == _utilsServerConstants2['default'].ConvertStatusFailed) {
                _modulesLogger2['default'].info(self.src.id, functionName + 'Update all files in topic message with fileId=' + self.fileId + ' with status=' + convertStatus);
                _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].update, self.src.id, { 'content.data.fileId': self.fileId }, { '$set': { 'content.data.$.metaData': { pages: self.convertedFileObj.pages },
                    'content.data.$.convertStatus': convertStatus,
                    'content.data.$.thumbnailFile': self.fileId + '_convert/page_1.svg',
                    'modified': Date.now() } }, { multi: true, 'new': true }, function (err, updateResults) {
                  if (err) {
                    _modulesLogger2['default'].error(self.src.id, functionName + 'Update all files with same fileId failed', err);
                    return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ConvertFileCleanWorkFailed));
                  } else {
                    if (convertStatus == _utilsServerConstants2['default'].ConvertStatusSuccess) {
                      _converter_helper2['default'].notifyClientsMessageUpdate(self.src, self);
                    }
                  }
                });
              }
            })();
          }
          return interCallback(null);
        }, function (interCallback) {
          _converter_helper2['default'].removeTempfolder(self.src, self, function (err) {
            if (err) {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Remove temp folder failed', err);
            } else {
              _modulesLogger2['default'].info(self.src.id, functionName + 'Remove temp folder failed successfully');
            }
            return cb(err);
          });
        }], function (err, result) {});
      }
    }, {
      key: 'convert',
      value: function convert(cb) {
        var self = this;
        var functionName = '[pptToSvgFileView.convert] ';
        var endRequestForRequestEndSoon = false;
        _async2['default'].waterfall([
        //Query file information from database
        function (interCallback) {
          _modulesLogger2['default'].info(self.src.id, _util2['default'].format(functionName + 'Get file object from message by messageId=%s fileId=%s.', self.messageId, self.fileId));
          _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].findOne, self.src.id, { '_id': self.messageId,
            'content.data.fileId': self.fileId }, { "content.data.$": 1 }, function (err, msgObj) {
            if (!err && msgObj) {
              _modulesLogger2['default'].info(self.src.id, _util2['default'].format(functionName + 'Get file object from message by messageId=%s fileId=%s successfully.', self.messageId, self.fileId));
              return interCallback(err, msgObj.content.data[0].toJSON());
            }
            _modulesLogger2['default'].info(self.src.id, _util2['default'].format(functionName + 'Get file object from message by messageId=%s fileId=%s failed.', self.messageId, self.fileId), err);
            return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
          });
        },
        //copy the file to that folder
        function (fileObj, interCallback) {
          self.convertedFileObj = fileObj;
          if (fileObj.metaData && fileObj.metaData.paging) {
            _modulesLogger2['default'].info(self.src.id, functionName + 'The file already converted ' + fileObj.metaData.paging + ' pages');
            return interCallback(null, fileObj);
          }
          _modulesLogger2['default'].info(self.src.id, functionName + 'Copy file to temp convert folder with bucket=' + _modulesFileGcsConfigJs2['default'].tempExtneralBucket + ' Folder=logan/' + self.fileId + '_convert/');
          _modulesFile2['default'].copyFile(self.src, {
            srcBucketName: _modulesFileGcsConfigJs2['default'].bucket,
            srcFileName: self.fileId,
            destBucketName: _modulesFileGcsConfigJs2['default'].tempExtneralBucket,
            destFileName: self.fileId + '_convert/' + self.fileId
          }, function (err, result) {
            if (err) {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Copy file failed', err);
            } else {
              _modulesLogger2['default'].info(self.src.id, functionName + 'Copy file successfully');
            }
            return interCallback(err, fileObj);
          });
        },
        //get the page number of the slides
        function (fileObj, interCallback) {
          if (fileObj.pages) {
            _modulesLogger2['default'].info(self.src.id, functionName + 'The slides file already get page number before. pages=' + fileObj.pages);
            return interCallback(null, fileObj);
          }
          var url = _converter_helper2['default'].getAsposeApiBaseUrl() + 'slides/' + encodeURI(self.fileId) + '/slides?' + 'folder=' + encodeURI('logan/' + self.fileId + '_convert') + '&storage=' + encodeURI(_converter_helper2['default'].asposeStorageName);
          try {
            url = _converter_helper2['default'].asposSign(self.src, url);
          } catch (err) {
            _modulesLogger2['default'].error(self.src.id, functionName + 'When sign aspose url happen error, no retry any more', err);
            self.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusFailed, function () {
              return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
            });
          }
          _modulesLogger2['default'].info(self.src.id, functionName + 'Query slides pages by url' + url);
          var options = { url: url, json: true };
          _request2['default'].get(options, function (err, response, body) {
            if (!err && response.statusCode == 200) {
              (function () {
                var pages = 0;
                if (body && body.Slides && body.Slides.SlideList) {
                  pages = body.Slides.SlideList.length;
                }
                _modulesLogger2['default'].info(self.src.id, functionName + 'Query slides pages by url' + url + ' successfully with data:', body);
                _converter_helper2['default'].setPagesToMetaData(self.src, self.messageId, self.fileId, pages, function (err, result) {
                  if (err) {
                    _modulesLogger2['default'].error(self.src.id, functionName + 'Set page to file failed', err);
                    return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                  } else {
                    _modulesLogger2['default'].info(self.src.id, functionName + 'Set page to file successfully');
                    fileObj.pages = pages;
                    return interCallback(null, fileObj);
                  }
                });
              })();
            } else {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Query slides pages by url' + url + ' faild', err, response.statusCode, body);
              return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
            }
          });
        },
        //use aspose api split document into doc for every 5 pages
        function (fileObj, interCallback) {
          var currentPage = fileObj.metaData.paging || 0;
          var pages = fileObj.pages;
          var stepPage = 5;
          _async2['default'].whilst(function () {
            _converter_helper2['default'].setPagingToMetaData(self.src, self.messageId, self.fileId, currentPage, function (err) {
              if (err) {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'Set paging of convert progress failed', err);
              }
            });
            if (_utilsServerHelper2['default'].requestWillEndSoon(self.src)) {
              _modulesLogger2['default'].info(self.src.id, 'This request will end soon, create another taskqueue to continue working');
              endRequestForRequestEndSoon = true;
              return false;
            }
            return currentPage + 1 <= pages;
          }, function (interCallback2) {
            var startPage = currentPage + 1;
            if (startPage > pages) {
              return interCallback2(null, currentPage);
            }
            var endPage = currentPage + stepPage;
            if (endPage > pages) {
              endPage = pages;
            }
            currentPage = endPage;
            var url = _converter_helper2['default'].getAsposeApiBaseUrl() + 'slides/' + encodeURI(self.fileId) + '/split?' + 'format=' + encodeURI('pdf') + '&from=' + startPage + '&to=' + endPage + '&folder=' + encodeURI('logan/' + self.fileId + '_convert') + '&storage=' + encodeURI(_converter_helper2['default'].asposeStorageName) + '&destFolder=' + encodeURI('logan/' + self.fileId + '_convert');
            try {
              url = _converter_helper2['default'].asposSign(self.src, url);
            } catch (err) {
              _modulesLogger2['default'].error(self.src.id, functionName + 'When sign aspose url happen error, no retry any more', err);
              self.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusFailed, function () {
                return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
              });
            }
            _modulesLogger2['default'].info(self.src.id, functionName + 'Split slides into pdfs by url' + url);
            var options = { url: url, json: true };
            _request2['default'].post(options, function (err, response, body) {
              if (!err && response.statusCode == 200) {
                _modulesLogger2['default'].info(self.src.id, functionName + 'Split slides document into pdfs by url' + url + ' successfully', body);
                //use aspose api convert pdf page to doc
                var docsToSvgUrls = [];
                if (body.SplitResult && body.SplitResult.Slides) {
                  for (var docIdx in body.SplitResult.Slides) {
                    var docItem = body.SplitResult.Slides[docIdx];
                    var href = docItem.Href;
                    var cutPos = href.lastIndexOf('/');
                    var docfileName = href.substring(cutPos + 1);
                    var pageNumber = parseInt(startPage) + parseInt(docIdx);
                    var _url2 = _converter_helper2['default'].getAsposeApiBaseUrl() + 'pdf/' + encodeURI(docfileName) + '/split?format=doc' + '&folder=' + encodeURI('logan/' + self.fileId + '_convert') + '&storage=' + encodeURI(_converter_helper2['default'].asposeStorageName);
                    try {
                      _url2 = _converter_helper2['default'].asposSign(self.src, _url2);
                    } catch (err) {
                      _modulesLogger2['default'].error(self.src.id, functionName + 'When sign aspose url happen error, no retry any more', err);
                      self.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusFailed, function () {
                        return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
                      });
                    }
                    docsToSvgUrls.push({ url: _url2, pageNumber: pageNumber });
                  }
                }
                //convert pdfs to docs
                _async2['default'].forEachOf(docsToSvgUrls, function (urlObj, key, interCallback3) {
                  var options = { url: urlObj.url, json: true };
                  _modulesLogger2['default'].info(self.src.id, functionName + 'Convert pdf to doc by url ' + urlObj.url);
                  _request2['default'].post(options, function (err, response, body) {
                    if (!err && response.statusCode == 200) {
                      (function () {
                        _modulesLogger2['default'].info(self.src.id, functionName + 'Convert pdf to doc by url ' + urlObj.url + ' successfully!');
                        //Convert doc to svg
                        var href = body.Result.Documents[0].Href;
                        var cutPos = href.lastIndexOf('/');
                        var docfileName = href.substring(cutPos + 1);
                        var docfileNamePage = 'page_' + urlObj.pageNumber.toString() + '.svg';
                        var url = _converter_helper2['default'].getAsposeApiBaseUrl() + 'words/' + encodeURI(docfileName) + '?format=svg' + '&folder=' + encodeURI('logan/' + self.fileId + '_convert') + '&storage=' + encodeURI(_converter_helper2['default'].asposeStorageName) + '&outPath=' + encodeURI('logan/' + self.fileId + '_convert/' + docfileNamePage);
                        try {
                          url = _converter_helper2['default'].asposSign(self.src, url);
                        } catch (err) {
                          _modulesLogger2['default'].error(self.src.id, functionName + 'When sign aspose url happen error, no retry any more', err);
                          self.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusFailed, function () {
                            return interCallback3(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
                          });
                        }
                        var options = { url: url, json: true };
                        _modulesLogger2['default'].info(self.src.id, functionName + 'Convert doc to svg by url' + url);
                        _request2['default'].get(options, function (err, response, body) {
                          if (!err && response.statusCode == 200) {
                            _modulesLogger2['default'].info(self.src.id, functionName + 'Convert doc to svg by url' + url + ' successfully!');
                            return interCallback3(null);
                          } else {
                            _modulesLogger2['default'].error(self.src.id, functionName + 'Convert doc to svg by url' + url + ' faild!', err, response.statusCode, body);
                            return interCallback3(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                          }
                        });
                      })();
                    } else {
                      _modulesLogger2['default'].error(self.src.id, functionName + 'Convert pdf to doc by url' + urlObj.url + ' faild!', err, response.statusCode, body);
                      return interCallback3(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                    }
                  });
                }, function (err) {
                  if (err) {
                    _modulesLogger2['default'].warn(self.src.id, functionName + 'Convert docs to svgs failed');
                    return interCallback2(err);
                  } else {
                    _modulesLogger2['default'].info(self.src.id, functionName + 'Convert docs to svgs success');
                    return interCallback2(null, endPage);
                  }
                });
              } else {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'Split slides document into pdfs by url' + url + ' faild', err, response.statusCode, body);
                return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
              }
            });
          }, function (err, n) {
            if (err) {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Convert to svg page by page happen error', err);
            }
            return interCallback(err, fileObj);
          });
        },
        //Copy converted folder back to real official folder
        function (fileObj, interCallback) {
          _modulesLogger2['default'].info(self.src.id, functionName + 'List all svg files from converted folder');
          _modulesFile2['default'].listFiles(self.src, { bucketName: _modulesFileGcsConfigJs2['default'].tempExtneralBucket,
            prefix: self.fileId + '_convert/page_'
          }, function (err, results) {
            _modulesLogger2['default'].info(self.src.id, functionName + 'List all svg files from converted folder with files number=' + results.length);
            if (results.length < fileObj.pages) {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Happen some errors for list pages. pagenumber should be ' + fileObj.pages);
              return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
            }
            _async2['default'].forEachOf(results, function (aSrcFile, idx, interCallback2) {
              var cutPosString = 'logan/';
              var cutPos = aSrcFile.metadata.name.indexOf(cutPosString);
              var path = null;
              if (cutPos >= 0) {
                path = aSrcFile.metadata.name.substring(cutPos + cutPosString.length);
              } else {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'Failed to get path from name=' + aSrcFile.metadata.name);
              }
              if (path) {
                _modulesLogger2['default'].info(self.src.id, functionName + 'Will copy file to bucket=' + _modulesFileGcsConfigJs2['default'].bucket + ' path=' + path);
                _modulesFile2['default'].createFileObj(self.src, { bucketName: _modulesFileGcsConfigJs2['default'].bucket,
                  path: path
                }, function (err, destFileObj) {
                  aSrcFile.copy(destFileObj, function (err, result) {
                    if (err) {
                      _modulesLogger2['default'].warn(self.src.id, functionName + 'Copy file failed', err);
                      return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                    }
                    result.setMetadata({ contentType: 'image/svg+xml' }, function (err, apiResponse) {
                      if (err) {
                        _modulesLogger2['default'].error(self.src.id, functionName + 'Set mimetype image/svg+xml failed', err);
                        return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                      } else {
                        return interCallback2(null);
                      }
                    });
                  });
                });
              } else {
                return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
              }
            }, function (err) {
              if (err) {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'Copy converted file back to real folder happen error', err);
              } else {
                _modulesLogger2['default'].info(self.src.id, functionName + 'Copy converted file back to real folder successfully');
              }
              return interCallback(err, fileObj);
            });
          });
        }], function (err, result) {
          if (endRequestForRequestEndSoon) {
            _fileviewCommon2['default'].endRequestAndLauchAnotherDefer(self.src, self, function (err) {
              return cb(err);
            });
          } else {
            return cb(err, result);
          }
        });
      }
    }]);
  
    return pptToSvgFileView;
  })(_fileviewCommon2['default'].FileViewer);
  
  var docToSvgFileView = (function (_fileViewCommon$FileViewer3) {
    _inherits(docToSvgFileView, _fileViewCommon$FileViewer3);
  
    function docToSvgFileView() {
      _classCallCheck(this, docToSvgFileView);
  
      _get(Object.getPrototypeOf(docToSvgFileView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(docToSvgFileView, [{
      key: 'cleanWork',
      value: function cleanWork(cb) {
        var functionName = '[docToSvgFileView.cleanWork] ';
        _modulesLogger2['default'].info(this.src.id, functionName + 'Begin do clean work');
        var self = this;
        _async2['default'].waterfall([function (interCallback) {
          if (self.convertedFileObj) {
            (function () {
              var convertStatus = self.convertedFileObj.convertStatus || 0;
              if (convertStatus == _utilsServerConstants2['default'].ConvertStatusSuccess || convertStatus == _utilsServerConstants2['default'].ConvertStatusFailed) {
                _modulesLogger2['default'].info(self.src.id, functionName + 'Update all files in topic message with fileId=' + self.fileId + ' with status=' + convertStatus);
                _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].update, self.src.id, { 'content.data.fileId': self.fileId }, { '$set': {
                    'content.data.$.convertStatus': convertStatus,
                    'content.data.$.thumbnailFile': self.fileId + '_convert/page_1.svg',
                    'modified': Date.now() } }, { multi: true, 'new': true }, function (err, updateResults) {
                  if (err) {
                    _modulesLogger2['default'].error(self.src.id, functionName + 'Update all files with same fileId failed', err);
                    return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ConvertFileCleanWorkFailed));
                  } else {
                    if (convertStatus == _utilsServerConstants2['default'].ConvertStatusSuccess) {
                      _converter_helper2['default'].notifyClientsMessageUpdate(self.src, self);
                    }
                  }
                });
              }
            })();
          }
          return interCallback(null);
        }, function (interCallback) {
          _converter_helper2['default'].removeTempfolder(self.src, self, function (err) {
            if (err) {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Remove temp folder failed', err);
            } else {
              _modulesLogger2['default'].info(self.src.id, functionName + 'Remove temp folder failed successfully');
            }
            return cb(err);
          });
        }], function (err, result) {});
      }
    }, {
      key: 'convert',
      value: function convert(cb) {
        var self = this;
        var functionName = '[docToSvgFileView.convert] ';
        var endRequestForRequestEndSoon = false;
        var oridocname = 'OriginalDoc';
        _async2['default'].waterfall([function (interCallback) {
          //Query file information from database
          _modulesLogger2['default'].info(self.src.id, _util2['default'].format('%sGet file object from message by messageId=%s fileId=%s.', functionName, self.messageId, self.fileId));
          _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].findOne, self.src.id, { '_id': self.messageId,
            'content.data.fileId': self.fileId }, { "content.data.$": 1 }, function (err, msgObj) {
            if (!err && msgObj) {
              _modulesLogger2['default'].info(self.src.id, _util2['default'].format('%sGet file object from message by messageId=%s fileId=%s successfully.', functionName, self.messageId, self.fileId));
              return interCallback(err, msgObj.content.data[0].toJSON());
            }
            _modulesLogger2['default'].info(self.src.id, _util2['default'].format('%sGet file object from message by messageId=%s fileId=%s failed.', functionName, self.messageId, self.fileId), err);
            return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
          });
        },
        //copy the file to that folder
        function (fileObj, interCallback) {
          self.convertedFileObj = fileObj;
          if (fileObj.metaData && fileObj.metaData.paging) {
            _modulesLogger2['default'].info(self.src.id, functionName + 'The file already converted ' + fileObj.metaData.paging + ' pages');
            return interCallback(null, fileObj);
          }
          _modulesLogger2['default'].info(self.src.id, functionName + 'Copy file to temp convert folder with bucket=' + _modulesFileGcsConfigJs2['default'].tempExtneralBucket + ' Folder=logan/' + self.fileId + '_convert/');
          _modulesFile2['default'].copyFile(self.src, {
            srcBucketName: _modulesFileGcsConfigJs2['default'].bucket,
            srcFileName: self.fileId,
            destBucketName: _modulesFileGcsConfigJs2['default'].tempExtneralBucket,
            destFileName: self.fileId + '_convert/' + oridocname
          }, function (err, result) {
            if (err) {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Copy file failed', err);
            } else {
              _modulesLogger2['default'].info(self.src.id, functionName + 'Copy file successfully');
            }
            return interCallback(err, fileObj);
          });
        },
        //get the page number of the doc
        function (fileObj, interCallback) {
          if (fileObj.pages) {
            _modulesLogger2['default'].info(self.src.id, functionName + 'The doc file already get page number before. pages=' + fileObj.pages);
            return interCallback(null, fileObj);
          }
          var url = _converter_helper2['default'].getAsposeApiBaseUrl() + 'words/' + encodeURI(oridocname) + '/statistics?' + 'folder=' + encodeURI('logan/' + self.fileId + '_convert') + '&storage=' + encodeURI(_converter_helper2['default'].asposeStorageName);
          try {
            url = _converter_helper2['default'].asposSign(self.src, url);
          } catch (err) {
            _modulesLogger2['default'].error(self.src.id, functionName + 'When sign aspose url happen error, no retry any more', err);
            self.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusFailed, function () {
              return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
            });
          }
          _modulesLogger2['default'].info(self.src.id, functionName + 'Query words pages by url' + url);
          var options = { url: url, json: true };
          _request2['default'].get(options, function (err, response, body) {
            if (!err && response.statusCode == 200) {
              (function () {
                var pages = 0;
                if (body && body.StatData && body.StatData.PageCount) {
                  pages = body.StatData.PageCount;
                }
                _modulesLogger2['default'].info(self.src.id, functionName + 'Query word pages by url' + url + ' successfully with data:', body);
                _converter_helper2['default'].setPagesToMetaData(self.src, self.messageId, self.fileId, pages, function (err, result) {
                  if (err) {
                    _modulesLogger2['default'].error(self.src.id, functionName + 'Set page to file failed', err);
                    return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                  } else {
                    _modulesLogger2['default'].info(self.src.id, functionName + 'Set page to file successfully');
                    fileObj.pages = pages;
                    return interCallback(null, fileObj);
                  }
                });
              })();
            } else {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Query word pages by url' + url + ' faild', err, response.statusCode, body);
              return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
            }
          });
        },
        //use aspose api split document into doc for every 5 pages
        function (fileObj, interCallback) {
          var currentPage = fileObj.metaData.paging || 0;
          var pages = fileObj.pages;
          var stepPage = 5;
          _async2['default'].whilst(function () {
            _converter_helper2['default'].setPagingToMetaData(self.src, self.messageId, self.fileId, currentPage, function (err) {
              if (err) {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'Set paging of convert progress failed', err);
              }
            });
            if (_utilsServerHelper2['default'].requestWillEndSoon(self.src)) {
              _modulesLogger2['default'].info(self.src.id, 'This request will end soon, create another taskqueue to continue working');
              endRequestForRequestEndSoon = true;
              return false;
            }
            return currentPage + 1 <= pages;
          }, function (interCallback2) {
            var startPage = currentPage + 1;
            if (startPage > pages) {
              return interCallback2(null, currentPage);
            }
            var endPage = currentPage + stepPage;
            if (endPage > pages) {
              endPage = pages;
            }
            currentPage = endPage;
            var url = _converter_helper2['default'].getAsposeApiBaseUrl() + 'words/' + encodeURI(oridocname) + '/split?' + 'format=' + encodeURI('svg') + '&from=' + startPage + '&to=' + endPage + '&folder=' + encodeURI('logan/' + self.fileId + '_convert') + '&storage=' + encodeURI(_converter_helper2['default'].asposeStorageName);
            try {
              url = _converter_helper2['default'].asposSign(self.src, url);
            } catch (err) {
              _modulesLogger2['default'].error(self.src.id, functionName + 'When sign aspose url happen error, no retry any more', err);
              self.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusFailed, function () {
                return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
              });
            }
            _modulesLogger2['default'].info(self.src.id, functionName + 'Split words into svgs by url' + url);
            var options = { url: url, json: true };
            _request2['default'].post(options, function (err, response, body) {
              if (!err && response.statusCode == 200) {
                _modulesLogger2['default'].info(self.src.id, functionName + 'Split doc document into svgs by url' + url + ' successfully', body);
                return interCallback2(null, endPage);
              } else {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'Split doc document into svgs by url' + url + ' faild', err, response.statusCode, body);
                return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
              }
            });
          }, function (err, n) {
            if (err) {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Convert to svg page by page happen error', err);
            }
            return interCallback(err, fileObj);
          });
        },
        //Copy converted folder back to real official folder
        function (fileObj, interCallback) {
          _modulesLogger2['default'].info(self.src.id, functionName + 'List all svg files from converted folder');
          var filePrefix = oridocname + '_page';
          _modulesFile2['default'].listFiles(self.src, { bucketName: _modulesFileGcsConfigJs2['default'].tempExtneralBucket,
            prefix: self.fileId + '_convert/' + filePrefix
          }, function (err, results) {
            _modulesLogger2['default'].info(self.src.id, functionName + 'List all svg files from converted folder with files number=' + results.length);
            if (results.length < fileObj.pages) {
              _modulesLogger2['default'].warn(self.src.id, functionName + 'Happen some errors for list pages. pagenumber should be ' + fileObj.pages);
              return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
            }
            _async2['default'].forEachOf(results, function (aSrcFile, idx, interCallback2) {
              var cutPosString = 'logan/';
              var cutPos = aSrcFile.metadata.name.indexOf(cutPosString);
              var path = null;
              if (cutPos >= 0) {
                path = aSrcFile.metadata.name.substring(cutPos + cutPosString.length);
              } else {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'Failed to get path from name=' + aSrcFile.metadata.name);
              }
              if (path) {
                path = path.replace(filePrefix, 'page_');
                path = path.replace('page_0', 'page_');
                _modulesLogger2['default'].info(self.src.id, functionName + 'Will copy file to bucket=' + _modulesFileGcsConfigJs2['default'].bucket + ' path=' + path);
                _modulesFile2['default'].createFileObj(self.src, { bucketName: _modulesFileGcsConfigJs2['default'].bucket,
                  path: path
                }, function (err, destFileObj) {
                  aSrcFile.copy(destFileObj, function (err, result) {
                    if (err) {
                      _modulesLogger2['default'].warn(self.src.id, functionName + 'Copy file failed', err);
                      return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                    }
                    result.setMetadata({ contentType: 'image/svg+xml' }, function (err, apiResponse) {
                      if (err) {
                        _modulesLogger2['default'].error(self.src.id, functionName + 'Set mimetype image/svg+xml failed', err);
                        return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
                      } else {
                        return interCallback2(null);
                      }
                    });
                  });
                });
              } else {
                return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
              }
            }, function (err) {
              if (err) {
                _modulesLogger2['default'].warn(self.src.id, functionName + 'Copy converted file back to real folder happen error', err);
              } else {
                _modulesLogger2['default'].info(self.src.id, functionName + 'Copy converted file back to real folder successfully');
              }
              return interCallback(err, fileObj);
            });
          });
        }], function (err, result) {
          if (endRequestForRequestEndSoon) {
            _fileviewCommon2['default'].endRequestAndLauchAnotherDefer(self.src, self, function (err) {
              return cb(err);
            });
          } else {
            return cb(err, result);
          }
        });
      }
    }]);
  
    return docToSvgFileView;
  })(_fileviewCommon2['default'].FileViewer);
  
  exports['default'] = {
    PdfToSvgFileView: PdfToSvgFileView,
    pptToSvgFileView: pptToSvgFileView,
    docToSvgFileView: docToSvgFileView
  };
  module.exports = exports['default'];

/***/ },
/* 103 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _fileviewCommon = __webpack_require__(37);
  
  var _fileviewCommon2 = _interopRequireDefault(_fileviewCommon);
  
  var _modulesFile = __webpack_require__(28);
  
  var _modulesFile2 = _interopRequireDefault(_modulesFile);
  
  var _gcloudLibStorage = __webpack_require__(44);
  
  var _gcloudLibStorage2 = _interopRequireDefault(_gcloudLibStorage);
  
  var _modulesFileGcsConfigJs = __webpack_require__(34);
  
  var _modulesFileGcsConfigJs2 = _interopRequireDefault(_modulesFileGcsConfigJs);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _process = __webpack_require__(21);
  
  var _process2 = _interopRequireDefault(_process);
  
  var _request = __webpack_require__(19);
  
  var _request2 = _interopRequireDefault(_request);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _util = __webpack_require__(12);
  
  var _util2 = _interopRequireDefault(_util);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _crypto = __webpack_require__(35);
  
  var _crypto2 = _interopRequireDefault(_crypto);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _messageMessageEvent = __webpack_require__(16);
  
  var _messageMessageEvent2 = _interopRequireDefault(_messageMessageEvent);
  
  var _converter_helper = __webpack_require__(36);
  
  var _converter_helper2 = _interopRequireDefault(_converter_helper);
  
  var docToSvgFileView = (function (_crtHelp$cloudConvertToSvgFileView) {
    _inherits(docToSvgFileView, _crtHelp$cloudConvertToSvgFileView);
  
    function docToSvgFileView() {
      _classCallCheck(this, docToSvgFileView);
  
      _get(Object.getPrototypeOf(docToSvgFileView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    return docToSvgFileView;
  })(_converter_helper2['default'].cloudConvertToSvgFileView);
  
  var pptToSvgFileView = (function (_crtHelp$cloudConvertToSvgFileView2) {
    _inherits(pptToSvgFileView, _crtHelp$cloudConvertToSvgFileView2);
  
    function pptToSvgFileView() {
      _classCallCheck(this, pptToSvgFileView);
  
      _get(Object.getPrototypeOf(pptToSvgFileView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    return pptToSvgFileView;
  })(_converter_helper2['default'].cloudConvertToSvgFileView);
  
  var excelToSvgFileView = (function (_crtHelp$cloudConvertToSvgFileView3) {
    _inherits(excelToSvgFileView, _crtHelp$cloudConvertToSvgFileView3);
  
    function excelToSvgFileView() {
      _classCallCheck(this, excelToSvgFileView);
  
      _get(Object.getPrototypeOf(excelToSvgFileView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(excelToSvgFileView, [{
      key: 'toPdf',
      value: function toPdf(inData, cb) {
        var functionName = '[excelToSvgFileView.toPdf] ';
        //The following options are created by our requirement to cloudconvert
        inData.toPdfConverteroptions = {
          pages_fit_wide: 1,
          pages_fit_tall: 1
        };
        _modulesLogger2['default'].info(this.src.id, functionName + 'Add toPdfConverteroptions to convert parameters');
        _get(Object.getPrototypeOf(excelToSvgFileView.prototype), 'toPdf', this).call(this, inData, cb);
      }
    }]);
  
    return excelToSvgFileView;
  })(_converter_helper2['default'].cloudConvertToSvgFileView);
  
  var PdfToSvgFileView = (function (_crtHelp$cloudConvertToSvgFileView4) {
    _inherits(PdfToSvgFileView, _crtHelp$cloudConvertToSvgFileView4);
  
    function PdfToSvgFileView() {
      _classCallCheck(this, PdfToSvgFileView);
  
      _get(Object.getPrototypeOf(PdfToSvgFileView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(PdfToSvgFileView, [{
      key: 'toPdf',
      value: function toPdf(inData, cb) {
        return cb(null, inData.fileObj);
      }
    }]);
  
    return PdfToSvgFileView;
  })(_converter_helper2['default'].cloudConvertToSvgFileView);
  
  exports['default'] = {
    excelToSvgFileView: excelToSvgFileView,
    docToSvgFileView: docToSvgFileView,
    pptToSvgFileView: pptToSvgFileView,
    PdfToSvgFileView: PdfToSvgFileView
  };
  module.exports = exports['default'];

/***/ },
/* 104 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _fileviewCommon = __webpack_require__(37);
  
  var _fileviewCommon2 = _interopRequireDefault(_fileviewCommon);
  
  var _modulesFile = __webpack_require__(28);
  
  var _modulesFile2 = _interopRequireDefault(_modulesFile);
  
  var _gcloudLibStorage = __webpack_require__(44);
  
  var _gcloudLibStorage2 = _interopRequireDefault(_gcloudLibStorage);
  
  var _modulesFileGcsConfigJs = __webpack_require__(34);
  
  var _modulesFileGcsConfigJs2 = _interopRequireDefault(_modulesFileGcsConfigJs);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _process = __webpack_require__(21);
  
  var _process2 = _interopRequireDefault(_process);
  
  var _request = __webpack_require__(19);
  
  var _request2 = _interopRequireDefault(_request);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _util = __webpack_require__(12);
  
  var _util2 = _interopRequireDefault(_util);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _crypto = __webpack_require__(35);
  
  var _crypto2 = _interopRequireDefault(_crypto);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _messageMessageEvent = __webpack_require__(16);
  
  var _messageMessageEvent2 = _interopRequireDefault(_messageMessageEvent);
  
  var _converter_helper = __webpack_require__(36);
  
  var _converter_helper2 = _interopRequireDefault(_converter_helper);
  
  var convertListFileView = (function (_fileViewCommon$FileViewer) {
    _inherits(convertListFileView, _fileViewCommon$FileViewer);
  
    function convertListFileView() {
      _classCallCheck(this, convertListFileView);
  
      _get(Object.getPrototypeOf(convertListFileView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(convertListFileView, [{
      key: 'cleanWork',
      value: function cleanWork(cb) {
        var inData = {
          convertObj: this
        };
        _converter_helper2['default'].cleanWork(this.src, inData, cb);
      }
    }, {
      key: 'setConvertList',
      value: function setConvertList(convertlist) {
        this.convertlist = convertlist;
      }
    }, {
      key: 'convert',
      value: function convert(cb) {
        var functionName = '[convertListFileView.convert] ';
        var num = this.convertlist.length;
        var self = this;
        function processOneConvert(idxVal) {
          if (idxVal >= num) {
            _modulesLogger2['default'].info(self.src.id, _util2['default'].format('%s No more convert avaliable!', functionName));
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].FileConvertFailed));
          }
          var convertObj = new self.convertlist[idxVal]();
          convertObj.setProperties(self.getProperties());
          convertObj.convert(function (err, result) {
            if (!err) {
              _modulesLogger2['default'].info(self.src.id, _util2['default'].format('%s Convert index=%d successfully!', functionName, idxVal));
              self.convertedFileObj = convertObj.convertedFileObj;
              return cb(null, result);
            }
            if (err.code == _errorsErrors2['default'].NoSuchConverter || err.code == _errorsErrors2['default'].TaskqueueEndBeforeTimout) {
              _modulesLogger2['default'].info(self.src.id, _util2['default'].format('%s Convert index=%d ask for end request!', functionName, idxVal));
              return cb(err, result);
            } else {
              idxVal = idxVal + 1;
              _modulesLogger2['default'].warn(self.src.id, _util2['default'].format('%s Try next converter with index=%d!', functionName, idxVal));
              return processOneConvert(idxVal);
            }
          });
        }
  
        processOneConvert(0);
      }
    }]);
  
    return convertListFileView;
  })(_fileviewCommon2['default'].FileViewer);
  
  exports['default'] = {
    convertListFileView: convertListFileView
  };
  module.exports = exports['default'];

/***/ },
/* 105 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * This is base class of a file viewer
   */
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _modulesMemcache = __webpack_require__(48);
  
  var _modulesMemcache2 = _interopRequireDefault(_modulesMemcache);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _taskqueueTaskqueueBackend = __webpack_require__(22);
  
  var _taskqueueTaskqueueBackend2 = _interopRequireDefault(_taskqueueTaskqueueBackend);
  
  var _aspose_fileviewerBackend = __webpack_require__(102);
  
  var _aspose_fileviewerBackend2 = _interopRequireDefault(_aspose_fileviewerBackend);
  
  var _aspose_cloudconvert_fileviewBackend = __webpack_require__(101);
  
  var _aspose_cloudconvert_fileviewBackend2 = _interopRequireDefault(_aspose_cloudconvert_fileviewBackend);
  
  var _cloudconvert_fileviewBackend = __webpack_require__(103);
  
  var _cloudconvert_fileviewBackend2 = _interopRequireDefault(_cloudconvert_fileviewBackend);
  
  var _convertlist_fileviewBackend = __webpack_require__(104);
  
  var _convertlist_fileviewBackend2 = _interopRequireDefault(_convertlist_fileviewBackend);
  
  var _converter_helper = __webpack_require__(36);
  
  var _converter_helper2 = _interopRequireDefault(_converter_helper);
  
  var convertHandlers = {
    'pdf_svg': _cloudconvert_fileviewBackend2['default'].PdfToSvgFileView,
    'ppt_svg': _cloudconvert_fileviewBackend2['default'].pptToSvgFileView,
    'doc_svg': _cloudconvert_fileviewBackend2['default'].docToSvgFileView,
    'excel_svg': _cloudconvert_fileviewBackend2['default'].excelToSvgFileView
  };
  
  var fileViewMaps = [{ fileType: 'application/pdf', ext: '.pdf', handleKey: 'pdf_svg', converted_file_ext: '.svg' }, { fileType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', ext: '.pptx', handleKey: 'ppt_svg', converted_file_ext: '.svg' }, { fileType: 'application/vnd.ms-powerpoint', ext: '.ppt', handleKey: 'ppt_svg', converted_file_ext: '.svg' }, { fileType: 'application/msword', ext: '.doc', handleKey: 'doc_svg', converted_file_ext: '.svg' }, { fileType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', ext: '.docx', handleKey: 'doc_svg', converted_file_ext: '.svg' }, { fileType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', ext: '.xlsx', handleKey: 'excel_svg', converted_file_ext: '.svg' }, { fileType: 'application/vnd.ms-excel', ext: '.xls', handleKey: 'excel_svg', converted_file_ext: '.svg' }];
  
  exports.getConvertedFileExt = function (src, fileObj) {
    var functionName = '[getConvertedFileExt] ';
    var fileName = fileObj.name;
    var fileType = fileObj.providerFileType;
    _modulesLogger2['default'].info(src.id, functionName + 'Try to get converted extension name by name=' + fileName + ' fileType=' + fileType);
    var _iteratorNormalCompletion = true;
    var _didIteratorError = false;
    var _iteratorError = undefined;
  
    try {
      for (var _iterator = fileViewMaps[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
        var _item = _step.value;
  
        if (fileName.toLowerCase().endsWith(_item.ext) || _item.fileType == fileType) {
          _modulesLogger2['default'].info(src.id, functionName + 'Get converted extension name by name=' + fileName + ' fileType=' + fileType + ' and get result=' + _item.converted_file_ext);
          return _item.converted_file_ext;
        }
      }
    } catch (err) {
      _didIteratorError = true;
      _iteratorError = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion && _iterator['return']) {
          _iterator['return']();
        }
      } finally {
        if (_didIteratorError) {
          throw _iteratorError;
        }
      }
    }
  
    _modulesLogger2['default'].info(src.id, functionName + 'Get converted extension name by name=' + fileName + ' fileType=' + fileType + ' no result');
    return null;
  };
  
  exports.convertViewFile = function (src, messageId, fileObj, cb) {
    var functionName = '[convertViewFile] ';
    var fileName = fileObj.name;
    var fileType = fileObj.providerFileType;
    var convertHandle = null;
    var handleKey = '';
    _modulesLogger2['default'].info(src.id, functionName + 'Try to convert file with  messageId=' + messageId + ' name=' + fileName + ' fileType=' + fileType);
    var selectedItem = null;
    var _iteratorNormalCompletion2 = true;
    var _didIteratorError2 = false;
    var _iteratorError2 = undefined;
  
    try {
      for (var _iterator2 = fileViewMaps[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
        var _item2 = _step2.value;
  
        if (fileName.toLowerCase().endsWith(_item2.ext) || _item2.fileType == fileType) {
          convertHandle = convertHandlers[_item2.handleKey] || null;
          if (convertHandle) {
            _modulesLogger2['default'].info(src.id, functionName + 'Has corresponding converter ' + _item2.handleKey);
            handleKey = _item2.handleKey;
            selectedItem = _item2;
            break;
          }
        }
      }
    } catch (err) {
      _didIteratorError2 = true;
      _iteratorError2 = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion2 && _iterator2['return']) {
          _iterator2['return']();
        }
      } finally {
        if (_didIteratorError2) {
          throw _iteratorError2;
        }
      }
    }
  
    if (convertHandle) {
      (function () {
        var converObj = null;
        if (Object.prototype.toString.call(convertHandle) === '[object Array]') {
          converObj = new _convertlist_fileviewBackend2['default'].convertListFileView(src, messageId, fileObj.fileId, handleKey);
          converObj.setConvertList(convertHandle);
        } else {
          converObj = new convertHandle(src, messageId, fileObj.fileId, handleKey);
        }
        converObj.validateConvert(function (err) {
          if (!err) {
            converObj.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusProgressing, function (err, result) {
              if (err) {
                _modulesLogger2['default'].warn(src.id, functionName + 'Can convert this file for update status failed', err);
                return cb(null);
              } else {
                var data = { messageId: converObj.messageId,
                  fileId: converObj.fileId,
                  handleKey: converObj.handleKey,
                  informat: selectedItem.ext.replace('.', ''),
                  outformat: selectedItem.converted_file_ext.replace('.', '')
                };
                converObj.convertedFileObj = { convertStatus: _utilsServerConstants2['default'].ConvertStatusProgressing };
                _converter_helper2['default'].notifyClientsMessageUpdate(src, converObj);
                _taskqueueTaskqueueBackend2['default'].launchDefer(src, 'convertAFileDefer', data, { defferOption: true,
                  backoff_seconds: 300,
                  attempts: 3,
                  callback: function callback(err, result) {
                    if (!err) {
                      _modulesLogger2['default'].info(src.id, functionName + 'Trigger a task to do convert work with messageId=' + messageId + 'fileId=' + fileObj.fileId);
                    } else {
                      _modulesLogger2['default'].info(src.id, functionName + 'Failed to trigger a task to do convert work with messageId=' + messageId + 'fileId=' + fileObj.fileId);
                    }
                    return cb(null);
                  }
                });
              }
            });
          } else {
            _modulesLogger2['default'].warn(src.id, functionName + 'Can not convert this file.');
            return cb(null);
          }
        });
      })();
    } else {
      _modulesLogger2['default'].warn(src.id, functionName + 'No corresponding converter.');
      return cb(null);
    }
  };
  
  function convertAFileDefer(src, data, cb) {
    var functionName = '[convertAFileDefer] ';
    var messageId = data.messageId;
    var fileId = data.fileId;
    var handleKey = data.handleKey;
    var informat = data.informat;
    var outformat = data.outformat;
    var extraData = data.extraData || {};
    var taskoptions = data._taskoptions;
  
    _modulesLogger2['default'].info(src.id, functionName + 'Try to convert file', data);
  
    var convertHandle = convertHandlers[handleKey] || null;
    if (!convertHandle) {
      _modulesLogger2['default'].warn(src.id, functionName + 'No corresponding converter ' + item.handleKey);
      return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
    }
    var converObj = null;
    if (Object.prototype.toString.call(convertHandle) === '[object Array]') {
      converObj = new _convertlist_fileviewBackend2['default'].convertListFileView(src, messageId, fileId, handleKey, informat, outformat, extraData);
      converObj.setConvertList(convertHandle);
    } else {
      converObj = new convertHandle(src, messageId, fileId, handleKey, informat, outformat, extraData);
    }
    converObj.convert(function (err, result) {
      if (err) {
        _modulesLogger2['default'].warn(src.id, functionName + 'Happen error', err);
        if (err.code == _errorsErrors2['default'].NoSuchConverter || err.code == _errorsErrors2['default'].TaskqueueEndBeforeTimout) {
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
        } else {
          if (taskoptions.attempt_times >= taskoptions.attempts || err.code == _errorsErrors2['default'].TaskNoRetryError) {
  
            _modulesLogger2['default'].warn(src.id, functionName + 'This file has try to convert serval times still failed or get no retry error, system won\'t do any conversion!');
            _modulesLogger2['default'].warn(src.id, functionName + ' attempt_times=' + taskoptions.attempt_times + ' attempts=' + taskoptions.attempts + ' err.code=' + err.code);
            converObj.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusFailed, function (err) {
              converObj.cleanWork(function () {
                return cb(err, result);
              });
            });
          } else {
            return cb(err, result);
          }
        }
      } else {
        _modulesLogger2['default'].info(src.id, functionName + 'Finish successfully');
        converObj.setConvertStatus(_utilsServerConstants2['default'].ConvertStatusSuccess, function (err) {
          converObj.cleanWork(function (err) {
            return cb(err, result);
          });
        });
      }
    });
  }
  _taskqueueTaskqueueBackend2['default'].registerDeferHandle('convertAFileDefer', convertAFileDefer);

/***/ },
/* 106 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _viewBaseViewBase2 = _interopRequireDefault(_viewBaseViewBase);
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  var _util = __webpack_require__(12);
  
  var _util2 = _interopRequireDefault(_util);
  
  var _messageMessageEvent = __webpack_require__(16);
  
  var _messageMessageEvent2 = _interopRequireDefault(_messageMessageEvent);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  exports.notifyCallback = (function (_vw$serverCallView) {
    _inherits(notifyCallback, _vw$serverCallView);
  
    function notifyCallback() {
      _classCallCheck(this, notifyCallback);
  
      _get(Object.getPrototypeOf(notifyCallback.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(notifyCallback, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var functionName = '[notifyCallback] ';
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        var data = req.body;
        _modulesLoggerIndex2['default'].info(src.id, _util2['default'].format('%s Notify user the document conver has some change', functionName), data);
        _messageMessageEvent2['default'].emitFileConverted(src, data, function (err, result) {
          if (err) {
            _modulesLoggerIndex2['default'].error(src.id, functionName + 'Failed to emit event to notify clients the message\'s changing', err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(err);
          } else {
            _modulesLoggerIndex2['default'].info(src.id, functionName + 'Successful to emit event to notify clients the message\'s changing is updated');
            return res.json({});
          }
        });
      }
    }]);
  
    return notifyCallback;
  })(_viewBaseViewBase2['default'].serverCallView);

/***/ },
/* 107 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * http://usejsdoc.org/
   */
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _fileviewController = __webpack_require__(106);
  
  var _fileviewController2 = _interopRequireDefault(_fileviewController);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var router = new _express.Router();
  
  router.post('/notify-callback', (0, _viewBaseViewBase.asView)(_fileviewController2['default'].notifyCallback));
  
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 108 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * author: Eric Ding
   */
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  exports.listMessagesByIdea = function (src, data, cb) {
    var matchCondition = {
      "parentMsg._id": _mongoose2['default'].Types.ObjectId(data.ideaId)
    };
  
    var sort = { _id: -1 };
    if (data.page <= 1) {
      delete data.nextRefObjId;
      delete data.prevRefObjId;
      data.page = 1;
    }
    var includeEqual = data.includeEqual || false;
    delete data.includeEqual;
    if (data.nextRefObjId) {
      if (includeEqual) {
        matchCondition["_id"] = { $lte: _mongoose2['default'].Types.ObjectId(data.nextRefObjId) };
      } else {
        matchCondition["_id"] = { $lt: _mongoose2['default'].Types.ObjectId(data.nextRefObjId) };
      }
      sort = { _id: -1 };
    } else if (data.prevRefObjId) {
      if (includeEqual) {
        matchCondition["_id"] = { $gte: _mongoose2['default'].Types.ObjectId(data.prevRefObjId) };
      } else {
        matchCondition["_id"] = { $gt: _mongoose2['default'].Types.ObjectId(data.prevRefObjId) };
      }
      sort = { _id: 1 };
    }
  
    var exeobj = _messageMessageModel2['default'].find(matchCondition).sort(sort).limit(data.size + 1);
    _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, results) {
      if (err) {
        logger.error(src.id, 'listCommentsByIdea happen error', err.message);
        return cb(null, { results: [] });
      }
  
      if (results.length > data.size) {
        if (data.prevRefObjId) {
          results = results.reverse();
          return cb(null, { results: results.slice(1, data.size + 1), havingNextPage: true });
        }
        return cb(null, { results: results.slice(0, data.size), havingNextPage: true });
      } else {
        if (data.prevRefObjId) {
          results = results.reverse();
        }
        return cb(null, { results: results, havingNextPage: false });
      }
    });
  };

/***/ },
/* 109 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * author: Eric Ding
   */
  
  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _viewBaseViewBase2 = _interopRequireDefault(_viewBaseViewBase);
  
  var _messageMessageBackend = __webpack_require__(26);
  
  var _messageMessageBackend2 = _interopRequireDefault(_messageMessageBackend);
  
  var _ideaBackend = __webpack_require__(108);
  
  var _ideaBackend2 = _interopRequireDefault(_ideaBackend);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  var _fluxConstantsMessageConstants = __webpack_require__(17);
  
  var _fluxConstantsMessageConstants2 = _interopRequireDefault(_fluxConstantsMessageConstants);
  
  var _authAuthorizers = __webpack_require__(24);
  
  var _authAuthorizers2 = _interopRequireDefault(_authAuthorizers);
  
  var _messageMessageEvent = __webpack_require__(16);
  
  var _messageMessageEvent2 = _interopRequireDefault(_messageMessageEvent);
  
  exports.deleteIdea = (function (_vw$ViewBase) {
    _inherits(deleteIdea, _vw$ViewBase);
  
    function deleteIdea() {
      _classCallCheck(this, deleteIdea);
  
      _get(Object.getPrototypeOf(deleteIdea.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(deleteIdea, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        var idea = req.message;
        req.relPermChecker.checkRelation(src, idea.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
          if (err) {
            return cb(err);
          }
          idea.remove(function (err, result) {
            if (err) {
              _modulesLoggerIndex2['default'].error(req.id, 'Error deleting idea', err);
              return cb(res, new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
            }
            _messageMessageEvent2['default'].emitCardDeleted(src, idea);
            return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send();
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_UPDATE)],
      enumerable: true
    }]);
  
    return deleteIdea;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  var listMessagesView = (function (_vw$anyCallView) {
    _inherits(listMessagesView, _vw$anyCallView);
  
    function listMessagesView() {
      _classCallCheck(this, listMessagesView);
  
      _get(Object.getPrototypeOf(listMessagesView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(listMessagesView, [{
      key: '_listMessages',
      value: function _listMessages(req, queryData, cb) {
        var self = this;
        _ideaBackend2['default'].listMessagesByIdea(req, queryData, function (err, results) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'listCommentsView call _listComments happen error', err.message);
            return cb(err);
          }
          if (queryData.prevRefObjId && results.results.length < queryData.size) {
            delete queryData.prevRefObjId;
            queryData.page = 1;
            return self._listMessages(req, queryData, cb);
          } else if (results.results.length === 0 && queryData.nextRefObjId) {
            queryData.prevRefObjId = queryData.nextRefObjId;
            delete queryData.nextRefObjId;
            queryData.page -= 1;
            queryData.includeEqual = true;
            return self._listMessages(req, queryData, function (err, data) {
              if (data.results) {
                data.results.havingNextPage = false;
              }
              return cb(null, data);
            });
          }
          delete queryData.ideaId;
          var data = {
            queryData: queryData,
            results: results
          };
          return cb(null, data);
        });
      }
    }, {
      key: 'handle',
      value: function handle(req, res, cb) {
        //Be care don't need embed parent message
        var queryData = {
          ideaId: req.params.ideaId,
          size: _utilsServerHelper2['default'].getListOfItemCaps(parseInt(req.query.size), 30),
          page: parseInt(req.query.page) || 1,
          nextRefObjId: req.query.nextRefObjId,
          prevRefObjId: req.query.prevRefObjId
        };
  
        var self = this;
        _async2['default'].waterfall([function (internalCallback) {
          _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].findOne, req.id, { _id: req.params.ideaId }, function (err, ideaMsg) {
            if (err) {
              _modulesLoggerIndex2['default'].error(req.id, err.message);
            }
            return internalCallback(err, ideaMsg);
          });
        }, function (ideaMsg, internalCallback) {
          if (!ideaMsg) {
            _modulesLoggerIndex2['default'].error(req.id, "idea with _id=" + req.params.ideaId + " not exited");
            return internalCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          }
          if (ideaMsg.category !== _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA) {
            return internalCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MessageUnexpectedCategory));
          }
          req.relPermChecker.checkRelation(req, ideaMsg.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
            return internalCallback(err, ideaMsg);
          });
        }, function (ideaMsg, internalCallback) {
          self._listMessages(req, queryData, internalCallback);
        }, function (data, internalCallback) {
          _messageMessageBackend2['default'].toDownloadableClientFormatMessagesIngoreParentMsg(req, data.results.results, function (err, convertedResults) {
            if (err) {
              return internalCallback(err);
            }
            data.results.results = convertedResults;
            return internalCallback(null, data);
          });
        }], function (err, data) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, "listCommentsView happen error", err);
            if (err.code == _errorsErrors2['default'].AuthorizeErrorPermission) {
              return cb(err);
            }
            return res.json({ data: [], total: 0, nextPageUrl: '', previousPageUrl: '' });
          }
          return res.json(_utilsServerHelper2['default'].createPagination(req, data));
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_IDEA_READ)],
      enumerable: true
    }]);
  
    return listMessagesView;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  exports.listMessagesView = listMessagesView;

/***/ },
/* 110 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * author: Eric Ding
   */
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _ideaController = __webpack_require__(109);
  
  var _ideaController2 = _interopRequireDefault(_ideaController);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var router = new _express.Router();
  
  router.get('/:ideaId/messages', (0, _viewBaseViewBase.asView)(_ideaController2['default'].listMessagesView));
  router['delete']('/:ideaId', (0, _viewBaseViewBase.asView)(_ideaController2['default'].deleteIdea));
  
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 111 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5),
      Schema = mongoose.Schema,
      config = __webpack_require__(4);
  
  var InviteSchema = new Schema({
  	invitees: [{
  		id: { type: Schema.Types.ObjectId, ref: 'User' },
  		username: String,
  		type: { type: String, 'default': 'guest' }, //admin | member | guest
  		joinTime: Date
  	}],
  	parent: {
  		type: { type: String },
  		id: { type: Schema.Types.ObjectId }
  	},
  	d: {
  		create: { type: Date, 'default': Date.now },
  		modify: { type: Date, 'default': Date.now },
  		start: Date,
  		end: Date
  	},
  	pType: String // calendar | office | webex etc.
  });
  
  /**
   * Virtuals
   */
  /**
   * Methods
   */
  InviteSchema.methods = {
  	makeInviteUrl: function makeInviteUrl(domain) {
  		return config.link + '/' + this.parent.type + '/' + this.parent._id + '/invite/' + this._id;
  	},
  	makeTopicUrl: function makeTopicUrl(domain) {
  		return config.link + '/' + this.parent.type + '/' + this.parent._id;
  	}
  };
  
  module.exports = mongoose.model('Invite', InviteSchema);

/***/ },
/* 112 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  //Version 1.0
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _messageController = __webpack_require__(113);
  
  var _messageController2 = _interopRequireDefault(_messageController);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var router = new _express.Router();
  
  //router.get('/', asView(controller.index));
  router.get('/parselink', (0, _viewBaseViewBase.asView)(_messageController2['default'].parseLink));
  router.get('/:id', (0, _viewBaseViewBase.asView)(_messageController2['default'].show));
  router.get('/:msgId/files/:fileId/viewerUrl', (0, _viewBaseViewBase.asView)(_messageController2['default'].getPreViewIndexUrl));
  //router.post('/', asView(controller.create));
  router.post('/:id', (0, _viewBaseViewBase.asView)(_messageController2['default'].update));
  router.patch('/:id', (0, _viewBaseViewBase.asView)(_messageController2['default'].update));
  router['delete']('/:id', (0, _viewBaseViewBase.asView)(_messageController2['default'].destroy));
  
  router.get('/:id/files/:fileKey', (0, _viewBaseViewBase.asView)(_messageController2['default'].getSingleDownloadUrl));
  
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 113 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Using Rails-like standard naming convention for endpoints.
   * GET     /message              ->  index
   * POST    /message              ->  create
   * GET     /message/:id          ->  show
   * PUT     /message/:id          ->  update
   * DELETE  /message/:id          ->  destroy
   */
  
  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var _messageModel = __webpack_require__(13);
  
  var _messageModel2 = _interopRequireDefault(_messageModel);
  
  var _messageBackend = __webpack_require__(26);
  
  var _messageBackend2 = _interopRequireDefault(_messageBackend);
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  var _authAuthService = __webpack_require__(15);
  
  var _authAuthService2 = _interopRequireDefault(_authAuthService);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _viewBaseViewBase2 = _interopRequireDefault(_viewBaseViewBase);
  
  var _userUserBackend = __webpack_require__(23);
  
  var _userUserBackend2 = _interopRequireDefault(_userUserBackend);
  
  var _fileFileBackend = __webpack_require__(54);
  
  var _fileFileBackend2 = _interopRequireDefault(_fileFileBackend);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _htmlToJson = __webpack_require__(178);
  
  var _htmlToJson2 = _interopRequireDefault(_htmlToJson);
  
  var _utilsIs = __webpack_require__(62);
  
  var _utilsIs2 = _interopRequireDefault(_utilsIs);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _querystring = __webpack_require__(45);
  
  var _querystring2 = _interopRequireDefault(_querystring);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _authAuthorizers = __webpack_require__(24);
  
  var _authAuthorizers2 = _interopRequireDefault(_authAuthorizers);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _modulesAnalyticsGoogle = __webpack_require__(33);
  
  var _modulesAnalyticsGoogle2 = _interopRequireDefault(_modulesAnalyticsGoogle);
  
  var _modulesAnalyticsGoogleConstants = __webpack_require__(32);
  
  var _modulesAnalyticsGoogleConstants2 = _interopRequireDefault(_modulesAnalyticsGoogleConstants);
  
  // Get list of messages
  exports.index = (function (_vw$ViewBase) {
    _inherits(index, _vw$ViewBase);
  
    function index() {
      _classCallCheck(this, index);
  
      _get(Object.getPrototypeOf(index.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(index, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        _messageModel2['default'].find(function (err, messages) {
          if (err) {
            return handleError(res, err);
          }
          return res.status(200).json(messages);
        });
      }
    }]);
  
    return index;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  // Get a single Message
  exports.show = (function (_vw$ViewBase2) {
    _inherits(show, _vw$ViewBase2);
  
    function show() {
      _classCallCheck(this, show);
  
      _get(Object.getPrototypeOf(show.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(show, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        _messageModel2['default'].findById(req.params.id, function (err, message) {
          if (err) {
            return handleError(res, err);
          }
          if (!message) {
            return res.status(404).send('Not Found');
          }
          req.relPermChecker.checkRelation(req, message.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
            if (err) {
              return cb(err);
            }
            var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
            _messageBackend2['default'].toDownloadableClientFormatMessages(src, [message], function (err, convertedResults) {
              if (err) {
                _modulesLoggerIndex2['default'].error(src.id, "Get message by id happenen error!", err);
                return cb(err);
              }
              return res.json(convertedResults[0]);
            });
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_READ)],
      enumerable: true
    }]);
  
    return show;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  // Creates a new Message in the DB.
  //exports.create = class create extends vw.anyCallView{
  //  static AUTHORIZERS = [new authorize.PermissionAuthorizer(authorize.pm.PERM_MSG_CREATE)];
  //  handle(req, res, cb){
  //    let data = req.body;
  //    let tempUser = null;
  //    if (req.user){
  //      data.sender = {
  //          _id: req.user._id,
  //          type: cst.TypeUser
  //      };
  //      tempUser = req.user;
  //    }
  //    else if(req.anonymousUser){
  //      data.sender = {
  //          _id: req.anonymousUser._id,
  //          type: cst.TypeAnonymous
  //      };
  //      tempUser = req.anonymousUser;
  //    }
  //    else{
  //      return cb(new esErr.ESErrors(esErr.AuthorizeFailed));
  //    }
  //    req.relPermChecker.checkRelation(req, data, cst.TypeMessage, (err)=>{
  //      if (err){
  //        return cb(err);
  //      }
  //      MessageBk.addMessagetoNoSenderPublicInfo(req, data, function(err, result){
  //        if (err){
  //          return res.status(cst.HttpErrorStatus).json(err);
  //        }
  //        if (result.sender.type == cst.TypeUser){
  //          result.sender = _.extend(result.sender, req.user.profile);
  //        }
  //        else if(result.sender.type == cst.TypeAnonymous){
  //          result.sender = _.extend(result.sender,
  //                                   {displayname: req.anonymousUser.displayname,
  //                                    picture_url:  req.anonymousUser.picture_url,
  //                                    username: req.anonymousUser.username});
  //        }
  //        return res.status(200).json(result);
  //      });
  //    });
  //  };
  //};
  
  // Updates an existing Message in the DB.
  exports.update = (function (_vw$anyCallView) {
    _inherits(update, _vw$anyCallView);
  
    function update() {
      _classCallCheck(this, update);
  
      _get(Object.getPrototypeOf(update.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(update, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var data = req.body;
        req.relPermChecker.checkRelation(req, data.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
          if (err) {
            return cb(err);
          }
          if (req.user) {
            data.sender = {
              _id: req.user._id,
              type: _utilsServerConstants2['default'].TypeUser,
              username: req.user.username,
              displayname: req.user.displayname,
              picture_url: _utilsServerHelper2['default'].getPicture_url(req.user.picturefile)
            };
          } else if (req.anonymousUser) {
            data.sender = {
              _id: req.anonymousUser._id,
              type: _utilsServerConstants2['default'].TypeAnonymous,
              username: req.anonymousUser.username,
              displayname: req.anonymousUser.displayname,
              picture_url: _utilsServerHelper2['default'].getPicture_url(req.user.picturefile)
            };
          } else {
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SysUnkownError));
          }
          var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
          _messageBackend2['default'].updateMessagetoNoSenderPublicInfo(src, data, function (err, result) {
            if (err) {
              return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(err);
            }
            if (result.sender.type == _utilsServerConstants2['default'].TypeUser) {
              result.sender = _lodash2['default'].extend(result.sender, req.user.profile);
            } else if (result.sender.type == _utilsServerConstants2['default'].TypeAnonymous) {
              result.sender = _lodash2['default'].extend(result.sender, { displayname: req.anonymousUser.displayname,
                picture_url: req.anonymousUser.picture_url,
                username: req.anonymousUser.username });
            }
            return res.status(200).json(result);
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_UPDATE)],
      enumerable: true
    }]);
  
    return update;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  // Deletes a Message from the DB.
  exports.destroy = (function (_vw$ViewBase3) {
    _inherits(destroy, _vw$ViewBase3);
  
    function destroy() {
      _classCallCheck(this, destroy);
  
      _get(Object.getPrototypeOf(destroy.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(destroy, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        _messageModel2['default'].findById(req.params.id, function (err, message) {
          if (err) {
            return handleError(res, err);
          }
          if (!message) {
            return res.status(404).send('Not Found');
          }
          req.relPermChecker.checkRelation(req, message.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
            if (err) {
              return cb(err);
            }
            _messageModel2['default'].remove(function (err) {
              if (err) {
                return handleError(res, err);
              }
              return res.status(204).send('No Content');
            });
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_UPDATE)],
      enumerable: true
    }]);
  
    return destroy;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.parseLink = (function (_vw$anyCallView2) {
    _inherits(parseLink, _vw$anyCallView2);
  
    function parseLink() {
      _classCallCheck(this, parseLink);
  
      _get(Object.getPrototypeOf(parseLink.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(parseLink, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var link = req.query.link;
        if (!link || !_utilsIs2['default'].$url(link, true)) {
          res.status(400).send('');
          return;
        }
  
        _htmlToJson2['default'].request(link, {
          'meta': ['meta', function ($meta) {
            return {
              property: $meta.attr("property") || "",
              name: $meta.attr("name") || "",
              content: $meta.attr("content") || ""
            };
          }],
          'link': ['link', function ($link) {
            return {
              href: $link.attr("href") || "",
              rel: $link.attr("rel") || ""
            };
          }],
          'title': ['title', function ($title) {
            return $title.html();
          }],
          'images': ['img', function ($img) {
            return $img.attr('src');
          }]
        }, function (err, result) {
          if (err) {
            res.status(400);
          } else {
            res.status(200).json(result);
          }
        });
      }
    }]);
  
    return parseLink;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  exports.getSingleDownloadUrl = (function (_vw$anyCallView3) {
    _inherits(getSingleDownloadUrl, _vw$anyCallView3);
  
    function getSingleDownloadUrl() {
      _classCallCheck(this, getSingleDownloadUrl);
  
      _get(Object.getPrototypeOf(getSingleDownloadUrl.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(getSingleDownloadUrl, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var msgId = req.params.id;
        var fileKey = _querystring2['default'].unescape(req.params.fileKey);
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
  
        if (!msgId || !fileKey) {
          _modulesLoggerIndex2['default'].error(src.id, 'getUploadUrl happen error ');
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
        var data = {
          objectId: msgId,
          objectType: 'message',
          fileKeys: [fileKey]
        };
        _messageModel2['default'].findById(msgId, function (err, message) {
          if (err) {
            _modulesLoggerIndex2['default'].error(src.id, 'getDownloadUrl happen error ', err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].UploadUrlCreateFailed));
          }
          req.relPermChecker.checkRelation(req, message.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
            if (err) {
              return cb(err);
            }
            _fileFileBackend2['default'].getDownloadUrls(src, data, function (err, results) {
              if (err) {
                _modulesLoggerIndex2['default'].error(src.id, 'getDownloadUrl happen error ', err);
                return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].UploadUrlCreateFailed));
              }
              return res.redirect(results[0]);
            });
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_READ)],
      enumerable: true
    }]);
  
    return getSingleDownloadUrl;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  exports.getPreViewIndexUrl = (function (_vw$anyCallView4) {
    _inherits(getPreViewIndexUrl, _vw$anyCallView4);
  
    function getPreViewIndexUrl() {
      _classCallCheck(this, getPreViewIndexUrl);
  
      _get(Object.getPrototypeOf(getPreViewIndexUrl.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(getPreViewIndexUrl, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var functionName = '[getPreViewIndexUrl.handle] ';
        var messageId = req.params.msgId;
        var fileId = req.params.fileId;
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        console.log(src.id, functionName + 'Try to get preview index file by messageId=' + messageId + 'and fileId=' + messageId);
        _utilsDbwrapper2['default'].execute(_messageModel2['default'], _messageModel2['default'].findOne, src.id, { '_id': messageId, 'content.data.fileId': fileId }, { "topicId": 1, "content.data.$": 1 }, function (err, message) {
          if (err || !message) {
            if (err) {
              _modulesLoggerIndex2['default'].error(src.id, functionName + 'Get message by messageId=' + messageId + 'and fileId=' + fileId, err);
            }
            if (!message) {
              _modulesLoggerIndex2['default'].warn(src.id, functionName + 'Get message by messageId=' + messageId + 'and fileId=' + fileId + ' no record');
            }
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          } else {
            req.relPermChecker.checkRelation(req, message.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
              if (err) {
                _modulesLoggerIndex2['default'].warn(src.id, functionName + 'Get message by messageId=' + messageId + 'and fileId=' + fileId + ' failed no permission');
                return cb(err);
              }
              _messageBackend2['default'].getPreviewFileUrl(src, message, function (err, result) {
                if (err) {
                  _modulesLoggerIndex2['default'].warn(src.id, functionName + 'Get message by messageId=' + messageId + 'and fileId=' + fileId + 'failed after call getPreviewFileUrl', err);
                  return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(err);
                }
                if (!result) {
                  _modulesLoggerIndex2['default'].warn(src.id, functionName + 'Get message by messageId=' + messageId + 'and fileId=' + fileId + 'failed after call getPreviewFileUrl no result');
                  return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].GetPreviewUrlFailed));
                }
                res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json({ url: result });
              });
            });
          }
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_READ)],
      enumerable: true
    }]);
  
    return getPreViewIndexUrl;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  function handleError(res, err) {
    return res.status(500).send(err);
  }

/***/ },
/* 114 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Broadcast updates to client when the model changes
   */
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  exports.register = register;
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _fluxConstantsMessageConstants = __webpack_require__(17);
  
  var _fluxConstantsMessageConstants2 = _interopRequireDefault(_fluxConstantsMessageConstants);
  
  var _fluxConstantsSocketConstants = __webpack_require__(60);
  
  var _fluxConstantsSocketConstants2 = _interopRequireDefault(_fluxConstantsSocketConstants);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _messageEvent = __webpack_require__(16);
  
  var _messageEvent2 = _interopRequireDefault(_messageEvent);
  
  //Model events to emit
  
  function register(socketio) {
    _messageEvent2['default'].onFileConverted(function (src, eventObj, cb) {
      var functionName = '[messageEvt.onFileConverted] ';
      _modulesLogger2['default'].info(src.id, functionName + 'Will send message update event to topic=' + eventObj.topicId + ' eventtype=' + _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.APP_EVENTS.MESSAGE_UPDATED + ' payload=', eventObj.payload);
  
      var data = Object.assign({
        //_id: eventObj.payload.messageId,
        category: _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.APP_EVENTS.MESSAGE_UPDATED
      }, eventObj.payload);
  
      socketio.to('topic_' + data.topicId).emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.GROUP_MESSAGE_SENT, data);
      return cb(null);
    });
  }

/***/ },
/* 115 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _migrateController = __webpack_require__(117);
  
  var _migrateController2 = _interopRequireDefault(_migrateController);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var router = new _express.Router();
  
  router.post('/', (0, _viewBaseViewBase.asView)(_migrateController2['default'].migrate));
  router.get('/:id', (0, _viewBaseViewBase.asView)(_migrateController2['default'].migrateQuery));
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 116 */
/***/ function(module, exports, __webpack_require__) {

  /* WEBPACK VAR INJECTION */(function(module) {'use strict';
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _taskqueueTaskqueueBackend = __webpack_require__(22);
  
  var _taskqueueTaskqueueBackend2 = _interopRequireDefault(_taskqueueTaskqueueBackend);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _migrateModel = __webpack_require__(118);
  
  var _migrateModel2 = _interopRequireDefault(_migrateModel);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _relationRelationBackend = __webpack_require__(57);
  
  var _relationRelationBackend2 = _interopRequireDefault(_relationRelationBackend);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _events = __webpack_require__(172);
  
  var _events2 = _interopRequireDefault(_events);
  
  var _userUserBackend = __webpack_require__(23);
  
  var _userUserBackend2 = _interopRequireDefault(_userUserBackend);
  
  var QuitHandleTimeout = 20000;
  var RetyWaitTime = 10000;
  var batchSize = 20;
  function updateMigrateData(src, updatedMigrateData, cb) {
    _utilsDbwrapper2['default'].execute(_migrateModel2['default'], _migrateModel2['default'].update, src.id, { migrateId: src.migrateId }, { migrateData: updatedMigrateData }, function (err, result) {
      return cb(err);
    });
  }
  
  function endRequestAndLauchAnotherDefer(src, updatedMigrateData, cb) {
    var mgdata = { migrateId: src.migrateId, funcName: src.funcName };
    updateMigrateData(src, updatedMigrateData, function () {
      _taskqueueTaskqueueBackend2['default'].launchDefer(src, 'migrateTaskHandle', mgdata, { defferOption: true,
        backoff_seconds: 300,
        attempts: 3
      });
      cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskqueueEndBeforeTimout));
    });
  }
  
  function fillUserRelation(src, migrateData, cb) {
    var startUserId = '';
    if (!migrateData.fillRelationData.userfillData) {
      migrateData.fillRelationData.userfillData = {};
    }
    if (migrateData.fillRelationData.userfillData.finished) {
      return cb(null);
    }
    if (migrateData.fillRelationData.userfillData.startUserId) {
      startUserId = migrateData.fillRelationData.userfillData.startUserId;
    }
    var userDB = __webpack_require__(14);
    var exeObj = userDB.find();
    if (startUserId) {
      exeObj = userDB.find({ '_id': { '$gt': startUserId } });
    }
    exeObj = exeObj.sort({ '_id': 1 });
    var queryStream = exeObj.stream();
    var lastProcessUser = null;
    var closeManully = false;
    var esClosedFlag = false;
    var userCnt = 0;
    queryStream.on('data', function (userObj) {
      userCnt += 1;
      if (src.esClosedFlag) {
        _modulesLogger2['default'].info(src.id, 'Should end process asap!');
        esClosedFlag = src.esClosedFlag;
        queryStream.destroy();
        return;
      }
      if (_utilsServerHelper2['default'].requestWillEndSoon(src)) {
        if (!closeManully) {
          _modulesLogger2['default'].info(src.id, 'Request will end soon, launch another defer to continue work!');
          closeManully = true;
          queryStream.destroy();
        }
      }
      if (userCnt >= batchSize) {
        queryStream.pause();
      }
  
      _userUserBackend2['default'].afterInsertUpdateUser(src, userObj, function (err, result) {
        lastProcessUser = userObj;
        userCnt -= 1;
        if (userCnt <= 0 && !esClosedFlag) {
          queryStream.resume();
        }
      });
    }).on('error', function (err) {
      //Retry this user after some time!
      setTimeout(function () {
        if (lastProcessUser) {
          migrateData.fillRelationData.userfillData.startUserId = lastProcessUser._id;
        }
        updateMigrateData(src, migrateData, function (err) {
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskqueueRetry));
        });
      }, RetyWaitTime);
    }).on('close', function () {
      if (esClosedFlag) {
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskqueueEndBeforeTimout));
      }
      if (closeManully) {
        setTimeout(function () {
          if (lastProcessUser) {
            migrateData.fillRelationData.userfillData.startUserId = lastProcessUser._id;
          }
          return endRequestAndLauchAnotherDefer(src, migrateData, cb);
        }, RetyWaitTime);
      } else {
        migrateData.fillRelationData.userfillData.finished = true;
        updateMigrateData(src, migrateData, function (err) {
          return cb(null);
        });
      }
    });
  }
  
  function fillTopicUserRelation(src, migrateData, cb) {
    var startTopicId = '';
    if (!migrateData.fillRelationData.topicfillData) {
      migrateData.fillRelationData.topicfillData = {};
    }
    if (migrateData.fillRelationData.topicfillData.startTopicId) {
      startTopicId = migrateData.fillRelationData.topicfillData.startTopicId;
    }
    var topicDB = __webpack_require__(18);
    var exeObj = topicDB.find();
    if (startTopicId) {
      exeObj = topicDB.find({ '_id': { '$gt': startTopicId } });
    }
    exeObj = exeObj.sort({ '_id': 1 });
    var queryStream = exeObj.stream();
    var lastProcessTopic = null;
    var closeManully = false;
    var topicCnt = 0;
    var esClosedFlag = false;
    queryStream.on('data', function (topicObj) {
      topicCnt += 1;
      if (src.esClosedFlag) {
        _modulesLogger2['default'].info(src.id, 'Should end process asap!');
        esClosedFlag = src.esClosedFlag;
        queryStream.destroy();
        return;
      }
      if (_utilsServerHelper2['default'].requestWillEndSoon(src)) {
        //Close the stream
        if (!closeManully) {
          closeManully = true;
          queryStream.destroy();
        }
      }
      if (topicCnt >= batchSize) {
        queryStream.pause();
      }
      var added_rels = [];
      var _iteratorNormalCompletion = true;
      var _didIteratorError = false;
      var _iteratorError = undefined;
  
      try {
        for (var _iterator = topicObj.members[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
          var memberItem = _step.value;
  
          if (memberItem.memberType === 'userId') {
            var added_rel = {
              target_id: memberItem.member,
              target_type: _utilsServerConstants2['default'].TypeUser,
              initiator_id: topicObj._id,
              initiator_type: _utilsServerConstants2['default'].TypeTopic,
              relation_type: memberItem.role,
              relationdef_id: _utilsServerConstants2['default'].TypeUser + '_' + memberItem.member + '_' + _utilsServerConstants2['default'].TypeTopic + '_' + topicObj._id + '_' + memberItem.role
            };
            added_rels.push(added_rel);
          }
        }
      } catch (err) {
        _didIteratorError = true;
        _iteratorError = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion && _iterator['return']) {
            _iterator['return']();
          }
        } finally {
          if (_didIteratorError) {
            throw _iteratorError;
          }
        }
      }
  
      _relationRelationBackend2['default'].addRelations(src, added_rels, function (err, result) {
        lastProcessTopic = topicObj;
        topicCnt -= 1;
        if (topicCnt <= 0 && !esClosedFlag) {
          queryStream.resume();
        }
      });
    }).on('error', function (err) {
      //Retry this user after some time!
      setTimeout(function () {
        if (lastProcessTopic) {
          migrateData.fillRelationData.topicfillData.startTopicId = lastProcessUser._id;
        }
        updateMigrateData(src, migrateData, function (err) {
          return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskqueueRetry));
        });
      }, RetyWaitTime);
    }).on('close', function () {
      if (esClosedFlag) {
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskqueueEndBeforeTimout));
      }
      if (closeManully) {
        setTimeout(function () {
          if (lastProcessTopic) {
            migrateData.fillRelationData.topicfillData.startTopicId = lastProcessTopic._id;
          }
          return endRequestAndLauchAnotherDefer(src, migrateData, cb);
        }, RetyWaitTime);
      } else {
        updateMigrateData(src, migrateData, function (err) {
          return cb(null);
        });
      }
    });
  }
  
  var fillRelation = function fillRelation(src, migrateData, cb) {
    if (!migrateData.fillRelationData) {
      migrateData.fillRelationData = {};
    }
    _async2['default'].waterfall([function (interCallBack) {
      //Fill users relation
      fillUserRelation(src, migrateData, function (err, result) {
        interCallBack(err);
      });
    }, function (interCallBack) {
      fillTopicUserRelation(src, migrateData, function (err, result) {
        interCallBack(err);
      });
    }], function (err, result) {
      cb(err);
    });
  };
  
  var cacheTitleIntoTopicUser = function cacheTitleIntoTopicUser(src, migrateData, cb) {
    var functionName = '[cacheTitleIntoTopicUser] ';
    var TopicUser = __webpack_require__(46);
    var Topic = __webpack_require__(18);
    var cursorId = '';
    var LIMIT = 20;
    var totalTopicNum = -LIMIT;
    var oneRoundUpdateTopicNum = LIMIT;
    _modulesLogger2['default'].info(src.id, functionName + 'Begin working');
    _async2['default'].whilst(function () {
      totalTopicNum = totalTopicNum + oneRoundUpdateTopicNum;
      _modulesLogger2['default'].info(src.id, functionName + 'Finish one round with topic number ' + oneRoundUpdateTopicNum + ' total=' + totalTopicNum);
      if (oneRoundUpdateTopicNum < LIMIT) {
        return false;
      }
      return true;
    }, function (interCallback) {
      var queryCondition = undefined;
      if (cursorId) {
        queryCondition = { _id: { $gt: cursorId } };
      }
      var exeobj = Topic.find(queryCondition).sort({ _id: 1 }).limit(LIMIT);
      _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, result) {
        if (err) {
          _modulesLogger2['default'].error(src.id, functionName + 'Query for topic happen error', err);
          return interCallback(err);
        }
        _async2['default'].each(result, function (topicObj, interCallback2) {
          _utilsDbwrapper2['default'].execute(TopicUser, TopicUser.update, src.id, { targetId: topicObj._id }, { $set: { targetType: _utilsServerConstants2['default'].TypeTopic, title: topicObj.title } }, { multi: true }, function (err, result) {
            interCallback2(err, result);
          });
        }, function (err, updateResult) {
          if (err) {
            _modulesLogger2['default'].error(src.id, functionName + 'Update topic title happen error', err);
          }
          oneRoundUpdateTopicNum = result.length;
          if (oneRoundUpdateTopicNum >= LIMIT) {
            cursorId = result[oneRoundUpdateTopicNum - 1]._id;
          }
          interCallback(err);
        });
      });
    }, function (err, result) {
      if (err) {
        _modulesLogger2['default'].warn(src.id, functionName + 'Update title into topicuser table task happen error', err);
      } else {
        _modulesLogger2['default'].info(src.id, functionName + 'Update title into topicuser table task done', err);
      }
      return cb(err, result);
    });
  };
  
  var funcNameMap = {
    'fillRelation': fillRelation,
    'cacheTitleIntoTopicUser': cacheTitleIntoTopicUser
  };
  
  var TaskeHandleNotifier = (function (_EventEmitter) {
    _inherits(TaskeHandleNotifier, _EventEmitter);
  
    function TaskeHandleNotifier() {
      _classCallCheck(this, TaskeHandleNotifier);
  
      _get(Object.getPrototypeOf(TaskeHandleNotifier.prototype), 'constructor', this).call(this);
    }
  
    return TaskeHandleNotifier;
  })(_events2['default']);
  
  var TaskeHandleNotifierObj = new TaskeHandleNotifier();
  
  var migrateTaskHandle = function migrateTaskHandle(src, mgdata, cb) {
    _modulesLogger2['default'].info(src.id, "Begin call handle migrateTaskHandle");
    var funcName = mgdata.funcName;
    if (funcName in funcNameMap) {
      src.migrateId = mgdata.migrateId;
      src.funcName = funcName;
      _utilsDbwrapper2['default'].execute(_migrateModel2['default'], _migrateModel2['default'].findOne, src.id, { migrateId: mgdata.migrateId }, function (err, result) {
        if (result) {
          var migrateData = {};
          if (result.migrateData) {
            migrateData = result.migrateData;
          }
          funcNameMap[funcName](src, migrateData, function (err, result) {
            if (!err || err.code == _errorsErrors2['default'].TaskNoRetryError) {
              RemoveMigrateTask(src, mgdata.migrateId);
            } else {
              if (mgdata.attempt_times >= mgdata.attempts) {
                SetFailedStatusMigrateTask(src, mgdata.migrateId);
              }
            }
  
            if (cb) {
              return cb(err, result);
            }
            setTimeout(function () {
              TaskeHandleNotifierObj.emit('finish', mgdata);
            }, 2000);
          });
        } else {
          _modulesLogger2['default'].info(src.id, "Get error from migrateDB", err);
          _modulesLogger2['default'].info(src.id, 'Query migrate data happen error!, end the migrate process');
          if (cb) {
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
          }
          setTimeout(function () {
            TaskeHandleNotifierObj.emit('finish', mgdata);
          }, 2000);
        }
      });
    } else {
      _modulesLogger2['default'].info(src.id, "There is no funcname in map " + funcName);
      RemoveMigrateTask(src, mgdata.migrateId);
      if (cb) {
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
      }
      setTimeout(function () {
        TaskeHandleNotifierObj.emit('finish', mgdata);
      }, 2000);
    }
  };
  
  _taskqueueTaskqueueBackend2['default'].registerDeferHandle('migrateTaskHandle', migrateTaskHandle);
  
  function RemoveMigrateTask(src, mgId, cb) {
    var exeObj = _migrateModel2['default'].remove({ migrateId: mgId });
    _utilsDbwrapper2['default'].execute(exeObj, exeObj.exec, src.id, function (err, result) {});
  }
  
  function SetFailedStatusMigrateTask(src, mgId, cb) {
    _utilsDbwrapper2['default'].execute(_migrateModel2['default'], _migrateModel2['default'].update, src.id, { migrateId: src.migrateId }, { status: _utilsServerConstants2['default'].MigrateFailedStatus }, function (err, result) {});
  }
  
  exports.lauchMigrate = function (src, data, cb) {
    var mgdata = { migrateId: src.id, funcName: data.funcName };
    var deferCallback = function deferCallback(err, result) {
      if (err) {
        if (cb) {
          return cb(err);
        }
        return;
      }
      var savedData = {
        migrateId: mgdata.migrateId
      };
      _utilsDbwrapper2['default'].execute(_migrateModel2['default'], _migrateModel2['default'].create, src.id, savedData, function (err, result) {
        if (err) {
          if (cb) {
            return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].RecordMigrageError));
          }
        }
        if (cb) {
          return cb(null, src.fullurl + '/api/migrate/' + result._id);
        }
      });
    };
    _taskqueueTaskqueueBackend2['default'].launchDefer(src, 'migrateTaskHandle', mgdata, { defferOption: true,
      backoff_seconds: 300,
      attempts: 3,
      callback: deferCallback
    });
  };
  
  exports.migrateQuery = function (src, data, cb) {
    _utilsDbwrapper2['default'].execute(_migrateModel2['default'], _migrateModel2['default'].findOne, src.id, { '_id': data }, function (err, result) {
      if (err) {
        return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].RecordMigrageError));
      }
      if (result) {
        if (result.status == _utilsServerConstants2['default'].MigrateFailedStatus) {
          return cb(null, { status: 'failed' });
        }
        return cb(null, { status: 'in_progressing' });
      } else {
        return cb(null, { status: 'success' });
      }
    });
  };
  
  if (__webpack_require__.c[0] === module) {
    var process = __webpack_require__(21);
    var exescriptName = 'cacheTitleIntoTopicUser';
    var config = __webpack_require__(4);
    var mongoose = __webpack_require__(5);
    process.env.DeferType = 'timeout';
  
    mongoose.connect(config.mongo.uri, config.mongo.options);
    mongoose.connection.on('connected', function () {
      _modulesLogger2['default'].info('MongoDB connected');
      process.env['mongoUA'] = 'connected';
      setTimeout(function () {
        console.log('Migrate from command line ' + exescriptName);
        exports.lauchMigrate({ id: 'migrate_command_request' }, { funcName: exescriptName });
      }, 6000);
    });
    mongoose.connection.on('error', function (err) {
      _modulesLogger2['default'].error('MongoDB connection error: ' + err);
      mongoose.disconnect();
    });
    mongoose.connection.on('disconnected', function () {
      _modulesLogger2['default'].warn('MongoDB disconnected! Reconnecting in 3 seconds');
      process.env['mongoUA'] = 'disconnected';
    });
  
    TaskeHandleNotifierObj.on('finish', function (mgdata) {
      setTimeout(function () {
        console.log('Migrate from command line ' + exescriptName + ' Finished');
        process.exit(1);
      }, QuitHandleTimeout);
    });
  }
  /* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(154)(module)))

/***/ },
/* 117 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _viewBaseViewBase2 = _interopRequireDefault(_viewBaseViewBase);
  
  var _authAuthorizers = __webpack_require__(24);
  
  var _authAuthorizers2 = _interopRequireDefault(_authAuthorizers);
  
  var _migrateBackend = __webpack_require__(116);
  
  var _migrateBackend2 = _interopRequireDefault(_migrateBackend);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _querystring = __webpack_require__(45);
  
  var _querystring2 = _interopRequireDefault(_querystring);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  exports.migrate = (function (_vw$ViewBase) {
    _inherits(migrateView, _vw$ViewBase);
  
    function migrateView() {
      _classCallCheck(this, migrateView);
  
      _get(Object.getPrototypeOf(migrateView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(migrateView, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var data = req.body;
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        _migrateBackend2['default'].lauchMigrate(src, data, function (err, result) {
          if (err) {
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(err);
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json({ url: _querystring2['default'].escape(result) });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_MIGRATE)],
      enumerable: true
    }]);
  
    return migrateView;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.migrateQuery = (function (_vw$ViewBase2) {
    _inherits(migrateQueryView, _vw$ViewBase2);
  
    function migrateQueryView() {
      _classCallCheck(this, migrateQueryView);
  
      _get(Object.getPrototypeOf(migrateQueryView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(migrateQueryView, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        var data = req.params['id'];
        _migrateBackend2['default'].migrateQuery(src, data, function (err, result) {
          if (err) {
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(err);
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(result);
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_MIGRATE)],
      enumerable: true
    }]);
  
    return migrateQueryView;
  })(_viewBaseViewBase2['default'].ViewBase);

/***/ },
/* 118 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var mongoose = __webpack_require__(5),
      Schema = mongoose.Schema;
  
  var MigrateSchema = new Schema({
      created: { type: Date, 'default': Date.now },
      migrateId: { type: String },
      migrateData: Schema.Types.Mixed,
      status: { type: String }
  });
  
  module.exports = mongoose.model('Migrate', MigrateSchema);

/***/ },
/* 119 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var _topicTopicModel = __webpack_require__(18);
  
  var _topicTopicModel2 = _interopRequireDefault(_topicTopicModel);
  
  var _userUserModel = __webpack_require__(14);
  
  var _userUserModel2 = _interopRequireDefault(_userUserModel);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _util = __webpack_require__(12);
  
  var _util2 = _interopRequireDefault(_util);
  
  var _taskqueueTaskqueueBackend = __webpack_require__(22);
  
  var _taskqueueTaskqueueBackend2 = _interopRequireDefault(_taskqueueTaskqueueBackend);
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _notifyTopicuserModel = __webpack_require__(46);
  
  var _notifyTopicuserModel2 = _interopRequireDefault(_notifyTopicuserModel);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  function cacheOneRound(src, paramsData, cb) {
    var functionName = '[cacheOneRound] ';
    var data = paramsData.taskData;
    var achedObjCompareData = data.cachedObjCompareData;
    var cachedObjId = data.cachedObjId;
    var cachedObjType = data.cachedObjType;
    var cursorId = data.cursorId || '';
    var LIMIT_RECS = 10;
    _async2['default'].waterfall([function (interCallback) {
      _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Get cached Object by id=%s, type=%s', functionName, cachedObjId, cachedObjType));
      if (cachedObjType == _utilsServerConstants2['default'].TypeTopic) {
        _utilsDbwrapper2['default'].execute(_topicTopicModel2['default'], _topicTopicModel2['default'].findById, src.id, { _id: cachedObjId }, function (err, topicObj) {
          if (err) {
            _modulesLogger2['default'].error(src.id, _util2['default'].format('%s Get topic by id=%s failed.', functionName, cachedObjId), err);
            return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          } else if (!topicObj) {
            _modulesLogger2['default'].warn(src.id, _util2['default'].format('%s Get topic by id=%s get empty data', functionName, cachedObjId));
            return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          } else {
            return interCallback(cb, topicObj.title, topicObj);
          }
        });
      } else if (cachedObjType == _utilsServerConstants2['default'].TypeUser) {
        _utilsDbwrapper2['default'].execute(_userUserModel2['default'], _userUserModel2['default'].findById, src.id, { _id: cachedObjId }, function (err, userObj) {
          if (err) {
            _modulesLogger2['default'].error(src.id, _util2['default'].format('%s Get user by id=%s failed.', functionName, cachedObjId), err);
            return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          } else if (!userObj) {
            _modulesLogger2['default'].warn(src.id, _util2['default'].format('%s Get user by id=%s get empty data', functionName, cachedObjId));
            return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          } else {
            return interCallback(cb, userObj.username + userObj.displayname, userObj);
          }
        });
      } else {
        _modulesLogger2['default'].warn(src.id, _util2['default'].format('%s Not support cache cachedObjType', functionName, cachedObjType));
        return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
      }
    }, function (cachedObjComparedDataR, cachedObj, interCallback) {
      if (cachedObjComparedDataR != achedObjCompareData) {
        _modulesLogger2['default'].info(src.id, _util2['default'].format('%s cached object been changed again during cache, cancel cache. new cachedObjComparedData=%s, old cachedObjComparedData=%s', functionName, cachedObjComparedDataR, achedObjCompareData));
        return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
      } else {
        var queryCondition = {};
        var shouldUpdateTags = false;
        if (cachedObjType == _utilsServerConstants2['default'].TypeTopic) {
          queryCondition.targetId = cachedObjId;
          queryCondition.targetType = cachedObjType;
        } else if (cachedObjType == _utilsServerConstants2['default'].TypeUser) {
          queryCondition.userId = cachedObjId;
          queryCondition.userType = cachedObjType;
        } else {
          _modulesLogger2['default'].warn(src.id, _util2['default'].format('%s Not support cache cachedObjType', functionName, cachedObjType));
          return interCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskNoRetryError));
        }
        if (shouldUpdateTags) {
          (function () {
            if (cursorId) {
              queryCondition._id = { $gt: cursorId };
            }
            var sortVar = { _id: 1 };
            _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Will query TopicUser by.', functionName), queryCondition, sortVar, LIMIT_RECS);
            var exeobj = _notifyTopicuserModel2['default'].find(queryCondition).sort(sortVar).limit(LIMIT_RECS);
            var partialTags = _utilsServerHelper2['default'].getTagsByType(cachedObj, cachedObjType);
            _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, data) {
              if (err) {
                _modulesLogger2['default'].error(src.id, _util2['default'].format('%s Query TopicUser failed', functionName), err);
                return interCallback(err);
              }
              _async2['default'].each(data, function (topicUserObj, interCallback2) {
                if (cachedObjType == _utilsServerConstants2['default'].TypeTopic) {
                  topicUserObj.tags = (function () {
                    var _topicUserObj$tags = [];
                    var _iteratorNormalCompletion = true;
                    var _didIteratorError = false;
                    var _iteratorError = undefined;
  
                    try {
                      for (var _iterator = topicUserObj.tags[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
                        var tagItem = _step.value;
  
                        if (!tagItem.startsWith(_utilsServerConstants2['default'].topicTagPrefix)) {
                          _topicUserObj$tags.push(tagItem);
                        }
                      }
                    } catch (err) {
                      _didIteratorError = true;
                      _iteratorError = err;
                    } finally {
                      try {
                        if (!_iteratorNormalCompletion && _iterator['return']) {
                          _iterator['return']();
                        }
                      } finally {
                        if (_didIteratorError) {
                          throw _iteratorError;
                        }
                      }
                    }
  
                    return _topicUserObj$tags;
                  })();
                }
                if (cachedObjType == _utilsServerConstants2['default'].TypeUser) {
                  topicUserObj.tags = (function () {
                    var _topicUserObj$tags2 = [];
                    var _iteratorNormalCompletion2 = true;
                    var _didIteratorError2 = false;
                    var _iteratorError2 = undefined;
  
                    try {
                      for (var _iterator2 = topicUserObj.tags[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
                        var tagItem = _step2.value;
  
                        if (!tagItem.startsWith(_utilsServerConstants2['default'].userTagPrefix)) {
                          _topicUserObj$tags2.push(tagItem);
                        }
                      }
                    } catch (err) {
                      _didIteratorError2 = true;
                      _iteratorError2 = err;
                    } finally {
                      try {
                        if (!_iteratorNormalCompletion2 && _iterator2['return']) {
                          _iterator2['return']();
                        }
                      } finally {
                        if (_didIteratorError2) {
                          throw _iteratorError2;
                        }
                      }
                    }
  
                    return _topicUserObj$tags2;
                  })();
                }
                topicUserObj.tags = _lodash2['default'].concat(topicUserObj.tags, partialTags);
                _modulesLogger2['default'].info(src.id, _util2['default'].format('%S Will save topicUser=%s with tags', functionName, topicUserObj._id.toString()), topicUserObj.tags);
                data.save(function (err) {
                  if (err) {
                    _modulesLogger2['default'].error(src.id, _util2['default'].format('%S Save topicUser=%s with tags failed', functionName, topicUserObj._id.toString()), err);
                    return interCallback2(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].DBError));
                  } else {
                    return interCallback2(null);
                  }
                });
              }, function (err) {
                if (!err && data.length > 0 && data.length >= LIMIT_RECS) {
                  data.cursorId = data[data.length - 1]._id.toString();
                  return interCallback(err, data.cursorId);
                } else {
                  return interCallback(err, '');
                }
              });
            });
          })();
        }
      }
    }], function (err, result) {
      if (err) {
        _modulesLogger2['default'].info(src.id, _util2['default'].format('%s Failed to cache for this round', functionName));
      }
      return cb(err, result);
    });
  }
  
  function cacheTopicUserDeferEntry(src, paramsData, cb) {
    var functionName = '[cacheTopicUserDeferEntry] ';
    var data = paramsData.data;
    var taskKey = paramsData.taskKey;
    _modulesLogger2['default'].info(src.id, _util2['default'].format("%s Begin ToicUser with data", functionName), paramsData);
    _async2['default'].whilst(function () {
      if (_utilsServerHelper2['default'].requestWillEndSoon(src)) {
        _modulesLogger2['default'].info(src.id, functionName + 'This request will end soon, create another taskqueue to continue working');
        _taskqueueTaskqueueBackend2['default'].launchDefer(src, taskKey, data, { defferOption: true,
          backoff_seconds: 300,
          attempts: 3,
          callback: function callback(err, result) {
            if (!err) {
              _modulesLogger2['default'].info(src.id, _util2['default'].format('%s trigger a task to do cache work successfuly', functionName));
            } else {
              _modulesLogger2['default'].error(src.id, _util2['default'].format('%s trigger a task to do cache work failed', functionName), err);
            }
          }
        });
        return false;
      }
      return continueVar;
    }, function (interCallback) {
      cacheOneRound(src, paramsData, function (err, result) {
        if (!result) {
          continueVar = false;
        }
        return interCallback(err, result);
      });
    }, function (err, result) {
      _modulesLogger2['default'].info(src.id, _util2['default'].format("%s This task of cachcing ToicpUser finished", functionName));
      return cb(err, result);
    });
  }
  
  function cacheTopicToTopicUserDefer(src, data, cb) {
    var functionName = '[cacheTopicToTopicUserDefer] ';
    _modulesLogger2['default'].info(src.id, _util2['default'].format("%s Begin cache topic info to ToicUser with data", functionName), data);
    var continueVar = true;
    var paramsData = {
      taskData: data,
      taskKey: 'cacheTopicToTopicUserDefer'
    };
    cacheTopicUserDeferEntry(src, paramsData, function (err, result) {
      if (!err && !result) {
        _modulesLogger2['default'].info(src.id, _util2['default'].format("%s Update topicuser's title information", functionName));
        var updateCondition = {
          targetId: data.cachedObjId,
          targetType: data.cachedObjType
        };
        _utilsDbwrapper2['default'].execute(_notifyTopicuserModel2['default'], _notifyTopicuserModel2['default'].update, src.id, updateCondition, { '$set': { 'title': data.cachedObjCompareData } }, { multi: true }, function (err, userObj) {
          if (err) {
            _modulesLogger2['default'].error(src.id, _util2['default'].format("%s Update topic user title happen error", functionName), err);
          }
          return cb(err, result);
        });
      } else {
        return cb(err, result);
      }
    });
  }
  
  function cacheUserToTopicUserDefer(src, data, cb) {
    var functionName = '[cacheUserToTopicUserDefer] ';
    _modulesLogger2['default'].info(src.id, _util2['default'].format("%s Begin cache topic info to ToicUser with data", functionName), data);
    var continueVar = true;
    var paramsData = {
      taskData: data,
      taskKey: 'cacheUserToTopicUserDefer'
    };
    cacheTopicUserDeferEntry(src, paramsData, cb);
  }
  
  _taskqueueTaskqueueBackend2['default'].registerDeferHandle('cacheTopicToTopicUserDefer', cacheTopicToTopicUserDefer);
  _taskqueueTaskqueueBackend2['default'].registerDeferHandle('cacheUserToTopicUserDefer', cacheUserToTopicUserDefer);

/***/ },
/* 120 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  //Version 1.0
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _syncController = __webpack_require__(121);
  
  var _syncController2 = _interopRequireDefault(_syncController);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _authAuthService = __webpack_require__(15);
  
  var _authAuthService2 = _interopRequireDefault(_authAuthService);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var router = new _express.Router();
  
  router.post('/users', (0, _viewBaseViewBase.asView)(_syncController2['default'].syncUsers));
  router.post('/companies', (0, _viewBaseViewBase.asView)(_syncController2['default'].syncCompanies));
  router.post('/permissiongroup', (0, _viewBaseViewBase.asView)(_syncController2['default'].syncPermissionGroup));
  // router.get('/:id/colleagues/topics', asView(controller.listTopicsForColleagues));
  
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 121 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _userUserModel = __webpack_require__(14);
  
  var _userUserModel2 = _interopRequireDefault(_userUserModel);
  
  var _passport = __webpack_require__(25);
  
  var _passport2 = _interopRequireDefault(_passport);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _jsonwebtoken = __webpack_require__(29);
  
  var _jsonwebtoken2 = _interopRequireDefault(_jsonwebtoken);
  
  var _escapeStringRegexp = __webpack_require__(42);
  
  var _escapeStringRegexp2 = _interopRequireDefault(_escapeStringRegexp);
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _modulesEmailEmailController = __webpack_require__(82);
  
  var _modulesEmailEmailController2 = _interopRequireDefault(_modulesEmailEmailController);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  var _authAuthService = __webpack_require__(15);
  
  var _authAuthService2 = _interopRequireDefault(_authAuthService);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _viewBaseViewBase2 = _interopRequireDefault(_viewBaseViewBase);
  
  var _userUserBackend = __webpack_require__(23);
  
  var _userUserBackend2 = _interopRequireDefault(_userUserBackend);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _syncBackendJs = __webpack_require__(73);
  
  var _syncBackendJs2 = _interopRequireDefault(_syncBackendJs);
  
  var _authPermissiongroupModel = __webpack_require__(79);
  
  var _authPermissiongroupModel2 = _interopRequireDefault(_authPermissiongroupModel);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var ObjectId = _mongoose2['default'].Schema.Types.ObjectId;
  
  var validationError = function validationError(res, err) {
    return res.status(422).json(err);
  };
  
  exports.syncUsers = (function (_vw$serverCallView) {
    _inherits(syncUsers, _vw$serverCallView);
  
    function syncUsers() {
      _classCallCheck(this, syncUsers);
  
      _get(Object.getPrototypeOf(syncUsers.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(syncUsers, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        var data = { users: req.body };
        src.fn = '[syncUsers]';
        _modulesLoggerIndex2['default'].info(src.id, '[syncUsers]Start syncing users from ' + _config2['default'].getEsnaLink(src.domain));
        _syncBackendJs2['default'].syncUsers(src, data, function (err, result) {
          if (err) {
            _modulesLoggerIndex2['default'].error(src.id, '[syncUsers]Error syncing users', err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
          }
          _modulesLoggerIndex2['default'].info(src.id, '[syncUsers]Sync finished : ');
          res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send(result);
        });
      }
    }]);
  
    return syncUsers;
  })(_viewBaseViewBase2['default'].serverCallView);
  
  exports.syncCompanies = (function (_vw$serverCallView2) {
    _inherits(syncCompanies, _vw$serverCallView2);
  
    function syncCompanies() {
      _classCallCheck(this, syncCompanies);
  
      _get(Object.getPrototypeOf(syncCompanies.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(syncCompanies, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        src.fn = '[syncCompanies]';
        var data = { companies: req.body };
  
        _modulesLoggerIndex2['default'].info(src.id, '[syncCompanies]Start syncing companies from ' + _config2['default'].getEsnaLink(src.domain) + ' with payload', data);
        _syncBackendJs2['default'].syncCompanies(src, data, function (err, result) {
          if (err) {
            _modulesLoggerIndex2['default'].error(src.id, '[syncCompanies]Error syncing companies', err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
          }
          _modulesLoggerIndex2['default'].info(src.id, '[syncCompanies]Sync finished : ');
          _modulesLoggerIndex2['default'].debug(src.id, '[syncCompanies]Sync result to onesna:', result);
          res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send(result);
        });
      }
    }]);
  
    return syncCompanies;
  })(_viewBaseViewBase2['default'].serverCallView);
  /**
   * Authentication callback
   */
  exports.authCallback = function (req, res, next) {
    res.redirect('/');
  };
  
  exports.syncPermissionGroup = (function (_vw$serverCallView3) {
    _inherits(syncPermissionGroup, _vw$serverCallView3);
  
    function syncPermissionGroup() {
      _classCallCheck(this, syncPermissionGroup);
  
      _get(Object.getPrototypeOf(syncPermissionGroup.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(syncPermissionGroup, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        var postData = {
          ndbid: req.body.id || '',
          description: req.body.description || '',
          name: req.body.name || '',
          type: req.body.type || '',
          permission_name: req.body.permission_name || '',
          permissions: req.body.permissions || []
        };
        if (!postData.permission_name) {
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
        _utilsDbwrapper2['default'].execute(_authPermissiongroupModel2['default'], _authPermissiongroupModel2['default'].findOneAndUpdate, src, { permission_name: postData.permission_name }, postData, { upsert: true, 'new': true }, function (err, result) {
          if (err) {
            _modulesLoggerIndex2['default'].error(src, 'syncPermissionGroup happen error', err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SysUnkownError));
          } else {
            res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(result.toJSON());
          }
        });
      }
    }]);
  
    return syncPermissionGroup;
  })(_viewBaseViewBase2['default'].serverCallView);

/***/ },
/* 122 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * author: Eric Ding
   */
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _taskController = __webpack_require__(124);
  
  var _taskController2 = _interopRequireDefault(_taskController);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var router = new _express.Router();
  
  router.get('/:taskId/messages', (0, _viewBaseViewBase.asView)(_taskController2['default'].listMessagesView));
  router['delete']('/:taskId', (0, _viewBaseViewBase.asView)(_taskController2['default'].deleteTask));
  
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 123 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * author: Eric Ding
   */
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  exports.listMessagesByTask = function (src, data, cb) {
    var matchCondition = {
      "parentMsg._id": _mongoose2['default'].Types.ObjectId(data.taskId)
    };
  
    var sort = { _id: -1 };
    if (data.page <= 1) {
      delete data.nextRefObjId;
      delete data.prevRefObjId;
      data.page = 1;
    }
    var includeEqual = data.includeEqual || false;
    delete data.includeEqual;
    if (data.nextRefObjId) {
      if (includeEqual) {
        matchCondition["_id"] = { $lte: _mongoose2['default'].Types.ObjectId(data.nextRefObjId) };
      } else {
        matchCondition["_id"] = { $lt: _mongoose2['default'].Types.ObjectId(data.nextRefObjId) };
      }
      sort = { _id: -1 };
    } else if (data.prevRefObjId) {
      if (includeEqual) {
        matchCondition["_id"] = { $gte: _mongoose2['default'].Types.ObjectId(data.prevRefObjId) };
      } else {
        matchCondition["_id"] = { $gt: _mongoose2['default'].Types.ObjectId(data.prevRefObjId) };
      }
      sort = { _id: 1 };
    }
    var exeobj = _messageMessageModel2['default'].find(matchCondition).sort(sort).limit(data.size + 1);
    _utilsDbwrapper2['default'].execute(exeobj, exeobj.exec, src.id, function (err, results) {
      if (err) {
        logger.error(src.id, 'listCommentsByTask happen error', err.message);
        return cb(null, { results: [] });
      }
      if (results.length > data.size) {
        if (data.prevRefObjId) {
          results = results.reverse();
          return cb(null, { results: results.slice(1, data.size + 1), havingNextPage: true });
        }
        return cb(null, { results: results.slice(0, data.size), havingNextPage: true });
      } else {
        if (data.prevRefObjId) {
          results = results.reverse();
        }
        return cb(null, { results: results, havingNextPage: false });
      }
    });
  };

/***/ },
/* 124 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * author: Eric Ding
   */
  
  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _viewBaseViewBase2 = _interopRequireDefault(_viewBaseViewBase);
  
  var _messageMessageBackend = __webpack_require__(26);
  
  var _messageMessageBackend2 = _interopRequireDefault(_messageMessageBackend);
  
  var _taskBackend = __webpack_require__(123);
  
  var _taskBackend2 = _interopRequireDefault(_taskBackend);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _messageMessageModel = __webpack_require__(13);
  
  var _messageMessageModel2 = _interopRequireDefault(_messageMessageModel);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  var _fluxConstantsMessageConstants = __webpack_require__(17);
  
  var _fluxConstantsMessageConstants2 = _interopRequireDefault(_fluxConstantsMessageConstants);
  
  var _messageMessageEvent = __webpack_require__(16);
  
  var _messageMessageEvent2 = _interopRequireDefault(_messageMessageEvent);
  
  var _authAuthorizers = __webpack_require__(24);
  
  var _authAuthorizers2 = _interopRequireDefault(_authAuthorizers);
  
  exports.deleteTask = (function (_vw$ViewBase) {
    _inherits(deleteTask, _vw$ViewBase);
  
    function deleteTask() {
      _classCallCheck(this, deleteTask);
  
      _get(Object.getPrototypeOf(deleteTask.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(deleteTask, [{
      key: 'handle',
      value: function handle(req, res, cb) {
  
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        var task = req.message;
        req.relPermChecker.checkRelation(src, task.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
          if (err) {
            return cb(err);
          }
          task.remove(function (err, result) {
            if (err) {
              _modulesLoggerIndex2['default'].error(req.id, 'Error deleting task', err);
              return cb(res, new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
            }
            _messageMessageEvent2['default'].emitCardDeleted(src, task);
            return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send();
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_UPDATE)],
      enumerable: true
    }]);
  
    return deleteTask;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  var listMessagesView = (function (_vw$anyCallView) {
    _inherits(listMessagesView, _vw$anyCallView);
  
    function listMessagesView() {
      _classCallCheck(this, listMessagesView);
  
      _get(Object.getPrototypeOf(listMessagesView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(listMessagesView, [{
      key: '_listMessages',
      value: function _listMessages(req, queryData, cb) {
        var self = this;
        _taskBackend2['default'].listMessagesByTask(req, queryData, function (err, results) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'listCommentsView call _listComments happen error', err.message);
            return cb(err);
          }
          if (queryData.prevRefObjId && results.results.length < queryData.size) {
            delete queryData.prevRefObjId;
            queryData.page = 1;
            return self._listMessages(req, queryData, cb);
          } else if (results.results.length === 0 && queryData.nextRefObjId) {
            queryData.prevRefObjId = queryData.nextRefObjId;
            delete queryData.nextRefObjId;
            queryData.page -= 1;
            queryData.includeEqual = true;
            return self._listMessages(req, queryData, function (err, data) {
              if (data.results) {
                data.results.havingNextPage = false;
              }
              return cb(null, data);
            });
          }
          delete queryData.taskId;
          var data = {
            queryData: queryData,
            results: results
          };
          return cb(null, data);
        });
      }
    }, {
      key: 'handle',
      value: function handle(req, res, cb) {
        //Be care don't need embed parent message
        var queryData = {
          taskId: req.params.taskId,
          size: _utilsServerHelper2['default'].getListOfItemCaps(req.query.size, 30),
          page: parseInt(req.query.page) || 1,
          nextRefObjId: req.query.nextRefObjId,
          prevRefObjId: req.query.prevRefObjId
        };
  
        var self = this;
        _async2['default'].waterfall([function (internalCallback) {
          _utilsDbwrapper2['default'].execute(_messageMessageModel2['default'], _messageMessageModel2['default'].findOne, req.id, { _id: req.params.taskId }, function (err, taskMsg) {
            if (err) {
              _modulesLoggerIndex2['default'].error(req.id, err.message);
            }
            return internalCallback(err, taskMsg);
          });
        }, function (taskMsg, internalCallback) {
          if (!taskMsg) {
            _modulesLoggerIndex2['default'].error(req.id, "task with _id=" + req.params.taskId + " not exited");
            return internalCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          }
          if (taskMsg.category !== _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.TASK) {
            return internalCallback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].MessageUnexpectedCategory));
          }
          req.relPermChecker.checkRelation(req, taskMsg.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
            return internalCallback(err, taskMsg);
          });
        }, function (taskMsg, internalCallback) {
          self._listMessages(req, queryData, internalCallback);
        }, function (data, internalCallback) {
          _messageMessageBackend2['default'].toDownloadableClientFormatMessagesIngoreParentMsg(req, data.results.results, function (err, convertedResults) {
            if (err) {
              return internalCallback(err);
            }
            data.results.results = convertedResults;
            return internalCallback(null, data);
          });
        }], function (err, data) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, "listCommentsView happen error", err);
            if (err.code == _errorsErrors2['default'].AuthorizeErrorPermission) {
              return cb(err);
            }
            return res.json({ data: [], total: 0, nextPageUrl: '', previousPageUrl: '' });
          }
          return res.json(_utilsServerHelper2['default'].createPagination(req, data));
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_TASK_READ)],
      enumerable: true
    }]);
  
    return listMessagesView;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  exports.listMessagesView = listMessagesView;

/***/ },
/* 125 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  //Version 1.0
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _taskqueueController = __webpack_require__(126);
  
  var _taskqueueController2 = _interopRequireDefault(_taskqueueController);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _authAuthService = __webpack_require__(15);
  
  var _authAuthService2 = _interopRequireDefault(_authAuthService);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var router = new _express.Router();
  
  router.post('/runner', (0, _viewBaseViewBase.asView)(_taskqueueController2['default'].runner));
  router.post('/syncSenderOfMessages', (0, _viewBaseViewBase.asView)(_taskqueueController2['default'].syncSenderOfMessages));
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 126 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  var _authAuthService = __webpack_require__(15);
  
  var _authAuthService2 = _interopRequireDefault(_authAuthService);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _viewBaseViewBase2 = _interopRequireDefault(_viewBaseViewBase);
  
  var _taskqueueBackend = __webpack_require__(22);
  
  var _taskqueueBackend2 = _interopRequireDefault(_taskqueueBackend);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _util = __webpack_require__(12);
  
  var _util2 = _interopRequireDefault(_util);
  
  function ChangeTimeoutOfReqTask(req, inWaitSeconds) {
    var waitSeconds = inWaitSeconds || _utilsServerConstants2['default'].taskRequestTimeoutSeconds;
    req.taskRequestTimeout = Date.now() + waitSeconds * 1000;
    req.clearTimeout();
    var tmout = setTimeout(function () {
      req.timedout = true;
      req.emit('timeout', waitSeconds * 1000);
    }, waitSeconds * 1000);
    return tmout;
  }
  
  exports.runner = (function (_vw$serverCallView) {
    _inherits(runner, _vw$serverCallView);
  
    function runner() {
      _classCallCheck(this, runner);
  
      _get(Object.getPrototypeOf(runner.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(runner, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var tmout = ChangeTimeoutOfReqTask(req, this.waitforSeconds);
        _modulesLoggerIndex2['default'].info(req.id, 'Task queue will run a task');
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        req.connection.on('close', function () {
          _modulesLoggerIndex2['default'].warn(req.id, 'Connection is closed');
          src.esClosedFlag = true;
        });
        src.taskRequestTimeout = req.taskRequestTimeout;
        _taskqueueBackend2['default'].runner(src, req.body, function (err, result) {
          clearTimeout(tmout);
          if (err) {
            _modulesLoggerIndex2['default'].warn(req.id, 'Task queue runner happen error', err);
            if (err.code == _errorsErrors2['default'].SysAlreadyRegisterDeferError || err.code == _errorsErrors2['default'].TaskNoRetryError || err.code == _errorsErrors2['default'].TaskqueueEndBeforeTimout) {
              //Never try again
              return res.status(_utilsServerConstants2['default'].HttpErrorTaskQueueNeverTry).json(err);
            } else {
              return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(err);
            }
          } else {
            _modulesLoggerIndex2['default'].info(req.id, 'Task queue runner finish successfuly');
            return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json({ status: 'success' });
          }
        });
      }
    }]);
  
    return runner;
  })(_viewBaseViewBase2['default'].serverCallView);
  
  exports.syncSenderOfMessages = (function (_exports$runner) {
    _inherits(syncSenderOfMessages, _exports$runner);
  
    function syncSenderOfMessages() {
      _classCallCheck(this, syncSenderOfMessages);
  
      _get(Object.getPrototypeOf(syncSenderOfMessages.prototype), 'constructor', this).apply(this, arguments);
    }
  
    return syncSenderOfMessages;
  })(exports.runner);

/***/ },
/* 127 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var _querystring = __webpack_require__(45);
  
  var _querystring2 = _interopRequireDefault(_querystring);
  
  var _topicModel = __webpack_require__(18);
  
  var _topicModel2 = _interopRequireDefault(_topicModel);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _escapeStringRegexp = __webpack_require__(42);
  
  var _escapeStringRegexp2 = _interopRequireDefault(_escapeStringRegexp);
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _modulesEmailSendgrid = __webpack_require__(83);
  
  var _modulesEmailSendgrid2 = _interopRequireDefault(_modulesEmailSendgrid);
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  var _authAuthService = __webpack_require__(15);
  
  var _authAuthService2 = _interopRequireDefault(_authAuthService);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _viewBaseViewBase2 = _interopRequireDefault(_viewBaseViewBase);
  
  var _topicBackend = __webpack_require__(75);
  
  var _topicBackend2 = _interopRequireDefault(_topicBackend);
  
  var _userUserBackend = __webpack_require__(23);
  
  var _userUserBackend2 = _interopRequireDefault(_userUserBackend);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _topicInviteModel = __webpack_require__(58);
  
  var _topicInviteModel2 = _interopRequireDefault(_topicInviteModel);
  
  var _messageMessageBackend = __webpack_require__(26);
  
  var _messageMessageBackend2 = _interopRequireDefault(_messageMessageBackend);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _fluxConstantsMessageConstants = __webpack_require__(17);
  
  var _fluxConstantsMessageConstants2 = _interopRequireDefault(_fluxConstantsMessageConstants);
  
  var _authAuthorizers = __webpack_require__(24);
  
  var _authAuthorizers2 = _interopRequireDefault(_authAuthorizers);
  
  var _notifyNotifyEvent = __webpack_require__(56);
  
  var _notifyNotifyEvent2 = _interopRequireDefault(_notifyNotifyEvent);
  
  var _notifyNotifyBackend = __webpack_require__(70);
  
  var _notifyNotifyBackend2 = _interopRequireDefault(_notifyNotifyBackend);
  
  var _modulesAnalyticsGoogle = __webpack_require__(33);
  
  var _modulesAnalyticsGoogle2 = _interopRequireDefault(_modulesAnalyticsGoogle);
  
  var _modulesAnalyticsGoogleConstants = __webpack_require__(32);
  
  var _modulesAnalyticsGoogleConstants2 = _interopRequireDefault(_modulesAnalyticsGoogleConstants);
  
  var _topicEvent = __webpack_require__(76);
  
  var _topicEvent2 = _interopRequireDefault(_topicEvent);
  
  // Get list of topics
  
  exports.index = (function (_vw$DeveloperAdminView) {
    _inherits(index, _vw$DeveloperAdminView);
  
    function index() {
      _classCallCheck(this, index);
  
      _get(Object.getPrototypeOf(index.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(index, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        _topicModel2['default'].find(function (err, topics) {
          if (err) {
            return handleError(res, _errorsErrors2['default']);
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(topics);
        });
      }
    }]);
  
    return index;
  })(_viewBaseViewBase2['default'].DeveloperAdminView);
  
  // Get a single Topic
  
  exports.show = (function (_vw$ViewBase) {
    _inherits(show, _vw$ViewBase);
  
    function show() {
      _classCallCheck(this, show);
  
      _get(Object.getPrototypeOf(show.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(show, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        _topicModel2['default'].findById(req.params.topicId, function (err, topic) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'Error finding topic', err);
            return handleError(res, new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
          }
          if (!topic) {
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send('Not Found');
          }
          req.relPermChecker.checkRelation(req, topic, _utilsServerConstants2['default'].TypeTopic, function (err) {
            if (err) {
              return cb(err);
            }
            return res.json(topic);
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_READ)],
      enumerable: true
    }]);
  
    return show;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.join = (function (_vw$ViewBase2) {
    _inherits(join, _vw$ViewBase2);
  
    function join() {
      _classCallCheck(this, join);
  
      _get(Object.getPrototypeOf(join.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(join, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        var me = req.user || req.anonymousUser;
  
        var data = {
          user: me,
          topicId: req.params.topicId
        };
        _topicBackend2['default'].joinTopic(src, data, function (err, result) {
          if (err) {
            if (err.code == _errorsErrors2['default'].AuthorizeErrorPermission) {
              return cb(err);
            }
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
          }
          result.topic = result.topic.toJSON();
          result.topic.restrict = _topicBackend2['default'].convertTopicRestrictToStringList(src, result.topic);
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send(result);
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_READ)],
      enumerable: true
    }]);
  
    return join;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.create = (function (_vw$ViewBase3) {
    _inherits(create, _vw$ViewBase3);
  
    function create() {
      _classCallCheck(this, create);
  
      _get(Object.getPrototypeOf(create.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(create, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        _modulesLoggerIndex2['default'].info(req.id, 'begin Creating Topic');
        _topicModel2['default'].create(req.body, function (err, topic) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'Error creating topic', err);
            return handleError(res, new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
          }
          if (!topic) {
            return res.status(_utilsServerConstants2['default'].HttpNotFoundStatus).json(_errorsErrors2['default'].NotExsistedError);
          }
          return res.status(201).json(topic);
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_CREATE)],
      enumerable: true
    }]);
  
    return create;
  })(_viewBaseViewBase2['default'].ViewBase);
  // Creates a new Topic in the DB.
  
  // Updates an existing Topic in the DB.
  exports.update = (function (_vw$ViewBase4) {
    _inherits(update, _vw$ViewBase4);
  
    function update() {
      _classCallCheck(this, update);
  
      _get(Object.getPrototypeOf(update.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(update, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        if (req.body._id) {
          delete req.body._id;
        }
        _topicModel2['default'].findById(req.params.topicId, function (err, topic) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'Error finding topic', err);
            return handleError(res, new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
          }
          if (!topic) {
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          }
          req.relPermChecker.checkRelation(req, topic, _utilsServerConstants2['default'].TypeTopic, function (err) {
            if (err) {
              return cb(err);
            }
            var updated = _lodash2['default'].merge(topic, req.body);
            var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
            updated.save(function (err) {
              if (err) {
                return handleError(res, err);
              }
              _topicEvent2['default'].emitTopicUpdated(src, updated, topic);
              return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(topic);
            });
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_UPDATE)],
      enumerable: true
    }]);
  
    return update;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.getInvite = (function (_vw$ViewBase5) {
    _inherits(getInvite, _vw$ViewBase5);
  
    function getInvite() {
      _classCallCheck(this, getInvite);
  
      _get(Object.getPrototypeOf(getInvite.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(getInvite, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        _topicInviteModel2['default'].findById(req.params.inviteId, function (err, invite) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'Error finding topic', err);
            return handleError(res, new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
          }
          if (!invite) {
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(invite);
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [_authAuthorizers2['default'].isInviteCreatorByParams],
      enumerable: true
    }]);
  
    return getInvite;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.searchTopics = (function (_vw$ViewBase6) {
    _inherits(searchTopics, _vw$ViewBase6);
  
    function searchTopics() {
      _classCallCheck(this, searchTopics);
  
      _get(Object.getPrototypeOf(searchTopics.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(searchTopics, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var str,
            skip,
            limit,
            query = [];
        if (req.query) {
          str = req.query.search;
          skip = req.query.skip;
          limit = req.query.limit;
        }
  
        if (str) {
          str = (0, _escapeStringRegexp2['default'])(str);
          query.push({
            $match: {
              $or: [{ title: { $regex: str, $options: 'i' } }]
            }
          });
        }
  
        query.push({
          $project: {
            _id: 1,
            title: 1,
            d: 1,
            members: 1
          }
        });
  
        if (skip) {
          query.push({ $skip: skip });
        }
  
        if (limit) {
          query.push({ $limit: limit });
        }
  
        _topicModel2['default'].aggregate(query, function (err, topics) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'Error searching topic', err);
            return handleError(res, new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json({ data: topics });
        });
      }
    }]);
  
    return searchTopics;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.newTopic = (function (_vw$ViewBase7) {
    _inherits(newTopic, _vw$ViewBase7);
  
    function newTopic() {
      _classCallCheck(this, newTopic);
  
      _get(Object.getPrototypeOf(newTopic.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(newTopic, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        if (!req.body || !req.body.topic || !req.body.invitees) {
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
        if (!req.user) {
          return res.status(_utilsServerConstants2['default'].HttpUnauthorizedStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateFailed));
        }
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req),
            data = {
          creator: req.user,
          invitees: req.body.invitees,
          topic: req.body.topic,
          startDateTime: req.body.startDateTime,
          endDateTime: req.body.endDateTime,
          now: Date.now(),
          members: [],
          informChannel: req.body.informChannel || 'server'
        };
  
        _topicBackend2['default'].newTopic(src, data, function (err, data) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'Error creating topic', err);
            return handleError(res, new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(data);
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_CREATE), _authAuthorizers2['default'].isApprovedAuthorizer],
      enumerable: true
    }]);
  
    return newTopic;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.getMembersOfTopic = (function (_vw$anyCallView) {
    _inherits(getMembersOfTopic, _vw$anyCallView);
  
    function getMembersOfTopic() {
      _classCallCheck(this, getMembersOfTopic);
  
      _get(Object.getPrototypeOf(getMembersOfTopic.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(getMembersOfTopic, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        if (!req.params || !req.params.topicId) {
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send('Bad request');
        }
        req.relPermChecker.checkRelation(req, req.params.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
          if (err) {
            return cb(err);
          }
          var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
          var page = Number(req.query.page) || 1,
              size = _utilsServerHelper2['default'].getListOfItemCaps(parseInt(req.query.size), 20),
              size = size > 30 ? 30 : size,
              apiRoute = _config2['default'].getLink(req.esDomain) + '/api/topics/' + req.params.topicId + '/members';
          var data = {
            topicId: req.params.topicId,
            pagination: {
              skip: (page - 1) * size,
              limit: size,
              apiRoute: apiRoute
            },
            search: req.query.search
          };
          _topicBackend2['default'].getUsersOfTopic(src, data, function (err, result) {
            if (err) {
              _modulesLoggerIndex2['default'].error(err);
              if (err.code == _errorsErrors2['default'].AuthorizeErrorPermission) {
                return cb(err);
              }
              return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
            }
            var returnData = {
              data: result.data,
              from: (page - 1) * size + 1,
              to: (page - 1) * size + result.data.length
            };
            if (result.hasNext) {
              returnData.nextPageUrl = apiRoute + '?page=' + (page + 1) + '&size=' + size;
            }
            if (page > 1) {
              returnData.previousPageUrl = apiRoute + '?page=' + (page - 1) + '&size=' + size;
            }
            return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(returnData);
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_READ)],
      enumerable: true
    }]);
  
    return getMembersOfTopic;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  exports.quitTopic = (function (_vw$ViewBase8) {
    _inherits(quitTopic, _vw$ViewBase8);
  
    function quitTopic() {
      _classCallCheck(this, quitTopic);
  
      _get(Object.getPrototypeOf(quitTopic.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(quitTopic, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        if (!req.params || !req.params.topicId) {
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
        _topicModel2['default'].findById(req.params.topicId, function (err, topic) {
          if (err) {
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
          }
          if (!topic) {
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          }
  
          if (req.user) {
            _topicBackend2['default'].userQuitTopic(req.user, topic, function (err, result) {
              if (err) {
                return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
              }
              return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send(result);
            });
          }
  
          if (req.anonymous) {
            _topicBackend2['default'].anonymousQuitTopic(req.anonymous, topic, function (err, result) {
              if (err) {
                return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
              }
              return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send(result);
            });
          }
        });
      }
    }]);
  
    return quitTopic;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.removeFromTopic = (function (_vw$ViewBase9) {
    _inherits(removeFromTopic, _vw$ViewBase9);
  
    function removeFromTopic() {
      _classCallCheck(this, removeFromTopic);
  
      _get(Object.getPrototypeOf(removeFromTopic.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(removeFromTopic, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        if (!req.params || !req.params.tid || !req.params.uid) {
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
        _topicModel2['default'].findById(req.params.topicId, function (err, topic) {
          if (err) {
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
          }
          if (!topic) {
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].NotExsistedError));
          }
  
          _topicBackend2['default'].quitTopicById(req.params.uid, topic, function (err, result) {
            if (err) {
              return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
            }
            return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send(result);
          });
        });
      }
    }]);
  
    return removeFromTopic;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.addToTopic = (function (_vw$ViewBase10) {
    _inherits(addToTopic, _vw$ViewBase10);
  
    function addToTopic() {
      _classCallCheck(this, addToTopic);
  
      _get(Object.getPrototypeOf(addToTopic.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(addToTopic, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        if (!req.body || !req.params || !req.params.topicId || !req.body.invitees) {
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
  
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        src.fn = '[addToTopic]';
        _topicModel2['default'].findById(req.params.topicId, function (err, topic) {
          if (err || !topic) {
            _modulesLoggerIndex2['default'].error(src.id, src.fn + 'Error find topic :' + req.params.topicId, err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
          }
          req.relPermChecker.checkRelation(req, topic, _utilsServerConstants2['default'].TypeTopic, function (err) {
            if (err) {
              return cb(err);
            }
            var src = {
              id: req.id,
              type: 'req',
              domain: req.esDomain
            };
            var data = {
              creator: req.user,
              invitees: req.body.invitees,
              topic: topic,
              startDateTime: req.body.startDateTime,
              endDateTime: req.body.endDateTime,
              now: Date.now(),
              members: [],
              informChannel: req.body.informChannel || 'server'
            };
  
            _topicBackend2['default'].addToTopic(src, data, function (err, result) {
              if (err) {
                _modulesLoggerIndex2['default'].error(src.id, src.fn + 'Error add to topic :' + req.params.topicId, err);
                return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
              }
              return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(result);
            });
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_UPDATE), _authAuthorizers2['default'].isApprovedAuthorizer],
      enumerable: true
    }]);
  
    return addToTopic;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.joinTopicFromInvite = (function (_vw$anyCall4001View) {
    _inherits(joinTopicFromInvite, _vw$anyCall4001View);
  
    function joinTopicFromInvite() {
      _classCallCheck(this, joinTopicFromInvite);
  
      _get(Object.getPrototypeOf(joinTopicFromInvite.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(joinTopicFromInvite, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        if (!req.params || !req.params.inviteId) {
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
  
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        var data = {
          inviteId: req.params.inviteId,
          user: req.anonymousUser || req.user || undefined,
          anonymous: req.anonymousUser
        };
        _topicBackend2['default'].joinTopicFromInvite(src, data, function (err, result) {
          if (err) {
            _modulesLoggerIndex2['default'].error(src.id, 'Error join topic with inviteId: ' + req.params.inviteId, err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
          }
          _modulesLoggerIndex2['default'].info(src.id, 'This is the entry info of this user :', result);
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send(result);
        });
      }
    }]);
  
    return joinTopicFromInvite;
  })(_viewBaseViewBase2['default'].anyCall4001View);
  
  exports.deleteInvite = (function (_vw$ViewBase11) {
    _inherits(deleteInvite, _vw$ViewBase11);
  
    function deleteInvite() {
      _classCallCheck(this, deleteInvite);
  
      _get(Object.getPrototypeOf(deleteInvite.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(deleteInvite, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
  
        req.invite.remove(function (err, invite) {
          if (err) {
            _modulesLoggerIndex2['default'].error(src.id, 'Error delete inviteId : ', req.invite._id, err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
          }
          _modulesLoggerIndex2['default'].info(src.id, 'Deleting Invite Successful :', req.invite._id);
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).send();
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [_authAuthorizers2['default'].isInviteCreatorByParams],
      enumerable: true
    }]);
  
    return deleteInvite;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.updateInvite = (function (_vw$ViewBase12) {
    _inherits(updateInvite, _vw$ViewBase12);
  
    function updateInvite() {
      _classCallCheck(this, updateInvite);
  
      _get(Object.getPrototypeOf(updateInvite.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(updateInvite, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        if (!req.body) {
          _modulesLoggerIndex2['default'].error(req.id, '[updateInvite] No request body for post api');
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
  
        var postInvite = req.body.data;
        if (postInvite && postInvite._id.toString() !== req.invite._id.toString()) {
          _modulesLoggerIndex2['default'].error(req.id, '[updateInvite] update Invite id does not match in url');
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
  
        var data = {
          topic: req.topic,
          creator: req.me,
          oldInvite: req.invite,
          newInvite: postInvite,
          informChannel: req.body.informChannel
        };
  
        _topicBackend2['default'].updateInvite(src, data, function (err, result) {
          if (err) {
            _modulesLoggerIndex2['default'].error(src.id, src.fn + 'Error update invite :' + postInvite._id, err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].ServerInternalError));
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(result);
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [_authAuthorizers2['default'].isInviteCreatorByParams],
      enumerable: true
    }]);
  
    return updateInvite;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  function handleError(res, err) {
    return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(err);
  }
  
  var ListMessageByRefView = (function (_vw$anyCallView2) {
    _inherits(ListMessageByRefView, _vw$anyCallView2);
  
    function ListMessageByRefView() {
      _classCallCheck(this, ListMessageByRefView);
  
      _get(Object.getPrototypeOf(ListMessageByRefView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(ListMessageByRefView, [{
      key: '_queryByRef',
      value: function _queryByRef(req, queryData, cb) {
        var self = this;
        _messageMessageBackend2['default'].queryByRef(req, queryData, function (err, results) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'ListMessageByRefView call _queryByRef happen error', err.message);
            return cb(err);
          }
          if (queryData.prevRefObjId && results.results.length < queryData.size) {
            delete queryData.prevRefObjId;
            queryData.page = 1;
            return self._queryByRef(req, queryData, cb);
          } else if (results.results.length === 0 && queryData.nextRefObjId) {
            queryData.prevRefObjId = queryData.nextRefObjId;
            delete queryData.nextRefObjId;
            queryData.page -= 1;
            queryData.includeEqual = true;
            return self._queryByRef(req, queryData, function (err, data) {
              if (data.results) {
                data.results.havingNextPage = false;
              }
              return cb(null, data);
            });
          }
          delete queryData.topicId;
          var data = {
            queryData: queryData,
            results: results
          };
          return cb(null, data);
        });
      }
    }, {
      key: 'handle',
      value: function handle(req, res, cb) {
        var queryData = {
          topicId: req.params.topicId,
          refTime: req.query.refTime,
          direction: req.query.direction || _utilsServerConstants2['default'].DirectionAfter,
          size: _utilsServerHelper2['default'].getListOfItemCaps(parseInt(req.query.size), 30),
          nextRefObjId: req.query.nextRefObjId,
          prevRefObjId: req.query.prevRefObjId,
          page: parseInt(req.query.page) || 1,
          begObjectId: req.query.begObjectId
        };
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        if (queryData.nextRefObjId && queryData.prevRefObjId) {
          _modulesLoggerIndex2['default'].error(src.id, 'ListMessageByRefView don\'t accept nextRefObjId and prevRefObjId together');
          return res.json({ data: [], total: 0, nextPageUrl: '', previousPageUrl: '' });
        }
  
        this._queryByRef(src, queryData, function (err, data) {
          _messageMessageBackend2['default'].toDownloadableClientFormatMessages(src, data.results.results, function (err, convertedResults) {
            if (err) {
              return res.json({ data: [], total: 0, nextPageUrl: '', previousPageUrl: '' });
            }
            data.results.results = convertedResults;
            return res.json(_utilsServerHelper2['default'].createPagination(req, data));
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_READ)],
      enumerable: true
    }]);
  
    return ListMessageByRefView;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  exports.ListMessageByRefView = ListMessageByRefView;
  
  var ListOfTopicTasksView = (function (_vw$anyCallView3) {
    _inherits(ListOfTopicTasksView, _vw$anyCallView3);
  
    function ListOfTopicTasksView() {
      _classCallCheck(this, ListOfTopicTasksView);
  
      _get(Object.getPrototypeOf(ListOfTopicTasksView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(ListOfTopicTasksView, [{
      key: '_listTopic',
      value: function _listTopic(req, queryData, cb) {
        var self = this;
        _messageMessageBackend2['default'].listTaskByTopic(req, queryData, function (err, results) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'ListOfTopicTasksView call _listTopic happen error', err.message);
            return cb(err);
          }
          if (queryData.prev && results.results.length < queryData.size) {
            queryData.page = 1;
            delete queryData.prev;
            return self._listTopic(req, queryData, cb);
          } else if (results.results.length === 0 && queryData.page > 1 && !queryData.prev) {
            queryData.page -= 1;
            return self._listTopic(req, queryData, function (err, data) {
              if (data.results) {
                data.results.havingNextPage = false;
              }
              return cb(null, data);
            });
          }
          delete queryData.topicId;
          var data = {
            queryData: queryData,
            results: results
          };
          return cb(null, data);
        });
      }
    }, {
      key: 'handle',
      value: function handle(req, res, cb) {
        var _this = this;
  
        req.relPermChecker.checkRelation(req, req.params.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
          if (err) {
            return cb(err);
          }
          var queryData = {
            topicId: req.params.topicId,
            size: _utilsServerHelper2['default'].getListOfItemCaps(parseInt(req.query.size), 30),
            page: parseInt(req.query.page) || 1,
            category: _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.TASK,
            prev: req.query.prev || false
          };
          var orderVal = [["content.dueDate", 1]];
          if (req.query.order) {
            try {
              var order_obj = JSON.parse(_querystring2['default'].unescape(req.query.order));
              if (order_obj.length > 0) {
                orderVal = [];
                var _iteratorNormalCompletion = true;
                var _didIteratorError = false;
                var _iteratorError = undefined;
  
                try {
                  for (var _iterator = order_obj[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
                    var order_item = _step.value;
  
                    if (order_item.value == 'desc') {
                      orderVal.push([order_item.by, -1]);
                    } else {
                      orderVal.push([order_item.by, 1]);
                    }
                  }
                } catch (err) {
                  _didIteratorError = true;
                  _iteratorError = err;
                } finally {
                  try {
                    if (!_iteratorNormalCompletion && _iterator['return']) {
                      _iterator['return']();
                    }
                  } finally {
                    if (_didIteratorError) {
                      throw _iteratorError;
                    }
                  }
                }
              }
            } catch (e) {
              _modulesLoggerIndex2['default'].info(req.id, 'Parse order happen error = %s' + e + ' .Still use default order value');
              orderVal = [["content.dueDate", 1]];
            }
          }
          queryData.order = orderVal;
  
          var filterVal = {};
          if (req.query.filter) {
            try {
              var filterObj = JSON.parse(_querystring2['default'].unescape(req.query.filter));
              if (Object.prototype.toString.call(filterObj) === '[object Array]') {
                var _iteratorNormalCompletion2 = true;
                var _didIteratorError2 = false;
                var _iteratorError2 = undefined;
  
                try {
                  for (var _iterator2 = filterObj[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
                    var filterItem = _step2.value;
  
                    filterVal[filterItem.by] = filterItem.value;
                  }
                } catch (err) {
                  _didIteratorError2 = true;
                  _iteratorError2 = err;
                } finally {
                  try {
                    if (!_iteratorNormalCompletion2 && _iterator2['return']) {
                      _iterator2['return']();
                    }
                  } finally {
                    if (_didIteratorError2) {
                      throw _iteratorError2;
                    }
                  }
                }
              } else {
                filterVal[filterObj.by] = filterObj.value;
              }
            } catch (e) {
              _modulesLoggerIndex2['default'].info(req.id, 'Parse filter happen error = %s' + e + ' .Still use default order value');
              filterVal = {};
            }
          }
          queryData.filter = filterVal;
          var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
          _this._listTopic(src, queryData, function (err, data) {
            _messageMessageBackend2['default'].toDownloadableClientFormatMessages(src, data.results.results, function (err, convertedResults) {
              if (err) {
                return res.json({ data: [], total: 0, nextPageUrl: '', previousPageUrl: '' });
              }
              data.results.results = convertedResults;
              if (req.query.order) {
                data.queryData.order = req.query.order;
              } else {
                delete data.queryData.order;
              }
              if (req.query.filter) {
                data.queryData.filter = req.query.filter;
              } else {
                delete data.queryData.filter;
              }
              return res.json(_utilsServerHelper2['default'].createPaginationByPage(req, data));
            });
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_UPDATE)],
      enumerable: true
    }]);
  
    return ListOfTopicTasksView;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  exports.ListOfTopicTasksView = ListOfTopicTasksView;
  
  var ListOfTopicIdeasView = (function (_vw$anyCallView4) {
    _inherits(ListOfTopicIdeasView, _vw$anyCallView4);
  
    function ListOfTopicIdeasView() {
      _classCallCheck(this, ListOfTopicIdeasView);
  
      _get(Object.getPrototypeOf(ListOfTopicIdeasView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(ListOfTopicIdeasView, [{
      key: '_listTopic',
      value: function _listTopic(req, queryData, cb) {
        var self = this;
        _messageMessageBackend2['default'].listIdeaByTopic(req, queryData, function (err, results) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'ListOfTopicIdeasView call _listTopic happen error', err.message);
            return cb(err);
          }
          if (queryData.prev && results.results.length < queryData.size) {
            queryData.page = 1;
            delete queryData.prev;
            return self._listTopic(req, queryData, cb);
          } else if (results.results.length === 0 && queryData.page > 1 && !queryData.prev) {
            queryData.page -= 1;
            return self._listTopic(req, queryData, function (err, data) {
              if (data.results) {
                data.results.havingNextPage = false;
              }
              return cb(null, data);
            });
          }
  
          delete queryData.topicId;
          var data = {
            queryData: queryData,
            results: results
          };
          return cb(null, data);
        });
      }
    }, {
      key: 'handle',
      value: function handle(req, res, cb) {
        var _this2 = this;
  
        req.relPermChecker.checkRelation(req, req.params.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
          if (err) {
            return cb(err);
          }
          var queryData = {
            topicId: req.params.topicId,
            size: _utilsServerHelper2['default'].getListOfItemCaps(parseInt(req.query.size), 30),
            page: parseInt(req.query.page) || 1,
            category: _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA,
            prev: req.query.prev || false
          };
          var orderVal = [["modified", -1]];
          if (req.query.order) {
            try {
              var order_obj = JSON.parse(_querystring2['default'].unescape(req.query.order));
              if (order_obj.length > 0) {
                orderVal = [];
                var _iteratorNormalCompletion3 = true;
                var _didIteratorError3 = false;
                var _iteratorError3 = undefined;
  
                try {
                  for (var _iterator3 = order_obj[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
                    var order_item = _step3.value;
  
                    if (order_item.value == 'desc') {
                      orderVal.push([order_item.by, -1]);
                    } else {
                      orderVal.push([order_item.by, 1]);
                    }
                  }
                } catch (err) {
                  _didIteratorError3 = true;
                  _iteratorError3 = err;
                } finally {
                  try {
                    if (!_iteratorNormalCompletion3 && _iterator3['return']) {
                      _iterator3['return']();
                    }
                  } finally {
                    if (_didIteratorError3) {
                      throw _iteratorError3;
                    }
                  }
                }
              }
            } catch (e) {
              _modulesLoggerIndex2['default'].info(req.id, 'Parse order happen error = %s' + e + ' .Still use default order value');
              orderVal = [["modified", -1]];
            }
          }
          queryData.order = orderVal;
  
          var filterVal = {};
          if (req.query.filter) {
            try {
              var filterObj = JSON.parse(_querystring2['default'].unescape(req.query.filter));
              if (Object.prototype.toString.call(filterObj) === '[object Array]') {
                var _iteratorNormalCompletion4 = true;
                var _didIteratorError4 = false;
                var _iteratorError4 = undefined;
  
                try {
                  for (var _iterator4 = filterObj[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
                    var filterItem = _step4.value;
  
                    filterVal[filterItem.by] = filterItem.value;
                  }
                } catch (err) {
                  _didIteratorError4 = true;
                  _iteratorError4 = err;
                } finally {
                  try {
                    if (!_iteratorNormalCompletion4 && _iterator4['return']) {
                      _iterator4['return']();
                    }
                  } finally {
                    if (_didIteratorError4) {
                      throw _iteratorError4;
                    }
                  }
                }
              } else {
                filterVal[filterObj.by] = filterObj.value;
              }
            } catch (e) {
              _modulesLoggerIndex2['default'].info(req.id, 'Parse filter happen error = %s' + e + ' .Still use default order value');
              filterVal = {};
            }
          }
          queryData.filter = filterVal;
          var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
          _this2._listTopic(src, queryData, function (err, data) {
            _messageMessageBackend2['default'].toDownloadableClientFormatMessages(src, data.results.results, function (err, convertedResults) {
              if (err) {
                return res.json({ data: [], total: 0, nextPageUrl: '', previousPageUrl: '' });
              }
              data.results.results = convertedResults;
              if (req.query.order) {
                data.queryData.order = req.query.order;
              } else {
                delete data.queryData.order;
              }
              if (req.query.filter) {
                data.queryData.filter = req.query.filter;
              } else {
                delete data.queryData.filter;
              }
              var parentInfos = [];
  
              var _iteratorNormalCompletion5 = true;
              var _didIteratorError5 = false;
              var _iteratorError5 = undefined;
  
              try {
                for (var _iterator5 = data.results.results[Symbol.iterator](), _step5; !(_iteratorNormalCompletion5 = (_step5 = _iterator5.next()).done); _iteratorNormalCompletion5 = true) {
                  var msgItem = _step5.value;
  
                  parentInfos.push({ '_id': msgItem._id, 'size': 1, 'chatCount': msgItem.chatCount, 'likeCount': msgItem.likeCount });
                }
              } catch (err) {
                _didIteratorError5 = true;
                _iteratorError5 = err;
              } finally {
                try {
                  if (!_iteratorNormalCompletion5 && _iterator5['return']) {
                    _iterator5['return']();
                  }
                } finally {
                  if (_didIteratorError5) {
                    throw _iteratorError5;
                  }
                }
              }
  
              _messageMessageBackend2['default'].getLatestMessageByParent(src, parentInfos, function (err, results) {
                if (err) {
                  _modulesLoggerIndex2['default'].warn(req.id, 'ListOfTopicIdeasView to get latest message happen error', err);
                  return res.json({ data: [], total: 0, nextPageUrl: '', previousPageUrl: '' });
                }
                for (var msgIdx in data.results.results) {
                  var msgItem = data.results.results[msgIdx];
                  //let lastestMsgs = results[msgIdx].data;
                  var chatMessagesCount = results[msgIdx].chatCount;
                  var likeMessagesCount = results[msgIdx].likeCount;
                  //                if (lastestMsgs && lastestMsgs.length > 0){
                  //                  msgItem.latestMessages = lastestMsgs;
                  //                }
                  //                else{
                  //                  msgItem.latestMessages = [];               
                  //                }
                  if (chatMessagesCount) {
                    msgItem.chatMessagesCount = chatMessagesCount;
                  } else {
                    msgItem.chatMessagesCount = 0;
                  }
                  if (likeMessagesCount) {
                    msgItem.likeMessagesCount = likeMessagesCount;
                  } else {
                    msgItem.likeMessagesCount = 0;
                  }
                }
                return res.json(_utilsServerHelper2['default'].createPaginationByPage(req, data));
              });
            });
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_UPDATE)],
      enumerable: true
    }]);
  
    return ListOfTopicIdeasView;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  ;
  
  exports.ListOfTopicIdeasView = ListOfTopicIdeasView;
  
  var addTaskView = (function (_vw$ViewBase13) {
    _inherits(addTaskView, _vw$ViewBase13);
  
    function addTaskView() {
      _classCallCheck(this, addTaskView);
  
      _get(Object.getPrototypeOf(addTaskView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(addTaskView, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        req.relPermChecker.checkRelation(req, req.params.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
          if (err) {
            return cb(err);
          }
          //req.body should be a task category
          var postData = req.body;
          postData.category = _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.TASK;
          postData.sender = { _id: req.user._id, type: _utilsServerConstants2['default'].TypeUser, username: req.user.username, displayname: req.user.displayname, picture_url: _utilsServerHelper2['default'].getPicture_url(req.user.picturefile) };
          postData.topicId = req.params.topicId;
          var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
          _messageMessageBackend2['default'].addMessagetoNoSenderPublicInfo(src, postData, function (err, result) {
            if (err) {
              return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(err);
            }
            result.sender = _lodash2['default'].extend(result.sender, req.user.profile);
            return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json({ 'data': [result] });
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_UPDATE)],
      enumerable: true
    }]);
  
    return addTaskView;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.addTaskView = addTaskView;
  
  var addIdeaView = (function (_vw$ViewBase14) {
    _inherits(addIdeaView, _vw$ViewBase14);
  
    function addIdeaView() {
      _classCallCheck(this, addIdeaView);
  
      _get(Object.getPrototypeOf(addIdeaView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(addIdeaView, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        req.relPermChecker.checkRelation(req, req.params.topicId, _utilsServerConstants2['default'].TypeTopic, function (err) {
          if (err) {
            return cb(err);
          }
          //req.body should be a task category
          var postData = req.body;
          postData.category = _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA;
          postData.sender = { _id: req.user._id, type: _utilsServerConstants2['default'].TypeUser, username: req.user.username, displayname: req.user.displayname, picture_url: _utilsServerHelper2['default'].getPicture_url(req.user.picturefile) };
          postData.topicId = req.params.topicId;
          var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
          _messageMessageBackend2['default'].addMessagetoNoSenderPublicInfo(src, postData, function (err, result) {
            if (err) {
              return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(err);
            }
            result.sender = _lodash2['default'].extend(result.sender, req.user.profile);
  
            return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json({ 'data': [result] });
          });
        });
      }
    }], [{
      key: 'AUTHORIZERS',
      value: [new _authAuthorizers2['default'].PermissionAuthorizer(_authAuthorizers2['default'].pm.PERM_TOPIC_UPDATE)],
      enumerable: true
    }]);
  
    return addIdeaView;
  })(_viewBaseViewBase2['default'].ViewBase);
  
  exports.addIdeaView = addIdeaView;

/***/ },
/* 128 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  //Version 1.0
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _express = __webpack_require__(10);
  
  var _userController = __webpack_require__(129);
  
  var _userController2 = _interopRequireDefault(_userController);
  
  var _authAuthService = __webpack_require__(15);
  
  var _authAuthService2 = _interopRequireDefault(_authAuthService);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var config = __webpack_require__(4);
  
  var router = new _express.Router();
  
  router.get('/me', (0, _viewBaseViewBase.asView)(_userController2['default'].MeInfoView));
  router.get('/me/topics', (0, _viewBaseViewBase.asView)(_userController2['default'].listTopicsForMe));
  router.get('/me/spaces', (0, _viewBaseViewBase.asView)(_userController2['default'].listTopicsForMe));
  //router.get('/:id/topics', asView(controller.listTopicsForUser));
  router.get('/:id/colleagues/', (0, _viewBaseViewBase.asView)(_userController2['default'].SearchColleaguesView));
  //router.get('/:id', asView(controller.show));
  router.get('/me/tasks', (0, _viewBaseViewBase.asView)(_userController2['default'].listTasksForMe));
  router.get('/me/tasks/assigned', (0, _viewBaseViewBase.asView)(_userController2['default'].listAssignedTasksForMe));
  router.get('/me/ideas', (0, _viewBaseViewBase.asView)(_userController2['default'].listIdeasForMe));
  router.get('/me/attachments/natives', (0, _viewBaseViewBase.asView)(_userController2['default'].listNativesForMe));
  
  // router.get('/:id/colleagues/topics', asView(controller.listTopicsForColleagues));
  
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 129 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _userModel = __webpack_require__(14);
  
  var _userModel2 = _interopRequireDefault(_userModel);
  
  var _passport = __webpack_require__(25);
  
  var _passport2 = _interopRequireDefault(_passport);
  
  //import config from '../../config'
  
  var _jsonwebtoken = __webpack_require__(29);
  
  var _jsonwebtoken2 = _interopRequireDefault(_jsonwebtoken);
  
  var _escapeStringRegexp = __webpack_require__(42);
  
  var _escapeStringRegexp2 = _interopRequireDefault(_escapeStringRegexp);
  
  var _mongoose = __webpack_require__(5);
  
  var _mongoose2 = _interopRequireDefault(_mongoose);
  
  var _modulesEmailEmailController = __webpack_require__(82);
  
  var _modulesEmailEmailController2 = _interopRequireDefault(_modulesEmailEmailController);
  
  var _modulesLoggerIndex = __webpack_require__(1);
  
  var _modulesLoggerIndex2 = _interopRequireDefault(_modulesLoggerIndex);
  
  var _authAuthService = __webpack_require__(15);
  
  var _authAuthService2 = _interopRequireDefault(_authAuthService);
  
  var _viewBaseViewBase = __webpack_require__(7);
  
  var _viewBaseViewBase2 = _interopRequireDefault(_viewBaseViewBase);
  
  var _userBackend = __webpack_require__(23);
  
  var _userBackend2 = _interopRequireDefault(_userBackend);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _messageMessageBackend = __webpack_require__(26);
  
  var _messageMessageBackend2 = _interopRequireDefault(_messageMessageBackend);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var _fluxConstantsMessageConstants = __webpack_require__(17);
  
  var _fluxConstantsMessageConstants2 = _interopRequireDefault(_fluxConstantsMessageConstants);
  
  var _modulesAnalyticsGoogle = __webpack_require__(33);
  
  var _modulesAnalyticsGoogle2 = _interopRequireDefault(_modulesAnalyticsGoogle);
  
  var _modulesAnalyticsGoogleConstants = __webpack_require__(32);
  
  var _modulesAnalyticsGoogleConstants2 = _interopRequireDefault(_modulesAnalyticsGoogleConstants);
  
  var ObjectId = _mongoose2['default'].Schema.Types.ObjectId;
  
  exports.MeInfoView = (function (_vw$anyCallView) {
    _inherits(MeInfoView, _vw$anyCallView);
  
    function MeInfoView() {
      _classCallCheck(this, MeInfoView);
  
      _get(Object.getPrototypeOf(MeInfoView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(MeInfoView, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        _modulesLoggerIndex2['default'].info(req.id, 'begin MeInfoView');
        if (req.anonymousUser) {
          req.anonymousUser.secret = undefined;
          return res.json(req.anonymousUser);
        } else if (req.user) {
          //var user = req.user.toJSON();	   
          _userModel2['default'].findOne({ '_id': req.user._id }, function (err, user) {
            if (user) {
              user.secret = undefined;
              user.permissions = req.user.extendPermissions;
              return res.json(user);
            } else {
              return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SysUnkownError));
            }
          });
          //user.permissions = req.user.extendPermissions;
          //return res.json(user);
        } else {
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SysUnkownError));
          }
      }
    }]);
  
    return MeInfoView;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  exports.SearchColleaguesView = (function (_vw$regUserCallView) {
    _inherits(SearchColleaguesView, _vw$regUserCallView);
  
    function SearchColleaguesView() {
      _classCallCheck(this, SearchColleaguesView);
  
      _get(Object.getPrototypeOf(SearchColleaguesView.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(SearchColleaguesView, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        _modulesLoggerIndex2['default'].info(req.id, 'begin SearchColleaguesView');
        var str;
        var query = [];
        if (req.query) {
          str = req.query.search;
        }
        if (str) {
          str = (0, _escapeStringRegexp2['default'])(str);
        }
        var src = _utilsServerHelper2['default'].getSrcFromRequest(req);
        var data = {
          search: str,
          user: req.user
        };
        _userBackend2['default'].searchColleagues(src, data, function (err, users) {
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(users);
        });
      }
    }]);
  
    return SearchColleaguesView;
  })(_viewBaseViewBase2['default'].regUserCallView);
  
  exports.listTopicsForMe = (function (_vw$anyCallView2) {
    _inherits(listTopicsForMe, _vw$anyCallView2);
  
    function listTopicsForMe() {
      _classCallCheck(this, listTopicsForMe);
  
      _get(Object.getPrototypeOf(listTopicsForMe.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(listTopicsForMe, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var me = req.user || req.anonymousUser;
        _modulesLoggerIndex2['default'].info(req.id, me.aType + ' begin listTopicsForMe :' + me.username + ' with userId: ' + me._id);
        var page = Number(req.query.page) || 1,
            size = Number(req.query.size) || 10,
            size = size > 20 ? 20 : size,
            src = _utilsServerHelper2['default'].getSrcFromRequest(req),
            apiRoute = '/api/users/me/spaces';
  
        var data = {
          user: me,
          pagination: {
            skip: (page - 1) * size,
            limit: size,
            apiRoute: apiRoute
          },
          search: req.query.search,
          order: req.query.orderBy
        };
  
        var callback = function callback(err, result) {
          if (err || !result) {
            return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json({ data: [] });
          }
          var returnData = {
            data: result.data,
            from: (page - 1) * size + 1,
            to: (page - 1) * size + result.data.length
          };
          if (result.hasNext) {
            returnData.nextPageUrl = apiRoute + '?page=' + (page + 1) + '&size=' + size;
            if (data.search) {
              returnData.nextPageUrl += '&search=' + data.search;
            }
            if (data.filterType) {
              returnData.nextPageUrl += '&filtertype=' + data.filterType;
            }
          }
          if (page > 1) {
            returnData.previousPageUrl = apiRoute + '?page=' + (page - 1) + '&size=' + size;
            if (data.search) {
              returnData.previousPageUrl += '&search=' + data.search;
            }
            if (data.filterType) {
              returnData.previousPageUrl += '&filtertype=' + data.filterType;
            }
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(returnData);
        };
  
        if (data.search && data.search.length > 0) {
          _userBackend2['default'].listTopicsForMe(src, data, callback);
        } else {
          var fillType = req.query.filtertype || 'all';
          data.filterType = fillType;
          _userBackend2['default'].listRecentAccessedTopicsForMe(src, data, callback);
        }
      }
    }]);
  
    return listTopicsForMe;
  })(_viewBaseViewBase2['default'].anyCallView);
  
  exports.listTopicsForUser = (function (_vw$DeveloperAdminView) {
    _inherits(listTopicsForUser, _vw$DeveloperAdminView);
  
    function listTopicsForUser() {
      _classCallCheck(this, listTopicsForUser);
  
      _get(Object.getPrototypeOf(listTopicsForUser.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(listTopicsForUser, [{
      key: 'handle',
      value: function handle(req, res, cb) {
  
        if (!req.user) {
          return res.status(_utilsServerConstants2['default'].HttpUnauthorizedStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthenticateFailed));
        }
        _modulesLoggerIndex2['default'].info(req.id, ' begin listTopicsForUser with userId: ' + req.params.id);
  
        if (!req.params || !req.params.id) {
          return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
        }
  
        var page = Number(req.query.page) || 1,
            size = Number(req.query.size) || 10,
            src = _utilsServerHelper2['default'].getSrcFromRequest(req),
            apiRoute = '/api/users/' + req.params.id + '/spaces';
  
        var data = {
          pagination: {
            skip: (page - 1) * size,
            limit: size,
            apiRoute: apiRoute
          },
          search: req.query.search,
          objId: req.params.id
        };
  
        _userBackend2['default'].listTopicsForMe(src, data, function (err, result) {
          if (err || !result) {
            return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json([]);
          }
          var returnData = {
            data: result.data,
            from: (page - 1) * size + 1,
            to: (page - 1) * size + result.data.length
          };
          if (result.hasNext) {
            returnData.nextPageUrl = apiRoute + '?page=' + (page + 1) + '&size=' + size;
            if (data.search) {
              returnData.nextPageUrl += '&search=' + data.search;
            }
          }
          if (page > 1) {
            returnData.previousPageUrl = apiRoute + '?page=' + (page - 1) + '&size=' + size;
            if (data.search) {
              returnData.previousPageUrl += '&search=' + data.search;
            }
          }
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(returnData);
        });
      }
    }]);
  
    return listTopicsForUser;
  })(_viewBaseViewBase2['default'].DeveloperAdminView);
  
  var validationError = function validationError(res, err) {
    return res.status(422).json(err);
  };
  
  /**
   * Get list of users using mini-mongo
   * restriction: 'admin'
   */
  exports.index = function (req, res) {
    var func = 'user.controller[mongo]';
    try {
      var limit = req.query.limit || 20;
      var skip = req.query.skip || 0;
      limit = { limit: limit };
      skip = { skip: skip };
  
      var selector = req.query.selector;
      if (selector) {
        selector = JSON.parse(selector);
      }
  
      if (selector._id == 'me') {
        selector._id = req.user._id;
      }
  
      console.log(func, 'after', 'limit', limit, 'selector', selector);
      if (selector._id) {
        _userModel2['default'].findById(selector._id, function (err, user) {
          if (err) return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
          console.log(func, 'user', user.profile);
          if (!user) return res.status(_utilsServerConstants2['default'].HttpUnauthorizedStatus).send('Unauthorized');
          return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json([user.profile]);
        });
      } else {
        _userModel2['default'].find(selector, limit, skip, function (err, users) {
          //, '-salt -hashedPassword'
          console.log(func, 'users', users);
          if (err) return res.status(_utilsServerConstants2['default'].HttpErrorStatus).send(err);
          res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json(users);
        });
      }
    } catch (err) {
      console.error(func, err);
    }
  };
  
  /**
   * Get a single user
   */
  exports.show = (function (_vw$ViewBase) {
    _inherits(show, _vw$ViewBase);
  
    function show() {
      _classCallCheck(this, show);
  
      _get(Object.getPrototypeOf(show.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(show, [{
      key: 'handle',
      value: function handle(req, res, cb) {
        var userId = req.params.id;
  
        _userModel2['default'].findById(userId, function (err, user) {
          if (err) {
            _modulesLoggerIndex2['default'].error(err);
            return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].BadRequestError));
          }
          if (!user) return res.status(_utilsServerConstants2['default'].HttpUnauthorizedStatus).send('Unauthorized');
          res.json(user.profile);
        });
      }
    }]);
  
    return show;
  })(_viewBaseViewBase2['default'].ViewBase);
  /**
   * Authentication callback
   */
  exports.authCallback = function (req, res, next) {
    res.redirect('/');
  };
  
  exports.listTasksForMe = (function (_vw$regUserCallView2) {
    _inherits(listTasksForMe, _vw$regUserCallView2);
  
    function listTasksForMe() {
      _classCallCheck(this, listTasksForMe);
  
      _get(Object.getPrototypeOf(listTasksForMe.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(listTasksForMe, [{
      key: '_listTopic',
      value: function _listTopic(req, queryData, cb) {
        var self = this;
        _userBackend2['default'].listTasksByUserId(req, queryData, function (err, results) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'listTasksForMe call _listTopic happen error', err.message);
            return cb(err);
          }
          if (queryData.prevRefObjId && results.results.length < queryData.size) {
            delete queryData.prevRefObjId;
            queryData.page = 1;
            return self._listTopic(req, queryData, cb);
          } else if (results.results.length === 0 && queryData.nextRefObjId) {
            queryData.prevRefObjId = queryData.nextRefObjId;
            delete queryData.nextRefObjId;
            queryData.page -= 1;
            queryData.includeEqual = true;
            return self._listTopic(req, queryData, function (err, data) {
              if (data.results) {
                data.results.havingNextPage = false;
              }
              return cb(null, data);
            });
          }
  
          delete queryData.sender;
          var data = {
            queryData: queryData,
            results: results
          };
          return cb(null, data);
        });
      }
    }, {
      key: 'handle',
      value: function handle(req, res, cb) {
        var queryData = {
          sender: req.user._id,
          size: parseInt(req.query.size) || 30,
          page: parseInt(req.query.page) || 1,
          nextRefObjId: req.query.nextRefObjId,
          prevRefObjId: req.query.prevRefObjId,
          category: _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.TASK
        };
  
        this._listTopic(req, queryData, function (err, data) {
          _messageMessageBackend2['default'].toDownloadableClientFormatMessages(req, data.results.results, function (err, convertedResults) {
            _messageMessageBackend2['default'].fillTopicTitleInMsgs(req, convertedResults, function (err, convertedResults) {
              if (err) {
                return res.json({ data: [], total: 0, nextPageUrl: '', previousPageUrl: '' });
              }
              data.results.results = convertedResults;
              return res.json(_utilsServerHelper2['default'].createPagination(req, data));
            });
          });
        });
      }
    }]);
  
    return listTasksForMe;
  })(_viewBaseViewBase2['default'].regUserCallView);
  
  exports.listAssignedTasksForMe = (function (_vw$regUserCallView3) {
    _inherits(listAssignedTasksForMe, _vw$regUserCallView3);
  
    function listAssignedTasksForMe() {
      _classCallCheck(this, listAssignedTasksForMe);
  
      _get(Object.getPrototypeOf(listAssignedTasksForMe.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(listAssignedTasksForMe, [{
      key: '_listTopic',
      value: function _listTopic(req, queryData, cb) {
        var self = this;
        _userBackend2['default'].listAssignedTaskByTopic(req, queryData, function (err, results) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'listTasksForMe call _listTopic happen error', err.message);
            return cb(err);
          }
          if (queryData.prevRefObjId && results.results.length < queryData.size) {
            delete queryData.prevRefObjId;
            queryData.page = 1;
            return self._listTopic(req, queryData, cb);
          } else if (results.results.length === 0 && queryData.nextRefObjId) {
            queryData.prevRefObjId = queryData.nextRefObjId;
            delete queryData.nextRefObjId;
            queryData.page -= 1;
            queryData.includeEqual = true;
            return self._listTopic(req, queryData, function (err, data) {
              if (data.results) {
                data.results.havingNextPage = false;
              }
              return cb(null, data);
            });
          }
  
          delete queryData.assignee;
          var data = {
            queryData: queryData,
            results: results
          };
          return cb(null, data);
        });
      }
    }, {
      key: 'handle',
      value: function handle(req, res, cb) {
        var queryData = {
          assignee: req.user._id,
          size: parseInt(req.query.size) || 30,
          page: parseInt(req.query.page) || 1,
          nextRefObjId: req.query.nextRefObjId,
          prevRefObjId: req.query.prevRefObjId,
          category: _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.TASK
        };
  
        this._listTopic(req, queryData, function (err, data) {
          _messageMessageBackend2['default'].toDownloadableClientFormatMessages(req, data.results.results, function (err, convertedResults) {
            if (err) {
              return res.json({ data: [], total: 0, nextPageUrl: '', previousPageUrl: '' });
            }
            data.results.results = convertedResults;
            return res.json(_utilsServerHelper2['default'].createPagination(req, data));
          });
        });
      }
    }]);
  
    return listAssignedTasksForMe;
  })(_viewBaseViewBase2['default'].regUserCallView);
  
  exports.listIdeasForMe = (function (_vw$regUserCallView4) {
    _inherits(listIdeasForMe, _vw$regUserCallView4);
  
    function listIdeasForMe() {
      _classCallCheck(this, listIdeasForMe);
  
      _get(Object.getPrototypeOf(listIdeasForMe.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(listIdeasForMe, [{
      key: '_listTopic',
      value: function _listTopic(req, queryData, cb) {
        var self = this;
        _userBackend2['default'].listIdeasByUserId(req, queryData, function (err, results) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'listIdeaByUserId call _listTopic happen error', err.message);
            return cb(err);
          }
          if (queryData.prevRefObjId && results.results.length < queryData.size) {
            delete queryData.prevRefObjId;
            queryData.page = 1;
            return self._listTopic(req, queryData, cb);
          } else if (results.results.length === 0 && queryData.nextRefObjId) {
            queryData.prevRefObjId = queryData.nextRefObjId;
            delete queryData.nextRefObjId;
            queryData.page -= 1;
            queryData.includeEqual = true;
            return self._listTopic(req, queryData, function (err, data) {
              if (data.results) {
                data.results.havingNextPage = false;
              }
              return cb(null, data);
            });
          }
  
          delete queryData.sender;
          var data = {
            queryData: queryData,
            results: results
          };
          return cb(null, data);
        });
      }
    }, {
      key: 'handle',
      value: function handle(req, res, cb) {
        var queryData = {
          sender: req.user._id,
          size: parseInt(req.query.size) || 30,
          page: parseInt(req.query.page) || 1,
          nextRefObjId: req.query.nextRefObjId,
          prevRefObjId: req.query.prevRefObjId,
          category: _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.IDEA
        };
  
        this._listTopic(req, queryData, function (err, data) {
          _messageMessageBackend2['default'].toDownloadableClientFormatMessages(req, data.results.results, function (err, convertedResults) {
            _messageMessageBackend2['default'].fillTopicTitleInMsgs(req, convertedResults, function (err, convertedResults) {
              if (err) {
                return res.json({ data: [], total: 0, nextPageUrl: '', previousPageUrl: '' });
              }
              data.results.results = convertedResults;
              return res.json(_utilsServerHelper2['default'].createPagination(req, data));
            });
          });
        });
      }
    }]);
  
    return listIdeasForMe;
  })(_viewBaseViewBase2['default'].regUserCallView);
  
  exports.listNativesForMe = (function (_vw$ViewBase2) {
    _inherits(listNativesForMe, _vw$ViewBase2);
  
    function listNativesForMe() {
      _classCallCheck(this, listNativesForMe);
  
      _get(Object.getPrototypeOf(listNativesForMe.prototype), 'constructor', this).apply(this, arguments);
    }
  
    _createClass(listNativesForMe, [{
      key: '_listTopic',
      value: function _listTopic(req, queryData, cb) {
        var self = this;
        _userBackend2['default'].listNativesByUserId(req, queryData, function (err, results) {
          if (err) {
            _modulesLoggerIndex2['default'].error(req.id, 'listIdeaByUserId call _listTopic happen error', err.message);
            return cb(err);
          }
          if (queryData.prevRefObjId && results.results.length < queryData.size) {
            delete queryData.prevRefObjId;
            queryData.page = 1;
            return self._listTopic(req, queryData, cb);
          } else if (results.results.length === 0 && queryData.nextRefObjId) {
            queryData.prevRefObjId = queryData.nextRefObjId;
            delete queryData.nextRefObjId;
            queryData.page -= 1;
            queryData.includeEqual = true;
            return self._listTopic(req, queryData, function (err, data) {
              if (data.results) {
                data.results.havingNextPage = false;
              }
              return cb(null, data);
            });
          }
  
          delete queryData.sender;
          var data = {
            queryData: queryData,
            results: results
          };
          return cb(null, data);
        });
      }
    }, {
      key: 'handle',
      value: function handle(req, res, cb) {
        var me = req.user || req.anonymousUser;
        var queryData = {
          sender: me,
          size: parseInt(req.query.size) || 30,
          page: parseInt(req.query.page) || 1,
          nextRefObjId: req.query.nextRefObjId,
          prevRefObjId: req.query.prevRefObjId
        };
  
        this._listTopic(req, queryData, function (err, data) {
          _messageMessageBackend2['default'].toDownloadableClientFormatMessages(req, data.results.results, function (err, convertedResults) {
            _messageMessageBackend2['default'].fillTopicTitleInMsgs(req, convertedResults, function (err, convertedResults) {
              if (err) {
                return res.json({ data: [], total: 0, nextPageUrl: '', previousPageUrl: '' });
              }
              data.results.results = convertedResults;
              return res.json(_utilsServerHelper2['default'].createPagination(req, data));
            });
          });
        });
      }
    }]);
  
    return listNativesForMe;
  })(_viewBaseViewBase2['default'].ViewBase);

/***/ },
/* 130 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var express = __webpack_require__(10);
  var passport = __webpack_require__(25);
  var config = __webpack_require__(4);
  var User = __webpack_require__(14);
  
  // Passport Configuration
  __webpack_require__(132).setup(User, config);
  
  var router = express.Router();
  
  router.use('/local', __webpack_require__(131));
  router.use('/oauth', __webpack_require__(135));
  
  module.exports = router;

/***/ },
/* 131 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _passport = __webpack_require__(25);
  
  var _passport2 = _interopRequireDefault(_passport);
  
  var _authService = __webpack_require__(15);
  
  var _authService2 = _interopRequireDefault(_authService);
  
  var _express = __webpack_require__(10);
  
  var router = new _express.Router();
  router.post('/', function (req, res, next) {
    _passport2['default'].authenticate('local', function (err, user, info) {
      var error = err || info;
      if (error) return res.status(401).json(error);
      if (!user) return res.status(404).json({ message: 'Something went wrong, please try again.' });
  
      var token = _authService2['default'].signToken(user._id, user.role);
      res.json({ token: token });
    })(req, res, next);
  });
  
  module.exports = router;

/***/ },
/* 132 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _passport = __webpack_require__(25);
  
  var _passport2 = _interopRequireDefault(_passport);
  
  var _passportLocal = __webpack_require__(187);
  
  exports.setup = function (User, config) {
    _passport2['default'].use(new _passportLocal.Strategy({
      usernameField: 'username',
      passwordField: 'password' // this is the virtual field on the model
    }, function (username, password, done) {
      console.log('this is email and paswowrds', username, password);
      User.findOne({
        username: username.toLowerCase()
      }, function (err, user) {
        if (err) return done(err);
  
        if (!user) {
          return done(null, false, { message: 'This email is not registered.' });
        }
        if (!user.authenticate(password)) {
          return done(null, false, { message: 'This password is not correct.' });
        }
        return done(null, user);
      });
    }));
  };

/***/ },
/* 133 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * http://usejsdoc.org/
   */
  
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _accessTokenModel = __webpack_require__(59);
  
  var _accessTokenModel2 = _interopRequireDefault(_accessTokenModel);
  
  var _apiUserUserModel = __webpack_require__(14);
  
  var _apiUserUserModel2 = _interopRequireDefault(_apiUserUserModel);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _authServiceJs = __webpack_require__(15);
  
  var _authServiceJs2 = _interopRequireDefault(_authServiceJs);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _apiViewBaseViewBase = __webpack_require__(7);
  
  var _apiViewBaseViewBase2 = _interopRequireDefault(_apiViewBaseViewBase);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  exports.sync_add_accesstoken = function (src, data, cb) {
      var accesstoken = data.token;
      var onesnaUser = data.onesnaUser;
      _async2['default'].waterfall([function (callback) {
          _utilsDbwrapper2['default'].execute(_apiUserUserModel2['default'], _apiUserUserModel2['default'].findOne, src.id, { ndbid: accesstoken.userId }, callback);
      }, function (user, callback) {
          if (!user || user.lastupdatetime !== onesnaUser.lastupdatetime) {
              onesnaUser.ndbid = onesnaUser.id;
              onesnaUser.secret = onesnaUser.security_token;
              delete onesnaUser.id;
              _modulesLogger2['default'].info(src.id, 'User need insert or update by new data ' + onesnaUser.username);
              _utilsDbwrapper2['default'].execute(_apiUserUserModel2['default'], _apiUserUserModel2['default'].findOneAndUpdate, src.id, { ndbid: onesnaUser.ndbid }, onesnaUser, { upsert: true, 'new': true }, function (err, savedUser) {
                  if (!err) {
                      return callback(null, savedUser);
                  } else if (err.code == _errorsErrors2['default'].DBErrorDuplicateKey) {
                      //Under ndbid unique and username unique condition, happen such error only possible be username duplicate
                      //To avoid problem of endless loop, get user by username and replace secret in memory to make verify pass
                      _modulesLogger2['default'].info(reqid, 'Happen duplicate username ' + onesnaUser.username + '. Get user by same username from db!');
                      _utilsDbwrapper2['default'].execute(_apiUserUserModel2['default'], _apiUserUserModel2['default'].findOne, reqid, { username: onesnaUser.username }, function (err, savedUser) {
                          if (err || !savedUser) {
                              _modulesLogger2['default'].error(reqid, 'Failed to get user by username ' + onesnaUser.username);
                              return cb(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SyncAddAccessTokenFailed));
                          }
                          return callback(null, savedUser);
                      });
                  } else {
                      return callback(err, savedUser);
                  }
              });
          } else {
              return callback(null, user);
          }
      }, function (saved, callback) {
          if (!saved) {
              _modulesLogger2['default'].info(src.id, 'Insert or update user failed');
              return callback(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SyncAddAccessTokenFailed));
          }
          _utilsDbwrapper2['default'].execute(_accessTokenModel2['default'], _accessTokenModel2['default'].create, src.id, {
              accessToken: accesstoken.token,
              clientId: accesstoken.clientId,
              userId: saved._id,
              expires: accesstoken.expires,
              scope: accesstoken.scope
          }, callback);
      }, function (access_token, callback) {
          return callback(null, access_token);
      }], function (err, result) {
          return cb(err, result);
      });
  };

/***/ },
/* 134 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _accessTokenModel = __webpack_require__(59);
  
  var _accessTokenModel2 = _interopRequireDefault(_accessTokenModel);
  
  var _accessTokenBackend = __webpack_require__(133);
  
  var _accessTokenBackend2 = _interopRequireDefault(_accessTokenBackend);
  
  var _apiUserUserModel = __webpack_require__(14);
  
  var _apiUserUserModel2 = _interopRequireDefault(_apiUserUserModel);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _authServiceJs = __webpack_require__(15);
  
  var _authServiceJs2 = _interopRequireDefault(_authServiceJs);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _apiViewBaseViewBase = __webpack_require__(7);
  
  var _apiViewBaseViewBase2 = _interopRequireDefault(_apiViewBaseViewBase);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _utilsDbwrapper = __webpack_require__(8);
  
  var _utilsDbwrapper2 = _interopRequireDefault(_utilsDbwrapper);
  
  exports.deleteTokens = (function (_vw$serverCallView) {
      _inherits(deleteTokens, _vw$serverCallView);
  
      function deleteTokens() {
          _classCallCheck(this, deleteTokens);
  
          _get(Object.getPrototypeOf(deleteTokens.prototype), 'constructor', this).apply(this, arguments);
      }
  
      _createClass(deleteTokens, [{
          key: 'handle',
          value: function handle(req, res, cb) {
              if (!req.body || !req.body.accesstokens) {
                  _modulesLogger2['default'].error(req.id, 'Bad request, missing token');
                  return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SyncDeleteAccessTokenInvalidData));
              }
              var src = {
                  reqId: req.id,
                  type: 'req',
                  domain: req.esDomain
              };
              _utilsDbwrapper2['default'].execute(_accessTokenModel2['default'], _accessTokenModel2['default'].remove, req.id, {
                  accessToken: {
                      $in: req.body.accesstokens
                  }
              }, function (err, result) {
                  if (err) {
                      _modulesLogger2['default'].error(src.id, 'Error while deleting tokens ', req.body.accesstoken, err);
                      return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SyncDeleteAccessTokenFailed));
                  }
                  return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json({});
              });
          }
      }]);
  
      return deleteTokens;
  })(_apiViewBaseViewBase2['default'].serverCallView);
  
  exports.newToken = (function (_vw$serverCallView2) {
      _inherits(newToken, _vw$serverCallView2);
  
      function newToken() {
          _classCallCheck(this, newToken);
  
          _get(Object.getPrototypeOf(newToken.prototype), 'constructor', this).apply(this, arguments);
      }
  
      _createClass(newToken, [{
          key: 'handle',
          value: function handle(req, res, cb) {
              if (!req.body || !req.body.accesstoken) {
                  _modulesLogger2['default'].error(req.id, 'Bad request, missing token');
                  return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SyncAddAccessTokenInvalidData));
              }
              var token = req.body.accesstoken;
              if (!token.token || !token.clientId || !token.userId || !token.expires || !token.scope) {
                  _modulesLogger2['default'].error(req.id, 'Bad request without accesstoken, please check payload');
                  return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SyncAddAccessTokenInvalidData));
              }
              var onesnaUser = req.body.user;
              if (!onesnaUser) {
                  _modulesLogger2['default'].error(req.id, 'Bad request with out user, please check payload');
                  return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].SyncAddAccessTokenInvalidData));
              }
              var src = {
                  reqId: req.id,
                  type: 'req',
                  domain: req.esDomain
              };
              var data = {
                  token: token,
                  onesnaUser: onesnaUser
              };
              _accessTokenBackend2['default'].sync_add_accesstoken(src, data, function (err, result) {
                  if (err) {
                      _modulesLogger2['default'].error(src.id, 'Error syncing accesstoken for this user ', data, err);
                      return res.status(_utilsServerConstants2['default'].HttpErrorStatus).json(err);
                  }
                  return res.status(_utilsServerConstants2['default'].HttpSuccessStatus).json({});
              });
          }
      }]);
  
      return newToken;
  })(_apiViewBaseViewBase2['default'].serverCallView);

/***/ },
/* 135 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _passport = __webpack_require__(25);
  
  var _passport2 = _interopRequireDefault(_passport);
  
  var _authService = __webpack_require__(15);
  
  var _authService2 = _interopRequireDefault(_authService);
  
  var _express = __webpack_require__(10);
  
  var _accessTokenAccessTokenController = __webpack_require__(134);
  
  var _accessTokenAccessTokenController2 = _interopRequireDefault(_accessTokenAccessTokenController);
  
  var _apiViewBaseViewBase = __webpack_require__(7);
  
  var _apiViewBaseViewBase2 = _interopRequireDefault(_apiViewBaseViewBase);
  
  var router = new _express.Router();
  
  router.post('/accesstokens/add', _apiViewBaseViewBase2['default'].asView(_accessTokenAccessTokenController2['default'].newToken));
  router.post('/accesstokens/delete', _apiViewBaseViewBase2['default'].asView(_accessTokenAccessTokenController2['default'].deleteTokens));
  
  module.exports = router;

/***/ },
/* 136 */
/***/ function(module, exports) {

  'use strict';
  
  var siteAdminList = ['ericd@esna.com', 'zackc@esna.com', 'rayg@esna.com', 'andreasi@esna.com', 'mo@esna.com', 'harryh@esna.com', 'mehdi@esna.com'];
  
  module.exports = function (inUsername) {
    if (siteAdminList.indexOf(inUsername) >= 0) {
      return true;
    }
    return false;
  };

/***/ },
/* 137 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _xtend = __webpack_require__(197);
  
  var _xtend2 = _interopRequireDefault(_xtend);
  
  var _config = __webpack_require__(4);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _jsonwebtoken = __webpack_require__(29);
  
  var _jsonwebtoken2 = _interopRequireDefault(_jsonwebtoken);
  
  var _apiUserUserModel = __webpack_require__(14);
  
  var _apiUserUserModel2 = _interopRequireDefault(_apiUserUserModel);
  
  var _apiAnonymousAnonymousModel = __webpack_require__(30);
  
  var _apiAnonymousAnonymousModel2 = _interopRequireDefault(_apiAnonymousAnonymousModel);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _request = __webpack_require__(19);
  
  var _request2 = _interopRequireDefault(_request);
  
  var _authService = __webpack_require__(15);
  
  var _authorizers = __webpack_require__(24);
  
  var _utilsServerConstants = __webpack_require__(2);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _lru = __webpack_require__(77);
  
  var _lodash = __webpack_require__(11);
  
  var _lodash2 = _interopRequireDefault(_lodash);
  
  var _errorsErrors = __webpack_require__(3);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  function UnauthorizedError(code, error) {
      Error.call(this, error.message);
      this.message = error.message;
      this.inner = error;
      this.data = {
          message: this.message,
          code: code,
          type: "UnauthorizedError"
      };
  }
  
  UnauthorizedError.prototype = Object.create(Error.prototype);
  UnauthorizedError.prototype.constructor = UnauthorizedError;
  
  function getTokenSecret(token, cb) {
      if (!token) {
          return cb({ message: 'Can not find a valid token' });
      }
      var payload = _jsonwebtoken2['default'].decode(token);
      var uid = payload.user_id;
      // for Anonymous token
      if (payload.anonymous_id) {
          _apiAnonymousAnonymousModel2['default'].findById(payload.anonymous_id, function (err, anonymous) {
              if (err || !anonymous) return cb(null);
              if (anonymous) {
                  var secret = new Buffer(anonymous.secret, 'utf-8').toString('binary');
                  return cb(anonymous, secret);
              }
          });
      } else {
          // for Onesna token
          _apiUserUserModel2['default'].findOne({ ndbid: uid }, function (err, user) {
              if (err || !user) return cb(null);
              if (user) {
                  var secret = new Buffer(user.secret, 'utf-8').toString('binary');
                  return cb(user, secret + _config2['default'].commonSecretJwt, token);
              }
          });
      }
  }
  
  function noQsMethod(options) {
      return function (socket) {
          var server = this;
  
          if (!server.$emit) {
              //then is socket.io 1.0
              var Namespace = Object.getPrototypeOf(server.server.sockets).constructor;
              if (! ~Namespace.events.indexOf('authenticated')) {
                  Namespace.events.push('authenticated');
              }
          }
  
          var auth_timeout = setTimeout(function () {
              socket.disconnect('unauthorized');
          }, options.timeout || 5000);
  
          socket.on('authenticate', function (data) {
              clearTimeout(auth_timeout);
              getTokenSecret(token, function (user, secret) {
                  _jsonwebtoken2['default'].verify(token, secret, options, function (err, decoded) {
                      if (err) {
                          return socket.disconnect('unauthorized');
                      }
                      data.user = user;
                      data.decoded_token = (0, _xtend2['default'])({ _id: user._id }, decoded);
                      socket.emit('authenticated');
                      if (server.$emit) {
                          server.$emit('authenticated', socket);
                      } else {
                          server.server.sockets.emit('authenticated', socket);
                      }
                  });
              });
          });
      };
  }
  
  function authorize(options, onConnection) {
      var defaults = {
          success: function success(data, accept) {
              if (data.request) {
                  accept();
              } else {
                  accept(null, true);
              }
          },
          fail: function fail(error, data, accept) {
              if (data.request) {
                  accept(error);
              } else {
                  accept(null, false);
              }
          }
      };
  
      var auth = (0, _xtend2['default'])(defaults, options);
  
      if (!options.handshake) {
          return noQsMethod(options);
      }
  
      return function (data, accept) {
          var token, error;
          var req = data.request || data;
          var authorization_header = (req.headers || {}).authorization;
          var method;
  
          if (authorization_header) {
              var parts = authorization_header.split(' ');
              if (parts.length == 2) {
                  var scheme = parts[0],
                      credentials = parts[1];
  
                  if (/^Bearer$/i.test(scheme)) {
                      token = credentials;
                  }
              } else {
                  error = new UnauthorizedError('credentials_bad_format', {
                      message: 'Format is Authorization: Bearer [token]'
                  });
                  return auth.fail(error, data, accept);
              }
          }
  
          //get the token from query string
          if (req._query && req._query.token) {
              token = req._query.token;
              //here check token type
              method = req._query.tokenType || 'jwt';
          } else if (req.query && req.query.token) {
              token = req.query.token;
          }
  
          if (!token) {
              error = new UnauthorizedError('credentials_required', {
                  message: 'No Authorization header was found'
              });
              return auth.fail(error, data, accept);
          }
  
          if (method === 'jwt') {
              var cacheToken = 'jwt ' + token;
              if (cacheToken && _lru.socketCache.get(cacheToken)) {
                  var cachedObj = _lru.socketCache.get(cacheToken);
                  _lodash2['default'].assign(data, cachedObj);
                  _modulesLogger2['default'].info(req.id, 'Got user/anonymous from cache');
                  auth.success(data, accept);
              } else {
                  getTokenSecret(token, function (user, secret) {
                      _jsonwebtoken2['default'].verify(token, secret, options, function (err, decoded) {
                          if (err) {
                              error = new UnauthorizedError('invalid_token', err);
                              return auth.fail(error, data, accept);
                          }
                          _modulesLogger2['default'].info('socket jwt decoded:', decoded);
  
                          if (user.aType === 'user') {
                              data.user = user;
                          }
                          if (user.aType === 'anonymous') {
                              data.anonymousUser = user;
                          }
                          data.decoded_token = (0, _xtend2['default'])({ _id: user._id }, decoded);
                          _lru.socketCache.set(cacheToken, { user: data.user, anonymousUser: data.anonymousUser, decoded_token: data.decoded_token });
                          auth.success(data, accept);
                      });
                  });
              }
          } else if (method === 'oauth') {
              var cacheToken = 'Bearer ' + token;
              if (cacheToken && _lru.socketCache.get(cacheToken)) {
                  var cachedObj = _lru.socketCache.get(cacheToken);
                  _lodash2['default'].assign(data, cachedObj);
                  _modulesLogger2['default'].info(req.id, '[SocketOauthAuth]Got user/anonymous from cache', cacheToken);
                  return auth.success(data, accept);
              } else {
                  var oauthAuthen = new _authService.Oauth2Authenticator();
                  var oauthAuthor = new _authorizers.OAuthAuthorizer();
                  oauthAuthen.verify(token, function (err, user) {
                      if (err) {
                          return auth.fail(err, data, accept);
                      }
                      var scope = oauthAuthen.accessToken.scope;
  
                      if (oauthAuthor.scopesCompareOtherScopes(scope, [_utilsServerConstants2['default'].OAuth2ScopeLogan]) == _utilsServerConstants2['default'].IncludeScope) {
                          data.user = user;
                          _lru.socketCache.set(cacheToken, { user: user });
                          return auth.success(data, accept);
                      } else {
                          return auth.fail(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].AuthorizeErrorOauth2), data, accept);
                      }
                  });
              }
          }
      };
  };
  
  exports.authorize = authorize;

/***/ },
/* 138 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Created by ericd on 01/12/2015.
   */
  'use strict';
  
  var uuid = __webpack_require__(50);
  var logger = __webpack_require__(1);
  var morgan = __webpack_require__(88);
  var os = __webpack_require__(51);
  var errorHandler = __webpack_require__(171);
  var config = __webpack_require__(27);
  var async = __webpack_require__(9);
  var pmx = __webpack_require__(52);
  var winstonStream = {
      write: function write(message, encoding) {
          logger.info(message);
      }
  };
  
  var WORLDWIDEWEBHEADER = 'www.';
  morgan.token('id', function getId(req) {
      return req.id;
  });
  
  morgan.format('logan-onServer', function developmentFormatLine(tokens, req, res) {
      // get the status code if response written
      var status = res._header ? res.statusCode : undefined;
  
      // get status color
      var color = status >= 500 ? 31 // red
      : status >= 400 ? 33 // yellow
      : status >= 300 ? 36 // cyan
      : status >= 200 ? 32 // green
      : 0; // no color
  
      // get colored function
      var fn = developmentFormatLine[color];
  
      if (!fn) {
          // compile
          fn = developmentFormatLine[color] = morgan.compile('MorganRequest :id :remote-addr - :remote-user [:date] \x1b[0m:method :url \x1b[' + color + 'm:status \x1b[0m:response-time ms - :res[content-length]\x1b[0m :referrer :user-agent');
      }
  
      return fn(tokens, req, res);
  });
  
  morgan.format('logan-dev', function developmentFormatLine(tokens, req, res) {
      // get the status code if response written
      var status = res._header ? res.statusCode : undefined;
  
      // get status color
      var color = status >= 500 ? 31 // red
      : status >= 400 ? 33 // yellow
      : status >= 300 ? 36 // cyan
      : status >= 200 ? 32 // green
      : 0; // no color
  
      // get colored function
      var fn = developmentFormatLine[color];
  
      if (!fn) {
          // compile
          fn = developmentFormatLine[color] = morgan.compile(':id \x1b[0m:method :url \x1b[' + color + 'm:status \x1b[0m:response-time ms - :res[content-length]\x1b[0m');
      }
  
      return fn(tokens, req, res);
  });
  
  var appendReqId = function appendReqId(req, res, next) {
      req.id = uuid.v4();
      if (next) {
          next();
      }
  };
  
  var appendHost = function appendHost(req, res, next) {
      res.header('Logan-Host', os.hostname());
      if (next) {
          next();
      }
  };
  
  var appendVersion = function appendVersion(req, res, next) {
      res.header('Logan-Version', config.version);
      if (next) {
          next();
      }
  };
  
  var getDomainFromHost = function getDomainFromHost(req, res, next) {
      var domain = req.hostname;
      if (domain.startsWith(WORLDWIDEWEBHEADER)) {
          domain = domain.substr(WORLDWIDEWEBHEADER.length);
      }
      req.esDomain = domain;
      if (next) {
          next();
      }
  };
  
  var getProcessMeta = function getProcessMeta(req, res, next) {
      var meta = {
          host: os.hostname(),
          version: config.version,
          pid: process.pid,
          platform: process.platform,
          deployment_type: config.env
      };
  
      req.meta = meta;
      if (next) {
          next();
      }
  };
  
  var checkSysUA = function checkSysUA(req, res, next) {
      if (process.env['mongoUA'] === 'disconnected') {
          logger.error(req.id, 'Database connection stopped');
          return res.status(cst.HttpCriticalErrorStatus).json('Database connection Error');
      }
      if (next) {
          next();
      }
  };
  
  function parallel(middlewares) {
      return function (req, res, next) {
          async.each(middlewares, function (mw, cb) {
              mw(req, res, cb);
          }, next);
      };
  };
  
  module.exports = function (app) {
      var env = app.get('env');
      app.use(parallel([appendReqId, appendHost, appendVersion, getDomainFromHost, getProcessMeta]));
      app.use(checkSysUA);
      app.set('appPath', config.root + '/build');
  
      // CORS configuration
      // -----------------------------------------------------------------------------
  
      // var cors = {
      //   origin: config.allowOrigins
      // };
  
      // app.use(function(req, res, next) {
      //     var origin = cors.origin.indexOf(req.header('origin').toLowerCase()) > -1 ? req.headers.origin : cors.origin[0];
      //     res.header('Access-Control-Allow-Origin', origin);
      //     res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
      //     res.header('Access-Control-Allow-Headers', 'Content-Type');
      //     next();
      // });
  
      app.use(morgan('logan-onServer', { stream: winstonStream }));
      if ('logan-production' === env || 'logan-staging' === env) {
          // app.use(pmx.expressErrorHandler());
      }
      if ('development' === env || 'logan-testing' === env) {
          app.use(pmx.expressErrorHandler());
      }
  };

/***/ },
/* 139 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
  	value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _ZSLogger = __webpack_require__(49);
  
  var _ZSLogger2 = _interopRequireDefault(_ZSLogger);
  
  var ns = '[ClientEnvironment]';
  
  var ClientEnvironment = {};
  
  ClientEnvironment.defaultChatEventServer = 'localhost';
  ClientEnvironment.defaultLocalhostPort = ''; //can be set to 8080 for local SEWebsever test.
  
  ClientEnvironment.defaultLoginPageURLParams = '&product_name=zangspaces&login_view=google,office365,salesforce,native_expanded';
  
  ClientEnvironment.SERVER_TYPES = {
  	localhost: 'localhost',
  	dataServer: 'dataServer',
  	eventServer: 'eventServer',
  	loginServer: 'loginServer',
  	wcsServer: 'wcsServer'
  };
  
  ClientEnvironment.LOCAL_TESTING_PORTS = {
  	from: 5000,
  	to: 5100
  };
  ClientEnvironment.serversSubdomains = {
  	localhost: {
  		environmentGUID: 'c182f6b2-5a21-4b66-9633-1969e0d0a6bd',
  		dataServer: {
  			subdomain: '',
  			port: ''
  		},
  		eventServer: {
  			subdomain: '',
  			port: ''
  		},
  		loginServer: {
  			subdomain: '',
  			port: ''
  		},
  		wcsServer: {
  			subdomain: 'wcs.onesna.com',
  			port: ''
  		}
  	},
  
  	loganlocal: {
  		ga: "UA-77749335-1",
  		environmentGUID: 'adba6ebc-0d04-45c0-9e93-5a81371b1dd9',
  		dataServer: {
  			subdomain: 'loganlocal',
  			port: ''
  		},
  		eventServer: {
  			subdomain: 'loganlocal-socket',
  			port: ''
  		},
  		loginServer: {
  			subdomain: 'onesnatesting',
  			port: ''
  		},
  		wcsServer: {
  			subdomain: 'wcs.onesna.com', //'wcs.onesna.com',
  			port: ''
  		}
  	},
  
  	logantesting: {
  		environmentGUID: 'c899837d-fa1e-4652-a23b-a13328f146bf',
  		ga: "UA-77334981-2",
  		dataServer: {
  			subdomain: 'logantesting',
  			port: ''
  		},
  		eventServer: {
  			subdomain: 'logantesting-socket',
  			port: ''
  		},
  		loginServer: {
  			subdomain: 'onesnatesting',
  			port: ''
  		},
  		wcsServer: {
  			subdomain: 'wcstesting.onesna.com',
  			port: ''
  		}
  	},
  
  	loganstaging: {
  		environmentGUID: 'a22c8891-38f6-4778-be98-bda35b1d99c7',
  		dataServer: {
  			subdomain: 'loganstaging',
  			port: ''
  		},
  		eventServer: {
  			subdomain: 'loganstaging-socket',
  			port: ''
  		},
  		loginServer: {
  			subdomain: 'onesnastaging',
  			port: ''
  		},
  		wcsServer: {
  			subdomain: 'wcs.onesna.com',
  			port: ''
  		}
  	},
  
  	logan: {
  		environmentGUID: 'f1eb721d-3a98-485d-9365-8bd6882c3081',
  		ga: "UA-77334981-1",
  		dataServer: {
  			subdomain: 'logan',
  			port: ''
  		},
  		eventServer: {
  			subdomain: 'logan-socket',
  			port: ''
  		},
  		loginServer: {
  			subdomain: 'www',
  			port: ''
  		},
  		wcsServer: {
  			subdomain: 'wcs.onesna.com',
  			port: ''
  		}
  	}
  };
  
  ClientEnvironment.isLocalTesting = function (port, endpointType) {
  	return port >= ClientEnvironment.LOCAL_TESTING_PORTS.from && port <= ClientEnvironment.LOCAL_TESTING_PORTS.to && endpointType != ClientEnvironment.SERVER_TYPES.loginServer;
  };
  
  ClientEnvironment.getGUID = function () {
  	_ZSLogger2['default'].log(ns + '[getGUID]');
  	var parts = window.location.hostname.split('.');
  	var i = 0;
  	for (; i < parts.length; i++) {
  		var part = parts[i];
  		var cand = part.split('-');
  		if (cand.length > 0) return ClientEnvironment.serversSubdomains[cand[0]].environmentGUID;
  		if (ClientEnvironment.serversSubdomains[part]) return ClientEnvironment.serversSubdomains[part].environmentGUID;
  	}
  };
  
  ClientEnvironment.getServerRootUrl = function (endpointType, location) {
  	var func = ns + '[getServerMode]';
  	if (!location) {
  		location = window.location;
  	}
  	var hostname = location.hostname;
  	_ZSLogger2['default'].log(func, 'endpointType', endpointType, 'hostname', hostname);
  
  	var candidate = '';
  	var socketPref = '';
  	var subDomain = 'localhost';
  	var domain = 'localhost';
  	if (hostname.indexOf('localhost') < 0) {
  		var hst = hostname.split('.');
  		_ZSLogger2['default'].log(func, 'hst', hst);
  		subDomain = hst[0];
  		if (hst.length > 0) {
  			hst.splice(0, 1);
  		}
  
  		var candidateTag = subDomain.replace('-socket', '');
  		var socketTag = subDomain.replace('-candidate', '');
  
  		var lstCandid = candidateTag.split('-');
  		if (lstCandid.length > 1) {
  			subDomain = lstCandid[0];
  			candidate = '-' + lstCandid[1];
  		}
  
  		var lstSock = socketTag.split('-');
  		if (lstSock.length > 1) {
  			subDomain = lstSock[0];
  			socketPref = '-' + lstSock[1];
  		}
  
  		_ZSLogger2['default'].log(func, 'hst', hst);
  		var domain = hst.join('.');
  	}
  	_ZSLogger2['default'].log(func, 'domain', domain);
  	_ZSLogger2['default'].log(func, 'subDomain', subDomain);
  	_ZSLogger2['default'].log(func, 'candidate', candidate, 'socketPref', socketPref);
  
  	if (endpointType == ClientEnvironment.SERVER_TYPES.loginServer) {
  		candidate = '';
  		socketPref = '';
  	}
  
  	if (endpointType == ClientEnvironment.SERVER_TYPES.eventServer) {
  		socketPref = '';
  	}
  	_ZSLogger2['default'].log(func, 'candidate', candidate, 'socketPref', socketPref);
  
  	var subObj = ClientEnvironment.serversSubdomains[subDomain];
  	if (subObj) {
  		subObj = subObj[endpointType];
  		_ZSLogger2['default'].log(func, 'subObj', subObj);
  		var port = '';
  		var url = '';
  		if (ClientEnvironment.isLocalTesting(location.port, endpointType)) {
  			subObj.port = location.port;
  		}
  		if (subObj.port) {
  			port = ':' + subObj.port;
  		}
  
  		if (subObj.subdomain == 'localhost') {
  			url = location.protocol + '//' + subObj.subdomain + port; // + '/';
  		} else {
  				url = location.protocol + '//' + subObj.subdomain + socketPref + candidate + '.' + domain + port; // + '/';
  			}
  
  		if (endpointType == ClientEnvironment.SERVER_TYPES.wcsServer) {
  			url = subObj.subdomain;
  		}
  
  		_ZSLogger2['default'].log(func, 'url', url);
  		return url;
  	}
  };
  
  ClientEnvironment.getGoogleAnalyticKey = function (location) {
  	var func = ns + '[getGoogleAnalyticKey]';
  	if (!location) {
  		location = window.location;
  	}
  	var hostname = location.hostname;
  	_ZSLogger2['default'].log(func, 'hostname', hostname);
  
  	var candidate = '';
  	var socketPref = '';
  	var subDomain = 'localhost';
  	var domain = 'localhost';
  	if (hostname.indexOf('localhost') < 0) {
  		var hst = hostname.split('.');
  		_ZSLogger2['default'].log(func, 'hst', hst);
  		subDomain = hst[0];
  		if (hst.length > 0) {
  			hst.splice(0, 1);
  		}
  
  		var candidateTag = subDomain.replace('-socket', '');
  		var socketTag = subDomain.replace('-candidate', '');
  
  		var lstCandid = candidateTag.split('-');
  		if (lstCandid.length > 1) {
  			subDomain = lstCandid[0];
  			candidate = '-' + lstCandid[1];
  		}
  
  		var lstSock = socketTag.split('-');
  		if (lstSock.length > 1) {
  			subDomain = lstSock[0];
  			socketPref = '-' + lstSock[1];
  		}
  
  		_ZSLogger2['default'].log(func, 'hst', hst);
  		var domain = hst.join('.');
  	}
  	_ZSLogger2['default'].log(func, 'domain', domain);
  	_ZSLogger2['default'].log(func, 'subDomain', subDomain);
  	_ZSLogger2['default'].log(func, 'candidate', candidate, 'socketPref', socketPref);
  
  	var subObj = ClientEnvironment.serversSubdomains[subDomain];
  	if (subObj) {
  		return subObj.ga;
  	}
  	return null;
  };
  
  exports['default'] = ClientEnvironment;
  
  //https://developers.google.com/drive/web/quickstart/js
  //ClientEnvironment.loginServer= {
  //	'localhost': {
  //		'endpoint': 'https://onesnatesting.appspot.com/' //'http://localhost:8080/'
  //	},
  //	'testing':{
  //		'endpoint': 'https://onesnatesting.appspot.com/'
  //	},
  //	'staging': {
  //		'endpoint': 'https://onesnastaging.appspot.com/'
  //	},
  //	'production': {
  //		'endpoint': 'https://www.onesna.com/'
  //	}
  //};
  //
  //ClientEnvironment.dataServer= {
  //	'localhost': {
  //		'endpoint': 'http://logan.onesnatesting.appspot.com:5000/'
  //	},
  //	'testing':{
  //		'endpoint': 'https://onesnatesting.appspot.com/'
  //	},
  //	'staging': {
  //		'endpoint': 'https://logan.onesnastaging.appspot.com/'
  //	},
  //	'production': {
  //		'endpoint': 'https://www.onesna.com/'
  //	}
  //};
  //
  //ClientEnvironment.chatEventServer = {
  //	'localhost': {
  //		'endpoint':       ['http://logan.onesnatesting.appspot.com:5000']
  //	},
  //	'testing':{
  //		'endpoint':       ['https://esnachat-test.azurewebsites.net']
  //	},
  //	'staging': {
  //		'endpoint':       ['https://esnachat-staging.azurewebsites.net']
  //	},
  //	'production': {
  //		'endpoint':       ['https://esnachat-1.azurewebsites.net', 'https://esnachat-2.azurewebsites.net' ]
  //	}
  //};
  //
  //ClientEnvironment.getDefaultServerMode = function(url, port) {
  //	Log.log('url', url);
  //	if(port==5000){
  //		return 'localhost';
  //	}
  //
  //	if (url) {
  //		if (url.indexOf('staging') > 0) {
  //			return 'staging';
  //		}
  //		if (url.indexOf('test') > 0) {
  //			return 'test';
  //		}
  //		if (url.indexOf('onesna.com') > 0) {
  //			return 'production';
  //		}
  //	}
  //
  //	return 'localhost';
  //};
  //
  module.exports = exports['default'];

/***/ },
/* 140 */
/***/ function(module, exports, __webpack_require__) {

  // Development specific configuration
  // ==================================
  'use strict';
  
  var util = __webpack_require__(38);
  
  module.exports = {
      // MongoDB connection options
      env: 'development',
      ESNA_API_KEY: "b05f5eaa-42be-4830-a7b1-d44e7119c9e0",
      socketServers: ['http://logan.onesnatesting.appspot.com:5000'],
      port: process.env.PORT || 5000,
      esnaSubdomain: 'onesnatesting',
      mongo: {
          uri: process.env.DB_URI || 'mongodb://esnadb:esna1234@ds055574.mongolab.com:55574/dev',
          //uri: 'mongodb://127.0.0.1:27017/logan-dev',
          options: {
              db: {
                  safe: true
              },
              server: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              },
              replset: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              }
          }
      },
      logDB: {
          uri: process.env.LOGDB_URI || 'mongodb://esnadb:esna1234@ds055574.mongolab.com:55574/dev',
          //uri: 'mongodb://127.0.0.1:27017/logan-dev',
          options: {
              db: {
                  safe: true
              },
              server: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              },
              replset: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              }
          },
          logSize: 150000000
      },
      redis: {
          host: process.env['REDIS_HOST'] || 'pub-redis-14647.us-east-1-3.7.ec2.redislabs.com',
          port: process.env['REDIS_PORT'] || 14647,
          auth: process.env['REDIS_AUTH'] || 'logantesting',
          ssl: false
      },
      getLink: function getLink(domain) {
          return 'http://' + domain + ':' + this.port;
      },
      getEsnaLink: function getEsnaLink(domain) {
          var iss = util.getIssFromHostname(domain);
          return process.env.ESNA_LINK || 'https://' + this.esnaSubdomain + '.' + iss;
      },
      logLevel: process.env['LOG_LEVEL'] || 'silly',
      mongoLog: true,
      logRoutes: true,
      googleAnalyticsId: process.env['GA'] || "UA-77749335-1",
      sslServer: process.env['sslServer'] || false,
      SubDomains: {
          'socket': '',
          'task': ''
      },
      gcloudKey: __webpack_require__(20).normalize(__dirname + '/..') + '/private/gcskey_testing.json',
      projectId: 'onesnatesting',
      bucket: 'onesnatesting',
      tempExtneralBucket: 'onesnatesting_temp_external'
  };

/***/ },
/* 141 */
/***/ function(module, exports, __webpack_require__) {

  // Production specific configuration
  // =================================
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
      value: true
  });
  var util = __webpack_require__(38);
  var fs = __webpack_require__(43);
  var keyPem = fs.readFileSync(process.env['DB_KEY_PATH']);
  
  exports['default'] = {
      env: 'logan-production',
      getLink: function getLink(domain) {
          return 'https://' + domain;
      },
      getEsnaLink: function getEsnaLink(domain) {
          var iss = util.getIssFromHostname(domain);
          return 'https://www.' + iss;
      },
      // Server IP
      ip: process.env.OPENSHIFT_NODEJS_IP || process.env.IP || undefined,
  
      // Server port
      port: process.env.OPENSHIFT_NODEJS_PORT || process.env.PORT || 8080,
  
      // MongoDB connection options
      mongo: {
          uri: process.env.DB_URI,
          options: {
              db: {
                  safe: true
              },
              server: {
                  sslValidate: true,
                  sslCA: keyPem,
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              },
              replset: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              }
          }
      },
      logDB: {
          uri: process.env.LOGDB_URI,
          options: {
              db: {
                  safe: true
              },
              server: {
                  sslValidate: true,
                  sslCA: keyPem,
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              },
              replset: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              }
          },
          logSize: 1000000000
      },
      redis: {
          host: process.env['REDIS_HOST'],
          port: process.env['REDIS_PORT'],
          auth: process.env['REDIS_AUTH'],
          ssl: process.env['REDIS_KEY_PATH'] && process.env['REDIS_CERT_PATH'] ? {
              key: fs.readFileSync(process.env['REDIS_KEY_PATH']),
              cert: fs.readFileSync(process.env['REDIS_CERT_PATH'])
          } : !(process.env['REDIS_USE_SSL'] === 'false')
      },
      mongoLog: true,
      viewId: 121556116,
      googleAnalyticsId: "UA-77334981-1",
      useRedis: process.env['USE_REDIS'] || true,
      logLevel: process.env['LOG_LEVEL'] || 'info',
      projectId: 'esna.com:onesna-all',
      gcloudKey: process.env['GCLOUD_KEY_PATH'],
      ESNA_API_KEY: process.env['ESNA_API_KEY'],
      SubDomains: {
          'socket': 'socket',
          'task': 'processtask',
          'candidate': {
              'socket': '',
              'task': 'processtask'
          }
      },
      bucket: 'onesna',
      tempExtneralBucket: 'onesna_temp_external',
      logglyToken: 'eaa77580-ba2d-4d69-abbf-71d657662dbc',
      logglySubdomain: 'logantesting'
  };
  module.exports = exports['default'];

/***/ },
/* 142 */
/***/ function(module, exports, __webpack_require__) {

  // Stagging specific configuration
  // =================================
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
      value: true
  });
  var util = __webpack_require__(38);
  exports['default'] = {
      env: 'logan-staging',
      esnaSubdomain: 'onesnastaging',
      getLink: function getLink(domain) {
          return 'https://' + domain;
      },
      getEsnaLink: function getEsnaLink(domain) {
          var iss = util.getIssFromHostname(domain);
          return 'https://' + this.esnaSubdomain + '.' + iss;
      },
      // Server IP
      ip: process.env.OPENSHIFT_NODEJS_IP || process.env.IP || undefined,
  
      // Server port
      port: process.env.OPENSHIFT_NODEJS_PORT || process.env.PORT || 8080,
  
      // MongoDB connection options
      mongo: {
          uri: process.env.DB_URI || 'mongodb://zack:zack@ds061474.mongolab.com:61474/logan-staging',
          options: {
              db: {
                  safe: true
              },
              server: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              },
              replset: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              }
          }
      },
      logDB: {
          uri: process.env.LOGDB_URI || 'mongodb://zack:zack@ds061474.mongolab.com:61474/logan-staging',
          options: {
              db: {
                  safe: true
              },
              server: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              },
              replset: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              }
          },
          logSize: 150000000
      },
      redis: {
          host: process.env['REDIS_HOST'] || 'pub-redis-14647.us-east-1-3.7.ec2.redislabs.com',
          port: process.env['REDIS_PORT'] || 14647,
          auth: process.env['REDIS_AUTH'] || 'logantesting',
          ssl: false
      },
      mongoLog: true,
      logLevel: process.env['LOG_LEVEL'] || 'debug',
      projectId: 'onesnastaging',
      gcloudKey: process.env['GCLOUD_KEY_PATH'] || __webpack_require__(20).resolve('./private/gcskey_staging.json'),
      ESNA_API_KEY: process.env['ESNA_API_KEY'] || 'a7e2709c-b1ae-479a-a7ce-f3fab32a3a01',
      bucket: 'onesnastaging',
      tempExtneralBucket: 'onesnastaging_temp_external',
      logglyToken: 'eaa77580-ba2d-4d69-abbf-71d657662dbc',
      logglySubdomain: 'logantesting'
  };
  module.exports = exports['default'];

/***/ },
/* 143 */
/***/ function(module, exports, __webpack_require__) {

  // Test specific configuration
  // ===========================
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
      value: true
  });
  var util = __webpack_require__(38);
  exports['default'] = {
      env: 'logan-testing',
      esnaSubdomain: 'onesnatesting',
      getLink: function getLink(domain) {
          return 'https://' + domain;
      },
      getEsnaLink: function getEsnaLink(domain) {
          var iss = util.getIssFromHostname(domain);
          return 'https://' + this.esnaSubdomain + '.' + iss;
      },
  
      ip: process.env.OPENSHIFT_NODEJS_IP || process.env.IP || undefined,
  
      // Server port
      port: process.env.OPENSHIFT_NODEJS_PORT || process.env.PORT || 8080,
      // MongoDB connection options
      mongo: {
          uri: process.env.DB_URI || 'mongodb://zack:zack@ds061954.mongolab.com:61954/logan-testing',
          options: {
              db: {
                  safe: true
              },
              server: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              },
              replset: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              }
          }
      },
      logDB: {
          uri: process.env.LOGDB_URI || 'mongodb://zack:zack@ds061954.mongolab.com:61954/logan-testing',
          options: {
              db: {
                  safe: true
              },
              server: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              },
              replset: {
                  socketOptions: {
                      keepAlive: 1,
                      connectTimeoutMS: 30000
                  }
              }
          },
          logSize: 150000000
      },
      redis: {
          host: process.env['REDIS_HOST'] || 'pub-redis-14647.us-east-1-3.7.ec2.redislabs.com',
          port: process.env['REDIS_PORT'] || 14647,
          auth: process.env['REDIS_AUTH'] || 'logantesting',
          ssl: false
      },
      mongoLog: true,
      viewId: 121513396,
      googleAnalyticsId: "UA-77334981-2",
      useRedis: process.env['USE_REDIS'] || true,
      logLevel: process.env['LOG_LEVEL'] || 'silly',
      projectId: 'onesnatesting',
      gcloudKey: process.env['GCLOUD_KEY_PATH'] || __webpack_require__(20).resolve('./private/gcskey_testing.json'),
      ESNA_API_KEY: process.env['ESNA_API_KEY'] || 'b05f5eaa-42be-4830-a7b1-d44e7119c9e0',
      SubDomains: {
          'socket': '',
          'task': ''
      },
      bucket: 'onesnatesting',
      tempExtneralBucket: 'onesnatesting_temp_external',
      logglyToken: 'eaa77580-ba2d-4d69-abbf-71d657662dbc',
      logglySubdomain: 'logantesting'
  };
  module.exports = exports['default'];

/***/ },
/* 144 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Express configuration
   */
  
  'use strict';
  
  var express = __webpack_require__(10),
      compression = __webpack_require__(166),
      bodyParser = __webpack_require__(161),
      methodOverride = __webpack_require__(184),
      cookieParser = __webpack_require__(169),
      path = __webpack_require__(20),
      session = __webpack_require__(174),
      MongoStore = __webpack_require__(167)(session),
      config = __webpack_require__(27),
      passport = __webpack_require__(25),
      logger = __webpack_require__(1),
      mongoose = __webpack_require__(5);
  
  function haltOnTimedout(req, res, next) {
    if (!req.timedout) next();
  }
  
  module.exports = function (app) {
    app.use(compression());
    app.use(express['static'](path.join(__dirname, 'public')));
  
    app.use(function (req, res, next) {
      if (req.url.match(/^\/(css|js|img|font)\/.+/)) {
        logger.debug('setting cache ' + req.url);
        res.setHeader('Cache-Control', 'public, max-age=3600');
      }
      next();
    });
    app.use(bodyParser.urlencoded({ extended: false }));
    app.use(bodyParser.json());
    app.use(haltOnTimedout);
    app.use(methodOverride());
    //app.use(cookieParser());
    app.use(passport.initialize());
    app.set('etag', false);
  
    //  app.use(function (req, res, next) {
    //    session({
    //        secret: config.secrets.session,
    //        resave: true,
    //        saveUninitialized: true,
    //        store: new MongoStore({mongooseConnection: mongoose.connection})
    //    });
    //    next();
    //  });
  };

/***/ },
/* 145 */
/***/ function(module, exports, __webpack_require__) {

  /*! React Starter Kit | MIT License | http://www.reactstarterkit.com/ */
  
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  var _this = this;
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _path = __webpack_require__(20);
  
  var _express = __webpack_require__(10);
  
  var _jade = __webpack_require__(181);
  
  var _jade2 = _interopRequireDefault(_jade);
  
  var _frontMatter = __webpack_require__(175);
  
  var _frontMatter2 = _interopRequireDefault(_frontMatter);
  
  var _utilsFs = __webpack_require__(151);
  
  var _utilsFs2 = _interopRequireDefault(_utilsFs);
  
  // A folder with Jade/Markdown/HTML content pages
  var CONTENT_DIR = (0, _path.join)(__dirname, './content');
  
  // Extract 'front matter' metadata and generate HTML
  var parseJade = function parseJade(path, jadeContent) {
    var fmContent = (0, _frontMatter2['default'])(jadeContent);
    var htmlContent = _jade2['default'].render(fmContent.body);
    return Object.assign({ path: path, content: htmlContent }, fmContent.attributes);
  };
  
  var router = new _express.Router();
  
  router.get('/', function callee$0$0(req, res, next) {
    var path, fileName, source, content;
    return regeneratorRuntime.async(function callee$0$0$(context$1$0) {
      while (1) switch (context$1$0.prev = context$1$0.next) {
        case 0:
          context$1$0.prev = 0;
          path = req.query.path;
  
          if (!(!path || path === 'undefined')) {
            context$1$0.next = 5;
            break;
          }
  
          res.status(400).send({ error: 'The \'path\' query parameter cannot be empty.' });
          return context$1$0.abrupt('return');
  
        case 5:
          fileName = (0, _path.join)(CONTENT_DIR, (path === '/' ? '/index' : path) + '.jade');
          context$1$0.next = 8;
          return regeneratorRuntime.awrap(_utilsFs2['default'].exists(fileName));
  
        case 8:
          if (context$1$0.sent) {
            context$1$0.next = 10;
            break;
          }
  
          fileName = (0, _path.join)(CONTENT_DIR, path + '/index.jade');
  
        case 10:
          context$1$0.next = 12;
          return regeneratorRuntime.awrap(_utilsFs2['default'].exists(fileName));
  
        case 12:
          if (context$1$0.sent) {
            context$1$0.next = 16;
            break;
          }
  
          res.status(404).send({ error: 'The page \'' + path + '\' is not found.' });
          context$1$0.next = 21;
          break;
  
        case 16:
          context$1$0.next = 18;
          return regeneratorRuntime.awrap(_utilsFs2['default'].readFile(fileName, { encoding: 'utf8' }));
  
        case 18:
          source = context$1$0.sent;
          content = parseJade(path, source);
  
          res.status(200).send(content);
  
        case 21:
          context$1$0.next = 26;
          break;
  
        case 23:
          context$1$0.prev = 23;
          context$1$0.t0 = context$1$0['catch'](0);
  
          next(context$1$0.t0);
  
        case 26:
        case 'end':
          return context$1$0.stop();
      }
    }, null, _this, [[0, 23]]);
  });
  
  exports['default'] = router;
  module.exports = exports['default'];

/***/ },
/* 146 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
  	value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror = __webpack_require__(41);
  
  var _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror2 = _interopRequireDefault(_node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror);
  
  var _underscore = __webpack_require__(64);
  
  var _underscore2 = _interopRequireDefault(_underscore);
  
  var _componentsTranslate = __webpack_require__(47);
  
  var _componentsTranslate2 = _interopRequireDefault(_componentsTranslate);
  
  var _MeetingConstants = __webpack_require__(39);
  
  var _MeetingConstants2 = _interopRequireDefault(_MeetingConstants);
  
  var ns = '[PresenceConstants]';
  var PresenceConstants = {};
  
  PresenceConstants.IDEA_DEFAULT_DATA = {
  	bodyText: '',
  	description: '',
  	data: []
  };
  
  PresenceConstants.ACTIONS = (0, _node_modulesReactInterpolateComponentNode_modulesFbjsLibKeyMirror2['default'])({
  	EDIT_IDEA: null,
  	CREATE_IDEA: null,
  	ARRIVED_IDEA: null
  });
  
  PresenceConstants.API = {
  	TOPIC_IDEA_ADD: '/api/topics/:topicId/ideas',
  	IDEA_UPDATE: '/api/messages/:msgId',
  	IDEA_MESSAGES: '/api/ideas/:ideaId/messages'
  };
  
  PresenceConstants.getUserDefaultPresences = function (options) {
  	var func = ns + '[getUserDefaultPresences] ';
  	options = _underscore2['default'].assign({
  		role: _MeetingConstants2['default'].getUserTopicRole(options.topic, options.user)
  	}, options);
  	return PresenceConstants.getUserDefaultPresencesWithRole(options);
  };
  
  PresenceConstants.getUserDefaultPresencesWithRole = function (options) {
  	var func = ns + '[getUserDefaultPresencesWithRole] ';
  	options = _underscore2['default'].assign({
  		offline: true,
  		idle: true,
  		mediaSession: options.mediaSession || PresenceConstants.getDefaultMediaSessionPresence(),
  		desktop: false
  	}, options);
  
  	var data = {
  		offline: options.offline,
  		role: options.role,
  		mediaSession: options.mediaSession,
  		idle: options.idle,
  		desktop: options.desktop
  	};
  	return data;
  };
  
  PresenceConstants.getDefaultMediaSessionPresence = function () {
  	return { video: false, audio: false, connected: false, screenshare: false };
  };
  
  exports['default'] = PresenceConstants;
  module.exports = exports['default'];

/***/ },
/* 147 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
  	value: true
  });
  var logger = __webpack_require__(1);
  var config = __webpack_require__(4);
  var google = __webpack_require__(177);
  var fs = __webpack_require__(43);
  var key = JSON.parse(fs.readFileSync(config.gcloudKey, 'utf8'));
  var scopes = ['https://www.googleapis.com/auth/analytics.edit', 'https://www.googleapis.com/auth/analytics.manage.users'];
  
  var jwtClient = new google.auth.JWT(key.client_email, null, key.private_key, scopes, null);
  
  exports['default'] = jwtClient;
  module.exports = exports['default'];

/***/ },
/* 148 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  exports['default'] = __webpack_require__(84);
  module.exports = exports['default'];

/***/ },
/* 149 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * Socket.io configuration
   */
  
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _configEnvEnvironmentIndex = __webpack_require__(27);
  
  var _configEnvEnvironmentIndex2 = _interopRequireDefault(_configEnvEnvironmentIndex);
  
  var _authSocketAuth = __webpack_require__(137);
  
  var _authSocketAuth2 = _interopRequireDefault(_authSocketAuth);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _underscore = __webpack_require__(64);
  
  var _underscore2 = _interopRequireDefault(_underscore);
  
  var _os = __webpack_require__(51);
  
  var _os2 = _interopRequireDefault(_os);
  
  var _apiMessageMessageBackend = __webpack_require__(26);
  
  var _apiMessageMessageBackend2 = _interopRequireDefault(_apiMessageMessageBackend);
  
  var _apiTopicTopicBackend = __webpack_require__(75);
  
  var _apiTopicTopicBackend2 = _interopRequireDefault(_apiTopicTopicBackend);
  
  var _socketIoRedis = __webpack_require__(192);
  
  var _socketIoRedis2 = _interopRequireDefault(_socketIoRedis);
  
  var _fluxConstantsSocketConstants = __webpack_require__(60);
  
  var _fluxConstantsSocketConstants2 = _interopRequireDefault(_fluxConstantsSocketConstants);
  
  var _fluxConstantsMessageConstants = __webpack_require__(17);
  
  var _fluxConstantsMessageConstants2 = _interopRequireDefault(_fluxConstantsMessageConstants);
  
  var _fluxConstantsPresenceConstants = __webpack_require__(146);
  
  var _fluxConstantsPresenceConstants2 = _interopRequireDefault(_fluxConstantsPresenceConstants);
  
  var _utilsP2PMediaSessionMediaSessionManager = __webpack_require__(150);
  
  var _utilsP2PMediaSessionMediaSessionManager2 = _interopRequireDefault(_utilsP2PMediaSessionMediaSessionManager);
  
  var _utilsServerHelper = __webpack_require__(6);
  
  var _utilsServerHelper2 = _interopRequireDefault(_utilsServerHelper);
  
  var ns = '[socketio]';
  var io = __webpack_require__(191);
  // import ga from "./modules/analytics/google";
  // import gaCst from "./modules/analytics/google/constants";
  
  var totalSocketCount = 0;
  var metadata = {};
  
  var adapter;
  var pub = __webpack_require__(63).createClient(_configEnvEnvironmentIndex2['default'].redis.port, _configEnvEnvironmentIndex2['default'].redis.host, { tls: _configEnvEnvironmentIndex2['default'].redis.ssl, auth_pass: _configEnvEnvironmentIndex2['default'].redis.auth });
  var sub = __webpack_require__(63).createClient(_configEnvEnvironmentIndex2['default'].redis.port, _configEnvEnvironmentIndex2['default'].redis.host, { return_buffers: true, auth_pass: _configEnvEnvironmentIndex2['default'].redis.auth, tls: _configEnvEnvironmentIndex2['default'].redis.ssl });
  
  adapter = (0, _socketIoRedis2['default'])({
    pubClient: pub,
    subClient: sub
  });
  
  adapter.pubClient.on('error', function () {
    _modulesLogger2['default'].warn('pub connection lost');
  });
  adapter.subClient.on('error', function () {
    _modulesLogger2['default'].warn('sub connection lost');
  });
  
  adapter.prototype.on('error', function () {
    _modulesLogger2['default'].error('Redis adapter connection lost');
  });
  
  // When the user disconnects.. perform this
  function onDisconnect(socket) {}
  
  // When the user connects.. perform this
  function onConnect(socket) {
    // When the client emits 'info', this listens and executes
    socket.on('info', function (data) {
      console.info('[%s] %s', socket.address, JSON.stringify(data, null, 2));
    });
  
    socket.on('newmessage', function (data) {
      console.log('i got this piece of message', data);
    });
  
    // Insert sockets below
    __webpack_require__(158).register(socket);
    __webpack_require__(159).register(socket);
  }
  
  exports.initialize = function (server) {
    // socket.io (v1.x.x) is powered by debug.
    // In order to see all the debug output, set DEBUG (in server/config/local.env.js) to including the desired scope.
    //
    // ex: DEBUG: "http*,socket.io:socket"
  
    // We can authenticate socket.io users and access their token through socket.handshake.decoded_token
    //
    // 1. You will need to send the token in `client/components/socket/socket.service.js`
    //
    // 2. Require authentication here:
  
    io = io.listen(server);
  
    //io.configure(function() {
    //  io.set('transports', ['websocket']);
    //});
  
    //refernces for how to setup transport types:
    // http://stackoverflow.com/questions/28238628/socket-io-1-x-use-websockets-only
    // http://stackoverflow.com/questions/23962047/socket-io-v1-0-x-unknown-transport-polling
    // io.set('heartbeat interval', 25);
    // io.set('heartbeat timeout', 60);
  
    //io.set('transports', ['websocket']);
  
    if (_configEnvEnvironmentIndex2['default'].useRedis) {
      io.adapter(adapter);
    }
    var IO_NAME_SPACE = '/chat';
    var self = this;
    this.chat = io.of(IO_NAME_SPACE);
    this.chat.use(_authSocketAuth2['default'].authorize({
      handshake: true
    }));
  
    self.mediaSessionManager = new _utilsP2PMediaSessionMediaSessionManager2['default']();
  
    self.socketPartyLeaves = function (socket, channelName) {
      var func = ns + '[socketPartyLeaves]';
      var sessionId = null;
      if (socket.channelSessionData && socket.channelSessionData[channelName]) {
        sessionId = socket.channelSessionData[channelName].sessionId;
        _modulesLogger2['default'].info(func, 'about to delete mediasession', sessionId);
        delete socket.channelSessionData[channelName];
      }
  
      if (socket.logan_channels && socket.logan_channels[channelName]) {
        var topicId = socket.logan_channels[channelName].channel._id;
        var user = self.getSocketUserInfo(socket);
        var data = {
          sender: user,
          topicId: topicId //notify everybody else in the room that I joined the room
        };
  
        var payload = _underscore2['default'].assign({
          origin: 'server',
          category: _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.APP_EVENTS.PartyLeaves,
          content: {
            emitedby: 'server',
            sessionId: sessionId,
            data: []
          }
        }, data);
  
        console.log(func, '$channelName:', channelName, payload);
        socket.broadcast.to(channelName).emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.PRESENCE_EVENT_RESPONSE, payload);
  
        delete socket.logan_channels[channelName];
      }
    };
  
    self.hasTopicAccess = function (socket, topicId, cb) {
      var func = ns + '[hasTopicAccess]';
      try {
        if (topicId) {
          var user = self.getSocketUserInfo(socket);
          var data = {
            user: user,
            topicId: topicId //notify everybody else in the room that I joined the room
          };
          _apiTopicTopicBackend2['default'].hasTopicAccess(data, function (err, topicAccess) {
            _modulesLogger2['default'].info(func, err, 'topicId:', topicId, topicAccess.role);
            cb(err, topicAccess);
          });
        }
      } catch (err2) {
        _modulesLogger2['default'].error(func, err2, socket.metadata);
      }
    };
  
    self.socketRequestPartiesPresence = function (socket, channelName, topicAccess) {
      var func = ns + '[socketRequestPartiesPresence]';
      var topicId = socket.logan_channels[channelName].channel._id;
      var user = self.getSocketUserInfo(socket);
      var data = {
        sender: user,
        topicId: topicId //notify everybody else in the room that I joined the room
      };
  
      var sessionId = null;
      if (socket.channelSessionData && socket.channelSessionData[channelName]) {
        sessionId = socket.channelSessionData[channelName].sessionId;
      }
  
      var payload = _underscore2['default'].assign({
        category: _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.APP_EVENTS.RequestPartiesPresence,
        content: {
          sessionId: sessionId,
          data: []
        }
        //content: _.assign({
        //  sessionId: sessionId,
        //  data: []
        //}, PresenceConstants.getUserDefaultPresencesWithRole({
        //  role: topicAccess.role,
        //  offline: false
        //}))
      }, data);
  
      _modulesLogger2['default'].info(func, '$channelName:', channelName, payload);
      //io.of(IO_NAME_SPACE).to(channelName).emit(SocketConstants.EVENT_NAMESPACE.SEND_PRESENCE_EVENT, payload)
      socket.broadcast.to(channelName).emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.PRESENCE_EVENT_RESPONSE, payload);
    };
  
    self.getSocketUserInfo = function (socket) {
      if (!socket) {
        return {};
      }
      return {
        _id: socket.metadata.connector,
        username: socket.metadata.connector_email,
        displayname: socket.metadata.connector_displayname,
        picture_url: socket.metadata.connector_picture_url,
        type: socket.metadata.connectorType
      };
    };
  
    //  ver 1.x way -- http://socket.io/docs/migrating-from-0-9/
    this.chat.use(function (socket, next) {
      var handshakeData = socket.request;
      _modulesLogger2['default'].info('socket use() decoded_token:', socket.decoded_token);
  
      // make sure the handshake data looks good as before
      // if error do this:
      // next(new Error('not authorized');
      // else just call next
      next();
    });
  
    __webpack_require__(114).register(this.chat);
  
    this.chat.on('connection', function (socket) {
      // socket.request.headers.hostname = os.hostname();
      socket.metadata = {};
      try {
        socket.metadata = JSON.parse(JSON.stringify(metadata));
        totalSocketCount = totalSocketCount + 1;
        socket.metadata.socketid = socket.id;
        var user = socket.anonymousUser || socket.user;
        socket.metadata.connector = user ? user._id.toString() : undefined;
        socket.metadata.connector_email = user.username;
        socket.metadata.connector_displayname = user.displayname;
        socket.metadata.connector_picture_url = user.picture_url;
        socket.metadata.connectorType = user.aType;
        socket.metadata.transportType = socket.conn.transport.name;
  
        socket.channelSessionData = socket.channelSessionData || {};
  
        // //google analytics
        // socket.metadata.connectionStart = Date.now();
        // ga.postEvent({category: gaCst.c_Socket, action: gaCst.a_onConnect, label: socket.metadata.connector});
        // //
        _modulesLogger2['default'].info('1 socket connectino established, totalSocketCount: ', totalSocketCount, socket.metadata);
  
        //  connection means authentication already passed, notify client the logged in success with basic userinfo
        //      socket.emit ('s_loggedin', {
        //        userid: socket.decoded_token.userid,
        //        username: socket.decoded_token.username
        //      });
  
        //everyone automatically joins a special room named after userid upon connection
        // socket.join(socket.decoded_token.userid);
      } catch (err) {
        _modulesLogger2['default'].error('socket meta data initiation error', err, socket.metadata);
      }
  
      socket.on(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.ERROR, function () {
        socket.metadata.status = 'error';
        _modulesLogger2['default'].error('Error happened in socket-io', 'totalSocketCount: ', totalSocketCount, socket.metadata);
      });
  
      socket.on(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.CONNECTION_ERROR, function () {
        socket.metadata.status = 'connection_error';
        _modulesLogger2['default'].error('Error happened during connecting to socketio', 'totalSocketCount: ', totalSocketCount, socket.metadata);
      });
  
      socket.on(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.ON_DISCONNECT, function (payload) {
        var func = ns + '[' + _fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.ON_DISCONNECT + ']';
        totalSocketCount = totalSocketCount - 1;
        //      socket.metadata.totalSocketCount = totalSocketCount;
        try {
          socket.metadata.status = 'disconnected';
          // //google analytics
          // var duration = Date.now() - socket.metadata.connectionStart;
          // ga.postEvent({category: gaCst.c_Socket, action: gaCst.a_onDisconnect, label: socket.metadata.connector, value: duration});
          // delete socket.metadata.connectionStart;
          // //
          var user = self.getSocketUserInfo(socket);
          _modulesLogger2['default'].info(func, 'totalSocketCount: ', totalSocketCount, user);
          for (var channel in socket.logan_channels) {
            if (socket.logan_channels.hasOwnProperty(channel)) {
              var channelName = socket.logan_channels[channel].name;
              // do stuff
              _modulesLogger2['default'].info(func, 'ABOUT TO EMIT DISCONNECTIONS:');
              _modulesLogger2['default'].info(func, '1 socket disconnect, leave room: %s, socket.id: %s, username: %s', socket.logan_channels[channel], socket.id, user.username);
  
              self.socketPartyLeaves(socket, channelName);
            }
          }
        } catch (err) {
          _modulesLogger2['default'].error(func, err, socket.metadata);
        }
      });
  
      socket.on(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SUBSCRIBE_CHANNEL, function (data) {
        socket.logan_channels = socket.logan_channels || {};
  
        try {
          var channel = data.channel;
          var logData = JSON.parse(JSON.stringify(socket.metadata));
          logData.chanel = channel;
  
          _modulesLogger2['default'].info(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SUBSCRIBE_CHANNEL, 'ABOUT TO JOIN CHANNEL-------------------------------------:', logData);
  
          var channelName = _fluxConstantsSocketConstants2['default'].getChannelName(channel);
          self.hasTopicAccess(socket, channel._id, function (err, topicAccess) {
            if (topicAccess) {
              socket.join(channelName);
              socket.logan_channels[channelName] = { name: channelName, channel: channel };
              socket.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.CHANNEL_SUBSCRIBED, { channel: channel }); //notify myself joined successfully
              var user = self.getSocketUserInfo();
              socket.channelSessionData[channelName] = socket.channelSessionData[channelName] || self.mediaSessionManager.startUserMediaSession(data.topicId, user);
              self.socketRequestPartiesPresence(socket, channelName, topicAccess);
            } else {
              _modulesLogger2['default'].error('Invalid Channel Name', channel, err);
            }
          });
          //google analytics
          // ga.postEvent({category: gaCst.c_Socket, action: gaCst.a_joinRoom, label: channelName});
          //
        } catch (err) {
          _modulesLogger2['default'].error(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SUBSCRIBE_CHANNEL, err, socket.metadata);
        }
      });
  
      socket.on(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.UNSUBSCRIBE_CHANNEL, function (data) {
        socket.logan_channels = socket.logan_channels || {};
  
        try {
          var channel = data.channel;
          var channelName = _fluxConstantsSocketConstants2['default'].getChannelName(channel);
          if (channelName) {
            var logData = JSON.parse(JSON.stringify(socket.metadata));
            logData.chanel = channel;
            _modulesLogger2['default'].info(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.UNSUBSCRIBE_CHANNEL, 'channel:', logData);
            socket.leave(channelName);
            socket.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.CHANNEL_UNSUBSCRIBED, { channel: channel }); //notify myself joined successfully
            self.socketPartyLeaves(socket, channelName);
          }
        } catch (err) {
          _modulesLogger2['default'].error(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.UNSUBSCRIBE_CHANNEL, err, socket.metadata);
        }
      });
  
      //SocketConstants.EVENT_NAMESPACE.SEND_GROUP_MESSAGE
  
      socket.on(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SEND_GROUP_MESSAGE, function (data) {
        try {
          //data.datetime = new Date().toISOString();
  
          //1. should check whether the sender is authorized to send the message
          //2. set the sender of the message regardless of the original data
          //3. set created/update of the message before saving
          //4. before emiting the message, resolve message object with helper fields like: sender.displayname, sender.picture_url, and image links?
          //5. echo/broadcast the saved message with mongoDB ID
          //in case of failure it should throw SEND_GROUP_MESSAGE_FAILED.
  
          //echo back to sender
          //also echo back my own message
          socket.metadata.transportType = socket.conn.transport.name;
          var addMessagetoDownloadableClientFormatMessageBegtm = Date.now();
          var src = _utilsServerHelper2['default'].getSrcFromSocket(socket);
          var userObj = self.getSocketUserInfo(socket);
          data.sender.username = userObj.username;
          data.sender.displayname = userObj.displayname;
          data.sender.picture_url = userObj.picture_url;
          _apiMessageMessageBackend2['default'].addMessageWhenNoIdtoDownloadableClientFormatMessage(src, data, function (err, sentMsg) {
            var addMessagetoDownloadableClientFormatMessageEndtm = Date.now();
            // logger.debug("addMessagetoDownloadableClientFormatMessage consume time ",
            //             addMessagetoDownloadableClientFormatMessageEndtm - addMessagetoDownloadableClientFormatMessageBegtm);
            if (err) {
              _modulesLogger2['default'].error(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SEND_GROUP_MESSAGE, err, socket.metadata);
              return socket.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SEND_GROUP_MESSAGE_FAILED, data);
            }
            var channelName = 'topic_' + data.topicId;
            var logData = JSON.parse(JSON.stringify(socket.metadata));
            logData.channelName = channelName;
            _modulesLogger2['default'].info(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SEND_GROUP_MESSAGE, 'about to emit: ', logData);
            socket.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.GROUP_MESSAGE_SENT, sentMsg);
            //broadcast to everybody in the room the chat message
            // //google analytics
            // ga.postMessageEvent(sentMsg);
            // //
            socket['in'](channelName).broadcast.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.GROUP_MESSAGE_SENT, sentMsg);
          });
          //socket.emit(EVENT_NAMESPACE.SEND_GROUP_MESSAGE, data);
  
          //var channelName = 'topic_' + data.topicId;
          //logger.info(SocketConstants.EVENT_NAMESPACE.SEND_GROUP_MESSAGE, 'channelName:', channelName, socket.metadata);
          //broadcast to everybody in the room the chat message
          //socket.in(channelName).broadcast.emit(SocketConstants.EVENT_NAMESPACE.GROUP_MESSAGE_SENT, data);
        } catch (err) {
          _modulesLogger2['default'].error(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SEND_GROUP_MESSAGE, err, socket.metadata);
          return socket.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SEND_GROUP_MESSAGE_FAILED, data);
        }
      });
  
      socket.on(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.START_MEDIA_SESSION, function callee$2$0(data) {
        var func, user, channelName, sessionData;
        return regeneratorRuntime.async(function callee$2$0$(context$3$0) {
          while (1) switch (context$3$0.prev = context$3$0.next) {
            case 0:
              func = ns + '[' + _fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SEND_MEDIA_SESSION_EVENTS + ']';
              context$3$0.prev = 1;
  
              socket.metadata.transportType = socket.conn.transport.name;
  
              if (!(!data || !data.topicId)) {
                context$3$0.next = 5;
                break;
              }
  
              return context$3$0.abrupt('return');
  
            case 5:
              user = self.getSocketUserInfo(socket);
  
              _modulesLogger2['default'].info(func, ' user: ', user);
  
              channelName = 'topic_' + data.topicId;
              sessionData = self.mediaSessionManager.startUserMediaSession(data.topicId, user);
  
              _modulesLogger2['default'].info(func, 'startUserMediaSession.then: ', sessionData);
  
              if (!socket.channelSessionData) {
                socket.channelSessionData = {};
              }
              socket.channelSessionData[channelName] = sessionData;
  
              //echo back the session data.
              socket.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.MEDIA_SESSION_RESPONSE, {
                topicId: data.topicId,
                sender: user,
                category: _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO.MediaSessionReady,
                content: sessionData
              });
  
              setTimeout(function () {
                //we probalby need to delay this
                //let others know this user is ready to receive calsl
                socket['in'](channelName).broadcast.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.MEDIA_SESSION_RESPONSE, {
                  topicId: data.topicId,
                  sender: user,
                  category: _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO.READY,
                  content: {
                    sessionId: sessionData.sessionId
                  }
                });
              }, 1000);
              context$3$0.next = 20;
              break;
  
            case 16:
              context$3$0.prev = 16;
              context$3$0.t0 = context$3$0['catch'](1);
  
              _modulesLogger2['default'].error(func, context$3$0.t0, socket.metadata);
              return context$3$0.abrupt('return', socket.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.MEDIA_SESSION_RESPONSE, { error: context$3$0.t0 }));
  
            case 20:
            case 'end':
              return context$3$0.stop();
          }
        }, null, this, [[1, 16]]);
      });
  
      socket.on(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SEND_MEDIA_SESSION_EVENTS, function callee$2$0(data) {
        var func, user, channelName, sessionData, payload;
        return regeneratorRuntime.async(function callee$2$0$(context$3$0) {
          while (1) switch (context$3$0.prev = context$3$0.next) {
            case 0:
              func = ns + '[' + _fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SEND_MEDIA_SESSION_EVENTS + ']';
              context$3$0.prev = 1;
  
              _modulesLogger2['default'].info(func, 'begin', data);
              // //google analytics
              // if (data.category === MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO.TracksStatus) {
              //   if (!socket.metadata.videoStart) {
              //     // ga.postEvent({category: gaCst.c_Socket, action: gaCst.a_onVideoStart, label: socket.metadata.connector});
              //     socket.metadata.videoStart = Date.now();
              //   }
              // } else if (data.category === MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO.EndVideoChat) {
              //   let duration = socket.metadata.videoStart? Date.now() - socket.metadata.videoStart: 0;
              //   ga.postEvent({category: gaCst.c_Socket, action: gaCst.a_onVideoEnd, label: socket.metadata.connector, value: duration});
              //   delete socket.metadata.videoStart;
              // } else if (data.category === MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO.StartScreenShare) {
              //    if (!socket.metadata.sreenShareStart) {
              //     // ga.postEvent({category: gaCst.c_Socket, action: gaCst.a_onScreenShareStart, label: socket.metadata.connector});
              //     socket.metadata.sreenShareStart = Date.now();
              //   }
              // } else if (data.category === MessageConstants.ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO.StopScreenShare) {
              //   let duration = socket.metadata.sreenShareStart? Date.now() - socket.metadata.sreenShareStart: 0;
              //   ga.postEvent({category: gaCst.c_Socket, action: gaCst.a_onScreenShareEnd, label: socket.metadata.connector, value: duration});
              //   delete socket.metadata.sreenShareStart;
              // }
              // //
              socket.metadata.transportType = socket.conn.transport.name;
  
              if (!(!data || !data.topicId)) {
                context$3$0.next = 6;
                break;
              }
  
              return context$3$0.abrupt('return');
  
            case 6:
              user = self.getSocketUserInfo(socket);
              channelName = 'topic_' + data.topicId;
  
              socket.channelSessionData = socket.channelSessionData || {};
              socket.channelSessionData[channelName] = socket.channelSessionData[channelName] || self.mediaSessionManager.startUserMediaSession(data.topicId, user);
  
              sessionData = socket.channelSessionData[channelName];
  
              if (sessionData) {
                context$3$0.next = 15;
                break;
              }
  
              socket.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.MEDIA_SESSION_RESPONSE, {
                topicId: data.topicId,
                sender: user,
                category: _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO.InvalidMediaSession
              });
              _modulesLogger2['default'].error(func, 'invalid session');
              return context$3$0.abrupt('return');
  
            case 15:
  
              _modulesLogger2['default'].info(func, 'got sessionData: ', sessionData);
  
              if (!self.mediaSessionManager.processScreenShareAppRequests(data.topicId, user, data, sessionData, function (err, result) {
                _modulesLogger2['default'].info(func, 'processScreenShareAppRequests.then', err);
                if (result) {
                  _modulesLogger2['default'].info(func, ' result from processScreenShareAppRequests we have ScreenShareAppEvent result: ');
                  //socket.channelSessionData[channelName] = sessionData;
                  var payload = {
                    topicId: data.topicId,
                    sender: user,
                    category: data.category,
                    content: _underscore2['default'].assign({
                      sessionId: sessionData.sessionId
                    }, result)
                  };
                  payload.content = payload.content || {};
                  payload.content.sessionId = sessionData.sessionId;
                  _modulesLogger2['default'].info(func, 'about to emit back: ');
                  socket.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.MEDIA_SESSION_RESPONSE, payload);
                }
              })) {
                context$3$0.next = 18;
                break;
              }
  
              return context$3$0.abrupt('return');
  
            case 18:
              if (!self.mediaSessionManager.processScreenShareAppEvent(data.topicId, user, data, sessionData, function (err, result) {
                _modulesLogger2['default'].info(func, 'processScreenShareAppEvent.then', err, result);
                if (!err) {
                  result.content = result.content || {};
                  result.content.sessionId = sessionData.sessionId;
                  _modulesLogger2['default'].info(func, 'about to broadcast processScreenShareAppEvent: ', result);
                  socket['in'](channelName).broadcast.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.MEDIA_SESSION_RESPONSE, result);
                }
              })) {
                context$3$0.next = 20;
                break;
              }
  
              return context$3$0.abrupt('return');
  
            case 20:
              payload = _underscore2['default'].assign({
                topicId: data.topicId,
                sender: user,
                content: {}
              }, data);
  
              payload.content.sessionId = sessionData.sessionId;
              _modulesLogger2['default'].info(func, 'about to broadcast to others: ', payload);
              //let others know this user is ready to receive calsl
              socket['in'](channelName).broadcast.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.MEDIA_SESSION_RESPONSE, payload);
  
              //msgbk.addMessageWhenNoIdtoDownloadableClientFormatMessage({}, data, function(err, sentMsg){
              //
              //});
              context$3$0.next = 30;
              break;
  
            case 26:
              context$3$0.prev = 26;
              context$3$0.t0 = context$3$0['catch'](1);
  
              _modulesLogger2['default'].error(func, context$3$0.t0, socket.metadata);
              return context$3$0.abrupt('return', socket.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.MEDIA_SESSION_RESPONSE, { error: context$3$0.t0 }));
  
            case 30:
            case 'end':
              return context$3$0.stop();
          }
        }, null, this, [[1, 26]]);
      });
  
      socket.on(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SEND_PRESENCE_EVENT, function callee$2$0(data) {
        var func, user, channelName, sessionData, payload;
        return regeneratorRuntime.async(function callee$2$0$(context$3$0) {
          while (1) switch (context$3$0.prev = context$3$0.next) {
            case 0:
              func = ns + '[' + _fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.SEND_PRESENCE_EVENT + ']';
              context$3$0.prev = 1;
  
              _modulesLogger2['default'].info(func, 'begin', data);
              socket.metadata.transportType = socket.conn.transport.name;
  
              if (!(!data || !data.topicId)) {
                context$3$0.next = 6;
                break;
              }
  
              return context$3$0.abrupt('return');
  
            case 6:
              user = self.getSocketUserInfo(socket);
              channelName = 'topic_' + data.topicId;
  
              socket.channelSessionData = socket.channelSessionData || {};
              socket.channelSessionData[channelName] = socket.channelSessionData[channelName] || self.mediaSessionManager.startUserMediaSession(data.topicId, user);
  
              sessionData = socket.channelSessionData[channelName];
  
              if (sessionData) {
                context$3$0.next = 15;
                break;
              }
  
              socket.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.PRESENCE_EVENT_RESPONSE, {
                topicId: data.topicId,
                sender: user,
                category: _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO.InvalidMediaSession
              });
              _modulesLogger2['default'].error(func, 'invalid session');
              return context$3$0.abrupt('return');
  
            case 15:
              payload = _underscore2['default'].assign({
                topicId: data.topicId,
                sender: user,
                content: {}
              }, data);
  
              payload.content.sessionId = sessionData.sessionId;
              _modulesLogger2['default'].info(func, 'about to broadcast to others: ', payload);
              //let others know this user is ready to receive calsl
              socket['in'](channelName).broadcast.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.PRESENCE_EVENT_RESPONSE, payload);
  
              //msgbk.addMessageWhenNoIdtoDownloadableClientFormatMessage({}, data, function(err, sentMsg){
              //
              //});
              context$3$0.next = 25;
              break;
  
            case 21:
              context$3$0.prev = 21;
              context$3$0.t0 = context$3$0['catch'](1);
  
              _modulesLogger2['default'].error(func, context$3$0.t0, socket.metadata);
              return context$3$0.abrupt('return', socket.emit(_fluxConstantsSocketConstants2['default'].EVENT_NAMESPACE.PRESENCE_EVENT_RESPONSE, { error: context$3$0.t0 }));
  
            case 25:
            case 'end':
              return context$3$0.stop();
          }
        }, null, this, [[1, 21]]);
      });
  
      /*socket.on(SocketConstants.EVENT_NAMESPACE.SEND_DIRECT_MESSAGE, function (data) {
        try {
          data.datetime = new Date().toISOString();
          if (data.sender.id === socket.decoded_token._id) {
            logger.info(SocketConstants.EVENT_NAMESPACE.DIRECT_MESSAGE_SENT, 'touser: %s, message: %s...',
              data.touser.username, data.message.body.substring(0, 15), metadata);
            socket.emit(SocketConstants.EVENT_NAMESPACE.DIRECT_MESSAGE_SENT, data);  //echo back to myself
            socket.in(data.touser.id).broadcast.emit(SocketConstants.EVENT_NAMESPACE.DIRECT_MESSAGE_SENT, data);
          }
          else {
            logger.info(SocketConstants.EVENT_NAMESPACE.DIRECT_MESSAGE_SENT, 'fromuser: %s (%s) is not loggedin user, touser: %s, message: %s...',
              data.sender.username, data.sender.id, data.touser.username, data.message.body.substring(0, 15), metadata);
            socket.emit(SocketConstants.EVENT_NAMESPACE.DIRECT_MESSAGE_SEND_FAILED, data);  //echo back to myself
          }
        }
        catch (err) {
          logger.error(SocketConstants.EVENT_NAMESPACE.DIRECT_MESSAGE_SENT, err, socket.metadata);
        }
      });*/
  
      /*
      socket.on('c_invitejoin', function (data) {
        //invite touser to join the room
        //      data = {
        //        fromuser: {
        //          userid: userid,
        //          username: username
        //        },
        //        touser: {
        //          userid: userid,
        //          username: username
        //        }
        //        room: {
        //          roomname: roomname
        //        }
        //        datetime: datetime in ISOString
        //      }
          try {
          data.datetime = new Date().toISOString();
          if (data.sender.id === socket.decoded_token.userid) {
            logger.info('c_invitejoin, data:', data, metadata);
            socket.in(data.touser.id).broadcast.emit('s_invitejoin', data);
          }
          else {
            logger.info('c_invitejoin, fromuser: %s (%s) is not loggedin user, data:',
              data.sender.username, data.sender.id, data, metadata);
            socket.emit('s_invitejoin_fail', data);  //echo back to myself
          }
        }
        catch (err) {
          logger.error('c_invitejoin', err, socket.metadata);
        }
      });
       socket.on('c_readmsg', function (data) {
        //    the user read the message (usually put mouse/keyboard focus on the room window), need
        //    to notify other devices of the same user to mark the room read
        //      { fromuser: {
        //                    userid: 'afgdhfhlslfjxlldfl5670443',
        //                    username: 'zackc@esna.com'
        //                  },
        //        room: {
        //          roomname: 'room_123'
        //        },
        //        datetime: '2014-08-12T19:27:35.976Z'
        //      }
          try {
          data.datetime = new Date().toISOString();
          if (data.sender.id === socket.decoded_token.userid) {
            logger.info('c_readmsg, data: ', data, metadata);
             socket.emit('s_readmsg', data);  //echo back to myself
            //broadcast to all connected devices from the same user
            socket.in(data.sender.id).broadcast.emit('s_readmsg', data);
          }
          else {
            logger.info('c_readmsg, fromuser: %s (%s) is not loggedin user, data:',
              data.sender.username, data.sender.id, data, metadata);
            socket.emit('s_readmsg_fail', data);  //echo back to myself
          }
        }
        catch (err) {
          logger.error('c_readmsg: ', err, socket.metadata);
        }
      });
       socket.on('c_readprivatemsg', function (data) {
        //    the user read the private message (usually put mouse/keyboard focus on the room window), need
        //    to notify other devices of the same user to mark the room read
        //      data = {
        //        fromuser: {
        //          userid: userid,
        //          username: username
        //        },
        //        touser: {
        //          userid: userid,
        //          username: username
        //        }
        //        datetime: datetime in ISOString
        //      }
          try {
          data.datetime = new Date().toISOString();
          if (data.sender.id === socket.decoded_token.userid) {
            logger.info('c_readprivatemsg, data:', data, metadata);
            socket.in(data.sender.id).broadcast.emit('s_readprivatemsg', data);
          }
          else {
            logger.info('c_readprivatemsg, fromuser: %s (%s) is not loggedin user, data:',
              data.sender.username, data.sender.id, data, metadata);
            socket.emit('s_readprivatemsg_fail', data);  //echo back to myself
          }
        }
        catch (err) {
          logger.error('c_readprivatemsg', err, socket.metadata);
        }
      });
        socket.on('c_privatetyping', function (data) {
        //      data = {
        //        fromuser: {
        //          userid: userid,
        //          username: username
        //        },
        //        touser: {
        //          userid: userid,
        //          username: username
        //        }
        //        datetime: datetime in ISOString
        //      }
          try {
          data.datetime = new Date().toISOString();
          if (data.sender.id === socket.decoded_token.userid) {
            logger.info('c_privatetyping, data:', data, metadata);
            socket.in(data.touser.id).broadcast.emit('s_privatetyping', data);
          }
          else {
            logger.info('c_privatetyping, fromuser: %s (%s) is not loggedin user, data:',
              data.sender.username, data.sender.id, data, metadata);
            socket.emit('s_privatetyping_fail', data);  //echo back to myself
          }
        }
        catch (err) {
          logger.error('c_privatetyping', err, socket.metadata);
        }
      });
       socket.on('c_stop_privatetyping', function (data) {
        //      data = {
        //        fromuser: {
        //          userid: userid,
        //          username: username
        //        },
        //        touser: {
        //          userid: userid,
        //          username: username
        //        },
        //        datetime: datetime in ISOString
        //      }
          try {
          data.datetime = new Date().toISOString();
          if (data.sender.id === socket.decoded_token.userid) {
            logger.info('c_stop_privatetyping, data:', data, metadata);
            socket.in(data.touser.id).broadcast.emit('s_stop_privatetyping', data);
          }
          else {
            logger.info('c_stop_privatetyping, fromuser: %s (%s) is not loggedin user, data:',
              data.sender.username, data.sender.id, data, metadata);
            socket.emit('s_stop_privatetyping_fail', data);  //echo back to myself
          }
        }
        catch (err) {
          logger.error('c_stop_privatetyping', err, socket.metadata);
        }
      });
       socket.on('c_typing', function (data) {
        //    message received from client is json object:
        //      { fromuser: {
        //                    userid: 'afgdhfhlslfjxlldfl5670443',
        //                    username: 'zackc@esna.com'
        //                  },
        //        room: {
        //          roomname: 'room_123'
        //        },
        //        datetime: '2014-08-12T19:27:35.976Z'
        //      }
          try {
          data.datetime = new Date().toISOString();
          if (data.sender.id === socket.decoded_token.userid) {
            logger.info('c_typing, data: ', data, socket.metadata);
            //broadcast to everybody in the room the typing
            socket.in('topic_' + data.topic.id).broadcast.emit('s_typing', data);
          }
          else {
            logger.info('c_typing, fromuser: %s (%s) is not loggedin user, data:',
              data.sender.username, data.sender.id, data, metadata);
            socket.emit('s_typing_fail', data);  //echo back to myself
          }
        }
        catch (err) {
          logger.error('c_typing: ', err, socket.metadata);
        }
      });
       socket.on('c_stop_typing', function (data) {
        //    message received from client is json object:
        //      { fromuser: {
        //                    userid: 'afgdhfhlslfjxlldfl5670443',
        //                    username: 'zackc@esna.com'
        //                  },
        //        room: {
        //          roomname: 'room_123'
        //        },
        //        datetime: '2014-08-12T19:27:35.976Z'
        //      }
          try {
          data.datetime = new Date().toISOString();
          if (data.sender.id === socket.decoded_token.userid) {
            logger.info('c_stop_typing, data:', data, socket.metadata);
            //broadcast to everybody in the room the typing
            socket.in('topic_' + data.topic.id).broadcast.emit('s_stop_typing', data);
          }
          else {
            logger.info('c_stop_typing, fromuser: %s (%s) is not loggedin user, data:',
              data.sender.username, data.sender.id, data, metadata);
            socket.emit('s_stop_typing_fail', data);  //echo back to myself
          }
        }
        catch (err) {
          logger.error('c_stop_typing', err, socket.metadata);
        }
      });
      */
    });
  };

/***/ },
/* 150 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
  	value: true
  });
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  var _underscore = __webpack_require__(64);
  
  var _underscore2 = _interopRequireDefault(_underscore);
  
  var _async = __webpack_require__(9);
  
  var _async2 = _interopRequireDefault(_async);
  
  var _configEnvEnvironmentIndex = __webpack_require__(27);
  
  var _configEnvEnvironmentIndex2 = _interopRequireDefault(_configEnvEnvironmentIndex);
  
  var _apiFileFileBackend = __webpack_require__(54);
  
  var _apiFileFileBackend2 = _interopRequireDefault(_apiFileFileBackend);
  
  var _modulesFileGcsGcsService = __webpack_require__(84);
  
  var _modulesFileGcsGcsService2 = _interopRequireDefault(_modulesFileGcsGcsService);
  
  var _modulesLogger = __webpack_require__(1);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var _modulesUtilsIndex = __webpack_require__(40);
  
  var _modulesUtilsIndex2 = _interopRequireDefault(_modulesUtilsIndex);
  
  var _fluxConstantsSocketConstants = __webpack_require__(60);
  
  var _fluxConstantsSocketConstants2 = _interopRequireDefault(_fluxConstantsSocketConstants);
  
  var _fluxConstantsMessageConstants = __webpack_require__(17);
  
  var _fluxConstantsMessageConstants2 = _interopRequireDefault(_fluxConstantsMessageConstants);
  
  var _modulesMemcache = __webpack_require__(48);
  
  var _modulesMemcache2 = _interopRequireDefault(_modulesMemcache);
  
  var _Utils = __webpack_require__(86);
  
  var _Utils2 = _interopRequireDefault(_Utils);
  
  var ns = '[MediaSessionManager]';
  
  var SCREEN_SHARE_KEY_PREFIX = 'screen_share_files';
  
  var DEFAULT_UPLOAD_URL_DURATION = 60 * 60; //1 hour min
  var DEFAULT_DOWNLOAD_URL_DURATION = 60 * 60; //1min
  var MAX_NUMBER_OF_SCREEN_FILES = 10;
  function MediaSessionLockKey(sid) {
  	return 'MediaSessionLock:' + sid;
  }
  
  var MediaSessionManager = (function () {
  	function MediaSessionManager(options) {
  		_classCallCheck(this, MediaSessionManager);
  
  		this.confSessions = {}; //this shouldbe a mem-db;
  	}
  
  	_createClass(MediaSessionManager, [{
  		key: 'startUserMediaSession',
  		value: function startUserMediaSession(topicId, user) {
  			var userMediaSession = {
  				sessionId: _Utils2['default'].GUID(),
  				topicId: topicId,
  				joined: new Date()
  			};
  			return userMediaSession;
  		}
  	}, {
  		key: 'getTempFileKey',
  		value: function getTempFileKey(user) {
  			var prefix = arguments.length <= 1 || arguments[1] === undefined ? '' : arguments[1];
  
  			return prefix + _Utils2['default'].GUID();
  		}
  	}, {
  		key: 'getTempFileUploadUrl',
  		value: function getTempFileUploadUrl(user, fileObj, cb, expiration) {
  			return _modulesFileGcsGcsService2['default'].getUploadSignedUrl({}, { file: fileObj }, cb, expiration);
  		}
  	}, {
  		key: 'getTempFileDownloadUrl',
  		value: function getTempFileDownloadUrl(user, fileKey, cb, expiration) {
  			return _modulesFileGcsGcsService2['default'].getDownloadSignedUrl({}, { key: fileKey }, cb, expiration);
  		}
  	}, {
  		key: 'getNextAvailableFileIndex',
  		value: function getNextAvailableFileIndex(topicId, user, sessionData) {
  			var func = ns + '[getNextAvailableFileIndex]';
  			var nextIndex = sessionData.screenshare.activeFile + 1;
  			if (sessionData.screenshare.files.length < MAX_NUMBER_OF_SCREEN_FILES) {
  				nextIndex = sessionData.screenshare.files.length;
  				var newTempFile = {
  					uploadUrl: null,
  					downloadUrl: null,
  					fileIndex: nextIndex,
  					fileKey: 'screen_' + topicId + '/' + nextIndex, //.getTempFileKey(user, 'screen_' + topicId + '/'),
  					expires: null
  				};
  				sessionData.screenshare.files[nextIndex] = newTempFile;
  				_modulesLogger2['default'].debug(func, 'allocating a file in the pool nextIndex:', nextIndex);
  				return nextIndex;
  			}
  
  			if (nextIndex >= MAX_NUMBER_OF_SCREEN_FILES) {
  				nextIndex = 0;
  			}
  
  			_modulesLogger2['default'].debug(func, 'nextIndex', nextIndex);
  			return nextIndex;
  		}
  	}, {
  		key: 'generateScreenShareSignedUrls',
  		value: function generateScreenShareSignedUrls(topicId, user, contentType, cb) {
  			var func = ns + '[generateScreenShareSignedUrls]';
  			var expiration = _Utils2['default'].getSecondsFromNow(DEFAULT_UPLOAD_URL_DURATION);
  			contentType = contentType || '';
  			var dt = new Date();
  			console.log(func, expiration);
  			console.log(func, dt, dt.toISOString());
  			var result = {
  				files: [],
  				expires: expiration.toISOString()
  			};
  
  			var screenFiles = {};
  
  			var files = [];
  			var fileKeys = [];
  
  			_modulesLogger2['default'].info(func, 'begin:', topicId);
  			for (var i = 0; i < MAX_NUMBER_OF_SCREEN_FILES; i++) {
  				var nextIndex = i + 1;
  				var fileKey = 'screen_' + topicId + '/' + nextIndex;
  				screenFiles[fileKey] = { fileKey: fileKey };
  				fileKeys.push(fileKey);
  				files.push({
  					fileKey: fileKey,
  					'Content-Type': contentType
  				});
  			}
  
  			//logger.info(func, 'files:', files);
  
  			_apiFileFileBackend2['default'].getUploadSignedUrls({}, { files: files }, expiration, function (err, uploadResults) {
  				if (err) {
  					return cb(err, null);
  				}
  				_apiFileFileBackend2['default'].getDownloadSignedUrls({}, { fileKeys: fileKeys }, expiration, function (err, downloadResults) {
  					if (err) {
  						return cb(err, null);
  					}
  
  					for (var f in uploadResults) {
  						screenFiles[uploadResults[f].fileKey].uploadUrl = uploadResults[f].url;
  					}
  
  					for (var f in downloadResults) {
  						screenFiles[downloadResults[f].fileKey].downloadUrl = downloadResults[f].url;
  					}
  
  					for (var f in screenFiles) {
  						var file = {
  							fileKey: screenFiles[f].fileKey,
  							uploadUrl: screenFiles[f].uploadUrl,
  							downloadUrl: screenFiles[f].downloadUrl
  						};
  						result.files.push(file);
  					}
  
  					cb(null, result);
  				});
  			});
  		}
  	}, {
  		key: 'getScreenShareMemcacheKey',
  		value: function getScreenShareMemcacheKey(topicId) {
  			return SCREEN_SHARE_KEY_PREFIX + '_' + topicId;
  		}
  	}, {
  		key: 'processScreenShareAppRequests',
  		value: function processScreenShareAppRequests(topicId, user, data, sessionData, cb) {
  			var func = ns + '[processScreenShareAppRequests]';
  			var self = this;
  			sessionData.screenshare = sessionData.screenshare || { files: [], activeFile: 0 };
  			switch (data.category) {
  				case _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO.StartScreenShare:
  					var redKey = this.getScreenShareMemcacheKey(topicId);
  					//logger.info(func, 'about to clear redKey:', redKey);
  					//memcache.del({}, redKey, function(err, result){
  					//
  					//});
  					break;
  
  				case _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO.ScreenShareUploadUrl:
  					var redKey = this.getScreenShareMemcacheKey(topicId);
  					_modulesLogger2['default'].info(func, ' redKey:', redKey);
  					var contentType = null;
  					if (data && data.content) {
  						contentType = data.content['Content-Type'];
  					}
  					_modulesLogger2['default'].info(func, redKey, ' about to generate urls contentType:', contentType);
  					self.generateScreenShareSignedUrls(topicId, user, contentType, function (err, screenSignedData) {
  						if (err) {
  							return cb(err);
  						}
  						cb(null, screenSignedData);
  					});
  					return true;
  					break;
  			}
  			return false;
  		}
  	}, {
  		key: 'processScreenShareAppEvent',
  		value: function processScreenShareAppEvent(topicId, user, data, sessionData, cb) {
  			var func = ns + '[processScreenShareAppEvent]';
  			var self = this;
  			switch (data.category) {
  				case _fluxConstantsMessageConstants2['default'].ACTIVITY_CATEGORY_TYPES.APP_EVENTS.VIDEO.ScreenShareData:
  					if (data.content.image) {
  						cb(null, data);
  						return true;
  					}
  
  					var fileIndex = data.content.fileIndex;
  					_modulesLogger2['default'].debug(func, 'file exists fileIndex:', fileIndex, sessionData.screenshare.files[fileIndex]);
  					if (fileIndex && sessionData.screenshare.files[fileIndex]) {
  						data.content = data.content || {};
  						data.content.image = sessionData.screenshare.files[fileIndex].downloadUrl;
  						cb(null, data);
  					}
  					return true;
  			}
  			return false;
  		}
  	}]);
  
  	return MediaSessionManager;
  })();
  
  exports['default'] = MediaSessionManager;
  module.exports = exports['default'];

/***/ },
/* 151 */
/***/ function(module, exports, __webpack_require__) {

  /*! React Starter Kit | MIT License | http://www.reactstarterkit.com/ */
  
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
    value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _fs = __webpack_require__(43);
  
  var _fs2 = _interopRequireDefault(_fs);
  
  var exists = function exists(filename) {
    return new Promise(function (resolve) {
      _fs2['default'].exists(filename, resolve);
    });
  };
  
  var readFile = function readFile(filename) {
    return new Promise(function (resolve, reject) {
      _fs2['default'].readFile(filename, 'utf8', function (err, data) {
        if (err) {
          reject(err);
        } else {
          resolve(data);
        }
      });
    });
  };
  
  exports['default'] = { exists: exists, readFile: readFile };
  module.exports = exports['default'];

/***/ },
/* 152 */
/***/ function(module, exports) {

  module.exports = {
  	"version": "20160503195303"
  };

/***/ },
/* 153 */
/***/ function(module, exports) {

  /**
   * Copyright 2013-2015, Facebook, Inc.
   * All rights reserved.
   *
   * This source code is licensed under the BSD-style license found in the
   * LICENSE file in the root directory of this source tree. An additional grant
   * of patent rights can be found in the PATENTS file in the same directory.
   *
   * @providesModule invariant
   */
  
  'use strict';
  
  /**
   * Use invariant() to assert state which your program assumes to be true.
   *
   * Provide sprintf-style format (only %s is supported) and arguments
   * to provide information about what broke and what you were
   * expecting.
   *
   * The invariant message will be stripped in production, but the invariant
   * will remain to ensure logic does not differ in production.
   */
  
  function invariant(condition, format, a, b, c, d, e, f) {
    if (process.env.NODE_ENV !== 'production') {
      if (format === undefined) {
        throw new Error('invariant requires an error message argument');
      }
    }
  
    if (!condition) {
      var error;
      if (format === undefined) {
        error = new Error('Minified exception occurred; use the non-minified dev environment ' + 'for the full error message and additional helpful warnings.');
      } else {
        var args = [a, b, c, d, e, f];
        var argIndex = 0;
        error = new Error(format.replace(/%s/g, function () {
          return args[argIndex++];
        }));
        error.name = 'Invariant Violation';
      }
  
      error.framesToPop = 1; // we don't care about invariant's own frame
      throw error;
    }
  }
  
  module.exports = invariant;

/***/ },
/* 154 */
/***/ function(module, exports) {

  module.exports = function(module) {
  	if(!module.webpackPolyfill) {
  		module.deprecate = function() {};
  		module.paths = [];
  		// module.parent = undefined by default
  		module.children = [];
  		module.webpackPolyfill = 1;
  	}
  	return module;
  }


/***/ },
/* 155 */
/***/ function(module, exports, __webpack_require__) {

  var map = {
  	"./el": 65,
  	"./el.js": 65,
  	"./en": 53,
  	"./en.js": 53
  };
  function webpackContext(req) {
  	return __webpack_require__(webpackContextResolve(req));
  };
  function webpackContextResolve(req) {
  	return map[req] || (function() { throw new Error("Cannot find module '" + req + "'.") }());
  };
  webpackContext.keys = function webpackContextKeys() {
  	return Object.keys(map);
  };
  webpackContext.resolve = webpackContextResolve;
  module.exports = webpackContext;
  webpackContext.id = 155;


/***/ },
/* 156 */
/***/ function(module, exports, __webpack_require__) {

  var map = {
  	"./clientEnvironment.js": 139,
  	"./config-helper.js": 38,
  	"./development.js": 140,
  	"./index.js": 27,
  	"./logan-production.js": 141,
  	"./logan-staging.js": 142,
  	"./logan-testing.js": 143
  };
  function webpackContext(req) {
  	return __webpack_require__(webpackContextResolve(req));
  };
  function webpackContextResolve(req) {
  	return map[req] || (function() { throw new Error("Cannot find module '" + req + "'.") }());
  };
  webpackContext.keys = function webpackContextKeys() {
  	return Object.keys(map);
  };
  webpackContext.resolve = webpackContextResolve;
  module.exports = webpackContext;
  webpackContext.id = 156;


/***/ },
/* 157 */
/***/ function(module, exports) {

  module.exports = require("agenda");

/***/ },
/* 158 */
/***/ function(module, exports) {

  module.exports = require("api/message/message.socket.js");

/***/ },
/* 159 */
/***/ function(module, exports) {

  module.exports = require("api/user/user.socket.js");

/***/ },
/* 160 */
/***/ function(module, exports) {

  module.exports = require("babel-core/polyfill");

/***/ },
/* 161 */
/***/ function(module, exports) {

  module.exports = require("body-parser");

/***/ },
/* 162 */
/***/ function(module, exports) {

  module.exports = require("child_process");

/***/ },
/* 163 */
/***/ function(module, exports) {

  module.exports = require("cloudconvert");

/***/ },
/* 164 */
/***/ function(module, exports) {

  module.exports = require("cloudconvert/lib/process");

/***/ },
/* 165 */
/***/ function(module, exports) {

  module.exports = require("composable-middleware");

/***/ },
/* 166 */
/***/ function(module, exports) {

  module.exports = require("compression");

/***/ },
/* 167 */
/***/ function(module, exports) {

  module.exports = require("connect-mongo");

/***/ },
/* 168 */
/***/ function(module, exports) {

  module.exports = require("connect-timeout");

/***/ },
/* 169 */
/***/ function(module, exports) {

  module.exports = require("cookie-parser");

/***/ },
/* 170 */
/***/ function(module, exports) {

  module.exports = require("counterpart");

/***/ },
/* 171 */
/***/ function(module, exports) {

  module.exports = require("errorhandler");

/***/ },
/* 172 */
/***/ function(module, exports) {

  module.exports = require("events");

/***/ },
/* 173 */
/***/ function(module, exports) {

  module.exports = require("express-jwt");

/***/ },
/* 174 */
/***/ function(module, exports) {

  module.exports = require("express-session");

/***/ },
/* 175 */
/***/ function(module, exports) {

  module.exports = require("front-matter");

/***/ },
/* 176 */
/***/ function(module, exports) {

  module.exports = require("gcloud");

/***/ },
/* 177 */
/***/ function(module, exports) {

  module.exports = require("googleapis");

/***/ },
/* 178 */
/***/ function(module, exports) {

  module.exports = require("html-to-json");

/***/ },
/* 179 */
/***/ function(module, exports) {

  module.exports = require("http");

/***/ },
/* 180 */
/***/ function(module, exports) {

  module.exports = require("https");

/***/ },
/* 181 */
/***/ function(module, exports) {

  module.exports = require("jade");

/***/ },
/* 182 */
/***/ function(module, exports) {

  module.exports = require("jquery");

/***/ },
/* 183 */
/***/ function(module, exports) {

  module.exports = require("lru-cache");

/***/ },
/* 184 */
/***/ function(module, exports) {

  module.exports = require("method-override");

/***/ },
/* 185 */
/***/ function(module, exports) {

  module.exports = require("mongoose-integer");

/***/ },
/* 186 */
/***/ function(module, exports) {

  module.exports = require("newrelic");

/***/ },
/* 187 */
/***/ function(module, exports) {

  module.exports = require("passport-local");

/***/ },
/* 188 */
/***/ function(module, exports) {

  module.exports = require("react-dom/server");

/***/ },
/* 189 */
/***/ function(module, exports) {

  module.exports = require("react-translate-component");

/***/ },
/* 190 */
/***/ function(module, exports) {

  module.exports = require("sendgrid");

/***/ },
/* 191 */
/***/ function(module, exports) {

  module.exports = require("socket.io");

/***/ },
/* 192 */
/***/ function(module, exports) {

  module.exports = require("socket.io-redis");

/***/ },
/* 193 */
/***/ function(module, exports) {

  module.exports = require("trycatch");

/***/ },
/* 194 */
/***/ function(module, exports) {

  module.exports = require("url");

/***/ },
/* 195 */
/***/ function(module, exports) {

  module.exports = require("winston");

/***/ },
/* 196 */
/***/ function(module, exports) {

  module.exports = require("winston-loggly");

/***/ },
/* 197 */
/***/ function(module, exports) {

  module.exports = require("xtend");

/***/ }
/******/ ]);
//# sourceMappingURL=server.js.map