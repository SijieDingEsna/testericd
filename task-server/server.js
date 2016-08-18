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

  /**
   * http://usejsdoc.org/
   */
  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _cluster = __webpack_require__(28);
  
  var _cluster2 = _interopRequireDefault(_cluster);
  
  var cpuCount = __webpack_require__(3).cpus().length;
  var jobWorkers = [];
  var webWorkers = [];
  
  if (_cluster2['default'].isMaster) {
  
      // Create a worker for each CPU
      for (var i = 0; i < cpuCount; i += 1) {
          addJobWorker();
      }
  
      _cluster2['default'].on('exit', function (worker, code, signal) {
  
          if (jobWorkers.indexOf(worker.id) != -1) {
              console.log('job worker ' + worker.process.pid + ' died. Trying to respawn...');
              removeJobWorker(worker.id);
              addJobWorker();
          }
      });
  } else {
      if (process.env.job) {
          console.log('start job server: ' + _cluster2['default'].worker.id);
          __webpack_require__(21); //initialize the agenda here
      }
  }
  
  function addWebWorker() {
      webWorkers.push(_cluster2['default'].fork({ web: 1 }).id);
  }
  
  function addJobWorker() {
      jobWorkers.push(_cluster2['default'].fork({ job: 1 }).id);
  }
  
  function removeWebWorker(id) {
      webWorkers.splice(webWorkers.indexOf(id), 1);
  }
  
  function removeJobWorker(id) {
      jobWorkers.splice(jobWorkers.indexOf(id), 1);
  }

/***/ },
/* 1 */
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
/* 2 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  module.exports = __webpack_require__(6);

/***/ },
/* 3 */
/***/ function(module, exports) {

  module.exports = require("os");

/***/ },
/* 4 */
/***/ function(module, exports) {

  module.exports = require("path");

/***/ },
/* 5 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _modulesLogger = __webpack_require__(19);
  
  var _modulesLogger2 = _interopRequireDefault(_modulesLogger);
  
  var prefix = 'task-server';
  
  exports.info = function (args) {
    _modulesLogger2['default'].info(prefix, args);
  };
  
  exports.debug = function (args) {
    _modulesLogger2['default'].debug(prefix, args);
  };
  
  exports.warn = function (args) {
    _modulesLogger2['default'].warn(prefix, args);
  };
  
  exports.error = function (args) {
    _modulesLogger2['default'].error(prefix, args);
  };
  
  exports.sync = function (args) {
    _modulesLogger2['default'].sync(prefix, args);
  };
  
  exports.verbose = function (args) {
    _modulesLogger2['default'].verbose(prefix, args);
  };
  
  exports.silly = function (args) {
    _modulesLogger2['default'].silly('task-server', args);
  };

/***/ },
/* 6 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var path = __webpack_require__(4);
  var _ = __webpack_require__(30);
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
    version: __webpack_require__(22).version,
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
  module.exports = _.merge(all, __webpack_require__(23)("./" + process.env.NODE_ENV + '.js') || {});

/***/ },
/* 7 */
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
/* 8 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _request = __webpack_require__(13);
  
  var _request2 = _interopRequireDefault(_request);
  
  var _logger = __webpack_require__(5);
  
  var _logger2 = _interopRequireDefault(_logger);
  
  var _config = __webpack_require__(2);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _utilsServerConstants = __webpack_require__(10);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _errorsErrors = __webpack_require__(7);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _events = __webpack_require__(11);
  
  var _events2 = _interopRequireDefault(_events);
  
  var _os = __webpack_require__(3);
  
  var _os2 = _interopRequireDefault(_os);
  
  var _process = __webpack_require__(12);
  
  var _process2 = _interopRequireDefault(_process);
  
  var JobEvent = (function (_EventEmitter) {
    _inherits(JobEvent, _EventEmitter);
  
    function JobEvent() {
      _classCallCheck(this, JobEvent);
  
      _get(Object.getPrototypeOf(JobEvent.prototype), 'constructor', this).call(this);
    }
  
    _createClass(JobEvent, [{
      key: 'emit',
      value: function emit(evtName) {
        _get(Object.getPrototypeOf(JobEvent.prototype), 'emit', this).call(this, evtName);
      }
    }, {
      key: 'on',
      value: function on(evtName, cb) {
        _get(Object.getPrototypeOf(JobEvent.prototype), 'on', this).call(this, evtName, cb);
      }
    }]);
  
    return JobEvent;
  })(_events2['default']);
  
  function getCronUrlBase() {
    var hostname = _os2['default'].hostname();
    var hostnamePartialBaseUrlMaps = [{ hostNamePartial: 'logantesting-candidate', url: 'https://logantesting-candidate.esna.com' }, { hostNamePartial: 'logantesting-official', url: 'https://logantesting.esna.com' }, { hostNamePartial: 'logan-production', url: 'https://logan.onesna.com' }, { hostNamePartial: 'logan-candidate', url: 'https://logan-candidate.onesna.com' }];
  
    var _iteratorNormalCompletion = true;
    var _didIteratorError = false;
    var _iteratorError = undefined;
  
    try {
      for (var _iterator = hostnamePartialBaseUrlMaps[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
        var hostnamePartialBaseUrlItem = _step.value;
  
        if (hostname && hostname.indexOf(hostnamePartialBaseUrlItem.hostNamePartial) >= 0) {
          return hostnamePartialBaseUrlItem.url;
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
  
    _logger2['default'].warn('No hostname paritial is matched with this hostname ' + hostname);
    var svrPort = _config2['default'].port || 5000;
    if (svrPort == 5000) {
      return 'http://loganlocal.esna.com:5000';
    } else {
      _logger2['default'].warn('Can use cron job function for there is no valid baseurl');
      return null;
    }
  }
  
  var cronCfg = [
    //{cronId: 'test cron', url: '/api/taskqueue/testCron', interval: '10 seconds'},
  ];
  
  module.exports = function (agenda) {
    agenda.define('remove livRec', { priority: 'normal', concurrency: 1 }, function (job, done) {
      var livRecCon = agenda._mdb.collection('liveRec');
      var onhourbefore = new Date(Date.now() - 60 * 60 * 1000);
      _logger2['default'].info("Remove old live record begin");
      livRecCon.remove({ tm: { "$lt": onhourbefore } }, function (err, results) {
        if (err) {
          _logger2['default'].error("Remove old live record failed", err);
        } else {
          _logger2['default'].info("Remove old live record successfully");
        }
        done();
      });
    });
  
    var baseUrl = getCronUrlBase();
    if (!baseUrl) {
      return;
    }
  
    var _iteratorNormalCompletion2 = true;
    var _didIteratorError2 = false;
    var _iteratorError2 = undefined;
  
    try {
      var _loop = function () {
        var cronItem = _step2.value;
  
        var cronId = cronItem.cronId;
        var url = baseUrl + cronItem.url;
        agenda.define(cronId, function (job, done) {
          console.log('running cron task', cronId);
          var headers = {
            'Authorization': 'API_KEY ' + _config2['default'].ESNA_API_KEY
          };
          if (url && typeof url == 'string' && url.length > 0) {
            _logger2['default'].debug('cron job will send request to url ' + url);
            //Before send out request close this job
            done();
            (0, _request2['default'])({ method: 'POST',
              url: url,
              headers: headers,
              body: { interval: cronItem.interval },
              json: true
            }, function (err, response, body) {
              if (err && !err.code) {
                //Happen very critical error
                _logger2['default'].info('Finish cron job for happen very critical error' + err.message);
                job.attrs.status = 'dispatched';
                job.save();
              } else if (response && response.statusCode == _utilsServerConstants2['default'].HttpSuccessStatus) {
                _logger2['default'].info('Finish cron job successfully');
                job.attrs.status = 'dispatched';
                job.save();
              } else if (response && response.statusCode == _utilsServerConstants2['default'].HttpErrorTaskQueueNeverTry) {
                _logger2['default'].warn('Stop cron job for No corresponding function with function key ' + data.keyString);
                job.fail(body);
                job.attrs.status = 'dispatched';
                job.save();
              } else if (response && (response.statusCode == _utilsServerConstants2['default'].HttpUnauthorizedStatus || response.statusCode == _utilsServerConstants2['default'].HttpForbiddenStatus)) {
                _logger2['default'].warn('Stop cron job for Authentication or authorization happen error');
                job.fail(body);
                job.attrs.status = 'dispatched';
                job.save();
              } else if (response && response.statusCode == _utilsServerConstants2['default'].HttpNotFoundStatus) {
                _logger2['default'].warn('Stop cron job for Url not exsited error');
                job.fail(body);
                job.attrs.status = 'dispatched';
                job.save();
              } else {
                _logger2['default'].warn('Stop cron job for happen errors');
                job.fail(err || body);
                job.attrs.status = 'dispatched';
                job.save();
              }
            });
          } else {
            _logger2['default'].warn('cron job url is invalid', url);
            job.fail(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskqueueInvalidUrl));
            job.attrs.status = 'dispatched';
            job.save(done);
          }
        });
      };
  
      for (var _iterator2 = cronCfg[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
        _loop();
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
  
    agenda.cronCfg = cronCfg;
  };

/***/ },
/* 9 */
/***/ function(module, exports, __webpack_require__) {

  /**
   * http://usejsdoc.org/
   */
  'use strict';
  
  var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();
  
  var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }
  
  function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }
  
  var _request = __webpack_require__(13);
  
  var _request2 = _interopRequireDefault(_request);
  
  var _logger = __webpack_require__(5);
  
  var _logger2 = _interopRequireDefault(_logger);
  
  var _config = __webpack_require__(2);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _utilsServerConstants = __webpack_require__(10);
  
  var _utilsServerConstants2 = _interopRequireDefault(_utilsServerConstants);
  
  var _errorsErrors = __webpack_require__(7);
  
  var _errorsErrors2 = _interopRequireDefault(_errorsErrors);
  
  var _events = __webpack_require__(11);
  
  var _events2 = _interopRequireDefault(_events);
  
  var _os = __webpack_require__(3);
  
  var _os2 = _interopRequireDefault(_os);
  
  var _process = __webpack_require__(12);
  
  var _process2 = _interopRequireDefault(_process);
  
  var JobEvent = (function (_EventEmitter) {
    _inherits(JobEvent, _EventEmitter);
  
    function JobEvent() {
      _classCallCheck(this, JobEvent);
  
      _get(Object.getPrototypeOf(JobEvent.prototype), 'constructor', this).call(this);
    }
  
    _createClass(JobEvent, [{
      key: 'emit',
      value: function emit(evtName) {
        _get(Object.getPrototypeOf(JobEvent.prototype), 'emit', this).call(this, evtName);
      }
    }, {
      key: 'on',
      value: function on(evtName, cb) {
        _get(Object.getPrototypeOf(JobEvent.prototype), 'on', this).call(this, evtName, cb);
      }
    }]);
  
    return JobEvent;
  })(_events2['default']);
  
  function getCronUrlBase() {
    var hostname = _os2['default'].hostname();
    var hostnamePartialBaseUrlMaps = [{ hostNamePartial: 'logantesting-candidate', url: 'https://logantesting-candidate.esna.com' }, { hostNamePartial: 'logantesting-official', url: 'https://logantesting.esna.com' }, { hostNamePartial: 'logan-production', url: 'https://logan.onesna.com' }, { hostNamePartial: 'logan-candidate', url: 'https://logan-candidate.onesna.com' }];
  
    var _iteratorNormalCompletion = true;
    var _didIteratorError = false;
    var _iteratorError = undefined;
  
    try {
      for (var _iterator = hostnamePartialBaseUrlMaps[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
        var hostnamePartialBaseUrlItem = _step.value;
  
        if (hostname && hostname.indexOf(hostnamePartialBaseUrlItem.hostNamePartial) >= 0) {
          return hostnamePartialBaseUrlItem.url;
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
  
    _logger2['default'].warn('No hostname paritial is matched with this hostname ' + hostname);
    var svrPort = _config2['default'].port || 5000;
    if (svrPort == 5000) {
      return 'http://loganlocal.esna.com:5000';
    } else {
      _logger2['default'].warn('Can use cron job function for there is no valid baseurl');
      return null;
    }
  }
  
  module.exports = function (agenda) {
    agenda.define('defer task', { priority: 'normal', concurrency: 5 }, function (job, done) {
      console.log('running defer task');
      if (!job.esEvt) {
        job.esEvt = new JobEvent();
      }
      var data = job.attrs.data || null;
  
      if (!data) {
        _logger2['default'].warn('Stop job for no data');
        job.fail('Stop job for no data');
        job.attrs.status = 'dispatched';
        job.save(done);
        return job.esEvt.emit('finished');
      }
  
      var url = data.url;
      var headers = {
        'Authorization': 'API_KEY ' + _config2['default'].ESNA_API_KEY
      };
      if (url && typeof url == 'string' && url.length > 0) {
        _logger2['default'].info('Will send request to url ' + url);
        //Before send out request close this job
        done();
        (0, _request2['default'])({ method: 'POST',
          url: url,
          headers: headers,
          body: data,
          json: true
        }, //forever: true,
        //timeout: 300000
        function (err, response, body) {
          if (err && !err.code) {
            //Happen very critical error
            _logger2['default'].info('Finish job for happen very critical error' + err.message);
            job.attrs.status = 'dispatched';
            job.remove();
          } else if (response && response.statusCode == _utilsServerConstants2['default'].HttpSuccessStatus) {
            _logger2['default'].info('Finish job successfully');
            job.attrs.status = 'dispatched';
            job.remove();
          } else if (response && response.statusCode == _utilsServerConstants2['default'].HttpErrorTaskQueueNeverTry) {
            _logger2['default'].warn('Stop job for No corresponding function with function key ' + data.keyString);
            job.fail(body);
            job.attrs.status = 'dispatched';
            job.remove();
          } else if (response && (response.statusCode == _utilsServerConstants2['default'].HttpUnauthorizedStatus || response.statusCode == _utilsServerConstants2['default'].HttpForbiddenStatus)) {
            _logger2['default'].warn('Stop job for Authentication or authorization happen error');
            job.fail(body);
            job.attrs.status = 'dispatched';
            job.remove();
          } else if (response && response.statusCode == _utilsServerConstants2['default'].HttpNotFoundStatus) {
            _logger2['default'].warn('Stop job for Url not exsited error');
            job.fail(body);
            job.attrs.status = 'dispatched';
            job.remove();
          } else {
            var statusCode = undefined;
            if (response && response.statusCode) {
              statusCode = response.statusCode;
            }
            console.log('Happen error check retry.', err, statusCode, body);
            if (data.attempts) {
              data.attempt_times = data.attempt_times || 0;
              if (data.attempts > 0 && data.attempts > data.attempt_times) {
                var backoff_seconds = data.backoff_seconds || 0;
                var nextScheduleTime = new Date();
                nextScheduleTime.setSeconds(nextScheduleTime.getSeconds() + backoff_seconds * Math.pow(3, data.attempt_times));
                data.attempt_times += 1;
                job.schedule(nextScheduleTime);
                job.attrs.status = 'dispatching';
                job.save();
                _logger2['default'].info('Will try job at ' + nextScheduleTime.toString());
                return;
              } else if (data.attempts > 0 && data.attempts <= data.attempt_times) {
                job.attrs.status = 'dispatched';
                job.remove();
                _logger2['default'].info('The job stop retring for no more attempts');
              } else {
                //Endless attempt
                data.attempt_times += 1;
                var backoff_seconds = data.backoff_seconds || 0;
                backoff_seconds = backoff_seconds ? backoff_seconds || 2 : 2;
                var nextScheduleTime = new Date();
                nextScheduleTime.setSeconds(nextScheduleTime.getSeconds() + backoff_seconds * data.attempt_times);
                job.schedule(nextScheduleTime);
                job.attrs.status = 'dispatching';
                job.save();
                _logger2['default'].info('Will try job at ' + nextScheduleTime.toString());
                return;
              }
            } else {
              _logger2['default'].warn('Stop job for user require attempts 0');
              job.fail(err || body);
              job.attrs.status = 'dispatched';
              job.remove();
            }
          }
        });
      } else {
        _logger2['default'].warn('The url is invalid', url);
        job.fail(new _errorsErrors2['default'].ESErrors(_errorsErrors2['default'].TaskqueueInvalidUrl));
        job.attrs.status = 'dispatched';
        job.remove();
      }
      job.esEvt.emit('finished');
    });
  };

/***/ },
/* 10 */
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
/* 11 */
/***/ function(module, exports) {

  module.exports = require("events");

/***/ },
/* 12 */
/***/ function(module, exports) {

  module.exports = require("process");

/***/ },
/* 13 */
/***/ function(module, exports) {

  module.exports = require("request");

/***/ },
/* 14 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
  	value: true
  });
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _ZSLogger = __webpack_require__(25);
  
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
/* 15 */
/***/ function(module, exports, __webpack_require__) {

  // Development specific configuration
  // ==================================
  'use strict';
  
  var util = __webpack_require__(1);
  
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
      gcloudKey: __webpack_require__(4).normalize(__dirname + '/..') + '/private/gcskey_testing.json',
      projectId: 'onesnatesting',
      bucket: 'onesnatesting',
      tempExtneralBucket: 'onesnatesting_temp_external'
  };

/***/ },
/* 16 */
/***/ function(module, exports, __webpack_require__) {

  // Production specific configuration
  // =================================
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
      value: true
  });
  var util = __webpack_require__(1);
  var fs = __webpack_require__(29);
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
/* 17 */
/***/ function(module, exports, __webpack_require__) {

  // Stagging specific configuration
  // =================================
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
      value: true
  });
  var util = __webpack_require__(1);
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
      gcloudKey: process.env['GCLOUD_KEY_PATH'] || __webpack_require__(4).resolve('./private/gcskey_staging.json'),
      ESNA_API_KEY: process.env['ESNA_API_KEY'] || 'a7e2709c-b1ae-479a-a7ce-f3fab32a3a01',
      bucket: 'onesnastaging',
      tempExtneralBucket: 'onesnastaging_temp_external',
      logglyToken: 'eaa77580-ba2d-4d69-abbf-71d657662dbc',
      logglySubdomain: 'logantesting'
  };
  module.exports = exports['default'];

/***/ },
/* 18 */
/***/ function(module, exports, __webpack_require__) {

  // Test specific configuration
  // ===========================
  'use strict';
  
  Object.defineProperty(exports, '__esModule', {
      value: true
  });
  var util = __webpack_require__(1);
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
      gcloudKey: process.env['GCLOUD_KEY_PATH'] || __webpack_require__(4).resolve('./private/gcskey_testing.json'),
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
/* 19 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _config = __webpack_require__(2);
  
  var _config2 = _interopRequireDefault(_config);
  
  var pmx = __webpack_require__(32),
      winston = __webpack_require__(33);
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
  
  var os = __webpack_require__(3);
  
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
      __webpack_require__(34);
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
/* 20 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }
  
  var _agenda = __webpack_require__(26);
  
  var _agenda2 = _interopRequireDefault(_agenda);
  
  var _config = __webpack_require__(2);
  
  var _config2 = _interopRequireDefault(_config);
  
  var _logger = __webpack_require__(5);
  
  var _logger2 = _interopRequireDefault(_logger);
  
  var _nodeUuid = __webpack_require__(31);
  
  var _nodeUuid2 = _interopRequireDefault(_nodeUuid);
  
  var agendaname = _nodeUuid2['default'].v1();
  
  function allowHookAgenda() {
    var allowversions = ['0.8.0', '0.8.1'];
    var agendpjson = __webpack_require__(27);
    if (allowversions.indexOf(agendpjson.version) >= 0) {
      return true;
    }
    return false;
  }
  
  var mongoConnectionString = _config2['default'].mongo.uri;
  _logger2['default'].info('Mongo connection string ' + mongoConnectionString);
  var agenda = new _agenda2['default']({ db: { address: mongoConnectionString, collection: "jobCollectionName", options: { server: { auto_reconnect: true } } },
    name: agendaname });
  
  function hookfindAndModify(agenda) {
    var orifun = agenda._collection.findAndModify;
  
    function callbackhook(fromNewFun, callback) {
      function innerCallback(err, result) {
        //      if (fromNewFun){
        //        if (!err && result){
        //          if (result.value && result.value.lockedAt){
        //            var now = new Date();
        //            if (result.value.lockedAt.getTime() < now.getTime() - 1000){
        //              result.value.lockedAt = null;
        //              agenda._collection.save(result);
        //            }
        //          }
        //        }
        //      }
        callback(err, result);
      }
      return innerCallback;
    }
  
    agenda._collection.findAndModify = function (query, sort, doc, options, callback) {
      var callNewfun = false;
      if (callback.name == 'processDbResult') {
        callNewfun = true;
      }
  
      if (!callNewfun) {
        return orifun.call(agenda._collection, query, sort, doc, options, callbackhook(callNewfun, callback));
      } else {
        doc.$set.agdid = agendaname;
        if (!doc.$set.status && doc.$set.type == 'normal') {
          doc.$set.status = 'dispatching';
        }
        return orifun.call(agenda._collection, query, sort, doc, options, callbackhook(callNewfun, callback));
      }
    };
  }
  
  var checkLiveSys = function checkLiveSys(agendaObj) {
    var now = new Date();
    agendaObj.livRecCon = agendaObj._mdb.collection('liveRec');
    agendaObj.livRecCon.insertOne({ puuid: agendaname, tm: now });
    function checkLiveHandle() {
      var now = new Date();
      agendaObj.livRecCon.insertOne({ puuid: agendaname, tm: now });
      var gttm = new Date(now.valueOf() - agendaObj._processEvery * 2);
      agendaObj.livRecCon.find({ tm: { $gt: gttm } }).toArray(function (err, livResults) {
        var puuids = [];
        if (!err && livResults) {
          for (var liveResultIdx in livResults) {
            var livResult = livResults[liveResultIdx];
            puuids.push(livResult.puuid);
          }
        }
  
        agenda._collection.find({ status: 'dispatching' }).toArray(function (err, results) {
          if (!err && results) {
            for (var jobIdx in results) {
              var jobData = results[jobIdx];
              if (jobData.agdid && puuids.indexOf(jobData.agdid) == -1 && jobData.type === 'normal' && (!jobData.nextRunAt || jobData.nextRunAt < new Date())) {
                //The job dispaching but not update it's status
                jobData.lockedAt = null;
                jobData.lastRunAt = null;
                jobData.nextRunAt = new Date();
                agendaObj._collection.save(jobData);
              }
            }
          }
        });
      });
    }
  
    setInterval(checkLiveHandle, agendaObj._processEvery);
  };
  
  var jobTypes = process.env.JOB_TYPES ? process.env.JOB_TYPES.split(',') : ['defer', 'cron'];
  
  jobTypes.forEach(function (type) {
    _logger2['default'].info('loading job type' + type);
    __webpack_require__(24)("./" + type)(agenda);
  });
  
  if (jobTypes.length) {
    agenda.on('ready', function () {
      if (allowHookAgenda()) {
        checkLiveSys(agenda);
        hookfindAndModify(agenda);
        _logger2['default'].info("The agenda system is hooked by logan agenda  !");
      } else {
        _logger2['default'].warn("The agenda system is not hooked by logan agenda for it is not allowed version!");
      }
      agenda.every('1 hours', 'remove livRec');
      //    agenda.every('10 seconds', 'repeat task');
      //    agenda.every('13 seconds', 'repeat task');
      agenda._collection.update({ lockedAt: { $exists: true } }, { $set: { lockedAt: null } }, function (err, results) {
        if (agenda.cronCfg) {
          var _iteratorNormalCompletion = true;
          var _didIteratorError = false;
          var _iteratorError = undefined;
  
          try {
            for (var _iterator = agenda.cronCfg[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
              var cronItem = _step.value;
  
              var cronId = cronItem.cronId;
              var interval = cronItem.interval;
              agenda.every(interval, cronId);
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
        agenda.start();
      });
    });
  }
  
  module.exports = agenda;

/***/ },
/* 21 */
/***/ function(module, exports, __webpack_require__) {

  'use strict';
  
  __webpack_require__(20);

/***/ },
/* 22 */
/***/ function(module, exports) {

  module.exports = {
  	"version": "20160503195303"
  };

/***/ },
/* 23 */
/***/ function(module, exports, __webpack_require__) {

  var map = {
  	"./clientEnvironment.js": 14,
  	"./config-helper.js": 1,
  	"./development.js": 15,
  	"./index.js": 6,
  	"./logan-production.js": 16,
  	"./logan-staging.js": 17,
  	"./logan-testing.js": 18
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
  webpackContext.id = 23;


/***/ },
/* 24 */
/***/ function(module, exports, __webpack_require__) {

  var map = {
  	"./cron": 8,
  	"./cron.js": 8,
  	"./defer": 9,
  	"./defer.js": 9
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
  webpackContext.id = 24;


/***/ },
/* 25 */
/***/ function(module, exports) {

  module.exports = require("ZSLogger");

/***/ },
/* 26 */
/***/ function(module, exports) {

  module.exports = require("agenda");

/***/ },
/* 27 */
/***/ function(module, exports) {

  module.exports = require("agenda/package.json");

/***/ },
/* 28 */
/***/ function(module, exports) {

  module.exports = require("cluster");

/***/ },
/* 29 */
/***/ function(module, exports) {

  module.exports = require("fs");

/***/ },
/* 30 */
/***/ function(module, exports) {

  module.exports = require("lodash");

/***/ },
/* 31 */
/***/ function(module, exports) {

  module.exports = require("node-uuid");

/***/ },
/* 32 */
/***/ function(module, exports) {

  module.exports = require("pmx");

/***/ },
/* 33 */
/***/ function(module, exports) {

  module.exports = require("winston");

/***/ },
/* 34 */
/***/ function(module, exports) {

  module.exports = require("winston-loggly");

/***/ }
/******/ ]);
//# sourceMappingURL=server.js.map