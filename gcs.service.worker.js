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
  
  var gcloud = __webpack_require__(1);
  var process = __webpack_require__(3);
  var LRU = __webpack_require__(2);
  
  //console.log("=================>>>", process.argv)
  var gcloudConfig = JSON.parse(process.argv[2]);
  
  var gcs = gcloud.storage(gcloudConfig.credential);
  var bucket = gcs.bucket(gcloudConfig.bucket);
  var optionsLRU = {
    max: 10000
  };
  var signedURLCache = LRU(optionsLRU);
  
  function cacheSignedUrl(key, url, expires) {
    setTimeout(function () {
      var diffms = expires - Date.now();
      signedURLCache.set(key, url, diffms - 10000);
    }, 10);
  }
  
  process.on('message', function (fileData) {
    var cachedUrl = signedURLCache.get(fileData.key);
    if (cachedUrl) {
      fileData.url = cachedUrl;
      return process.send(fileData);
    }
  
    var file = bucket.file('logan/' + fileData.key);
    file.getSignedUrl({
      action: 'read',
      expires: fileData.expiration
    }, function (err, url) {
      if (err) {
        fileData.url = '';
        return process.send(fileData);
      }
      if (fileData.responseDisposition) {
        url += '&response-content-disposition=' + encodeURIComponent('attachment; filename="' + fileData.responseDisposition + '"');
      }
      fileData.url = url;
      cacheSignedUrl(fileData.key, url, fileData.expiration);
      return process.send(fileData);
    });
  });

/***/ },
/* 1 */
/***/ function(module, exports) {

  module.exports = require("gcloud");

/***/ },
/* 2 */
/***/ function(module, exports) {

  module.exports = require("lru-cache");

/***/ },
/* 3 */
/***/ function(module, exports) {

  module.exports = require("process");

/***/ }
/******/ ]);
//# sourceMappingURL=gcs.service.worker.js.map