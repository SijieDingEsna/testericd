
(function( $, undefined ) {
	var ns = '[viewer.js]';
	var queryParams = getQueryParams();
	const API_FILE_VIEWER_URLS = '/api/files/viewUrls/:token';
	const DELAY_TIME_TO_FETCH_MORE = 1000;
	const ZOOM_LEVEL_TICK = 10;
	const MAX_ZOOM_LEVEL = 1000;
	const SCROLL_DELAY = 500;
	const CONTROL_BAR_OFFSET = 45; //in pixel
	const PAGE_VIEW_TEMPLATE = 
		'<div class="zang-page zang-page-visible">' + 
			'<div class="zang-page-inner">' +
				'<div class="zang-page-content">' +
					'<div class="zang-page-svg"></div>' +
					'<div class="zang-page-autoscale"><div class="zang-subpx-fix"></div><div class="zang-page-links"></div></div>' +
				'</div>' + 
			'</div>' +
		'</div>';

	const TEST_FETCH_DATA = {
		data: [
			{
				page: 'page1',
				url: 'test/file2/page1.svg'
			},
			{
				page: 'page1',
				url: 'test/file2/page2.svg'
			},
			{
				page: 'page1',
				url: 'test/file2/page2.svg'
			},
			{
				page: 'page1',
				url: 'test/file2/page2.svg'
			},
			{
				page: 'page1',
				url: 'test/file2/page2.svg'
			}
		],
		totalPages: 5,
		nextPageUrl: ''
	}
	



	var config = {};
	var viewState = {
		totalPages: 0,
		pageNoFetched: 0,
		currentPage: 1,
		zoomLevel: 100, //in percentage
	}
	config.token = queryParams.token;
	config.theme = queryParams.theme || 'dark';
	config.controls = queryParams.controls || 1;
	config.hostUrl = queryParams.hostUrl || getApiHostUrl();
	console.info(ns, 'queryParams:', queryParams);
	console.info(ns, 'config', config);

	function getQueryParams() {
		// Parse query string to extract some parameters (it can fail for some input)
		var query = (document.location.search || document.location.hash || '').replace('#', '').replace('?', '');;
		var queryParams = query ? JSON.parse('{' + query.split('&').map(function (a) {
				return a.split('=').map(decodeURIComponent).map(JSON.stringify).join(': ');
			}).join(',') + '}') : {};
		return queryParams;
	}

	function getApiHostUrl(){
		var func = ns + '[getApiHostUrl]';
		return window.location.origin;
	}

	function setTotalNumberOfPages(totalPages){
		var func = ns + '[setTotalNumberOfPages]';
		console.info(func, 'totalPages', totalPages);
		if(!totalPages){
			totalPages = 0;
		}
		viewState.totalPages = totalPages;
		$('.page-display').html(viewState.currentPage + ' / ' + viewState.totalPages);

		$('.page-display').prop('disabled', false);
		if(viewState.totalPages <= 0){
			$('.page-display').prop('disabled', true);
		}
		updatePaginationControls();
	}

	function updatePaginationControls(){
		$('.scroll-previous-btn').prop('disabled', true);
		$('.scroll-next-btn').prop('disabled', true);
		if(viewState.totalPages > 0 &&  viewState.currentPage < viewState.totalPages){
			$('.scroll-next-btn').prop('disabled', false);
		}

		if(viewState.currentPage>1){
			$('.scroll-previous-btn').prop('disabled', false);
		}
	}

	function processFetchedData(resp){
		var func = ns + '[processFetchedData]';
		//need to init total number of pages
		setTotalNumberOfPages(resp.totalPages);
		if(resp.data){
			var pages = resp.data;
			var zangDoc = $('.zang-doc');
			for(var pageIndex in pages){
				var page = pages[pageIndex];
				viewState.pageNoFetched++;
				var pageNo = viewState.pageNoFetched;
				console.info(func, 'processing: ', page, 'pageNo:', pageNo);
				var pageView = $(PAGE_VIEW_TEMPLATE);
				var imgStr = '<img class="zang-page-svg-img zang-page-svg-img-' + page.page + '" src="' + page.url + '" />'
					+ '<div class="zang-page-svg-loader zang-page-svg-loader-' + page.page + '" ><img data-page="' + page.page + '" class="loader-img"   src="img/loading-spinner-red.svg" /></div>';
				//var imgStr =  '<object type="image/svg+xml" onload="return false;" data="' + page.url + '" ></object>';
				pageView.addClass('page-' + page.page);
				pageView.find('.zang-page-content').html(imgStr);
				zangDoc.append(pageView);
			}

			$('.loader-img').load(function(e) {
				var func = ns + '[loader-img].onload:';
				var data = $(this).data();
				//console.log(func, 'page:', data.page);
				setTimeout(function(){
					$('.zang-page-svg-loader-' + data.page).hide();
					$('.zang-page-svg-img-' + data.page).show();
				}, 500);
			});
			
			$('.zoom-out-btn').trigger('click');
				
		}
	}

	function fetchFileAllViewUrls(options){
		var func = ns + '[fetchFileAllViewUrls]';
		options = $.extend(true, {}, options);
		fetchFileViewUrls(options, function(err, response){
			console.info(func, err, response);		
			
			if(err){
				//return
			}
			else{
				console.info(func, 'about to render data received');
				processFetchedData(response);
				if(response.nextUrl){
					setTimeout(function(){
						console.info(func, 'about to fetch more data');
						fetchFileAllViewUrls({url: response.nextUrl});
					}, DELAY_TIME_TO_FETCH_MORE);
				}
			}
		});
	}

	function fetchFileViewUrls(options, callback){
		var func = ns + '[fetchFileViewUrls]';
		options = $.extend(true, {url: API_FILE_VIEWER_URLS.replace(':token', config.token)}, options);
		console.info(func, options);
		//
		//if(callback){
		//	callback(null, TEST_FETCH_DATA);
		//}
		//return;
		$.ajax({
			url: options.url,
			type: 'GET',
			dataType: 'json',
			success: function(data) {
				console.info(func, 'data:', data);
				if(callback){
					callback(null, data);
				}
			},
			error: function( jqXHR, textStatus, errorThrown ) {
				console.error(func, jqXHR, textStatus, errorThrown)
				if(callback){
					callback(errorThrown, null);
				}
			}
		});
	}



	function bindButtons(){
		$('.scroll-previous-btn').click(function(e){
			var func = ns + 'scroll-previous-btn.onClick';
			console.info(func, 'begin');
			if(viewState.currentPage <=1){
				console.info(func, 'first page is reached');
				viewState.currentPage = 1;
				return;
			}

			viewState.currentPage--;
			$('html, body').animate({
				scrollTop: ($('.page-' + viewState.currentPage).offset().top - CONTROL_BAR_OFFSET)
			}, SCROLL_DELAY);
			setTotalNumberOfPages(viewState.totalPages);
		});


		$('.scroll-next-btn').click(function(e){
			var func = ns + '[scroll-next-btn.onClick]';
			console.info(func, 'begin');
			if(viewState.currentPage >= viewState.totalPages){
				console.info(func, 'last page is reached');
				viewState.currentPage = viewState.totalPages;
				return;
			}

			viewState.currentPage++;
			$('html, body').animate({
				scrollTop: ($('.page-' + viewState.currentPage).offset().top - CONTROL_BAR_OFFSET)
			}, SCROLL_DELAY);
			setTotalNumberOfPages(viewState.totalPages);
		});

		$('.zoom-in-btn').click(function(e){
			var func = ns + '[zoom-in-btn.onClick]';
			console.info(func, 'begin');
			viewState.zoomLevel += ZOOM_LEVEL_TICK;
			if(viewState.zoomLevel>=MAX_ZOOM_LEVEL){
				viewState.zoomLevel = MAX_ZOOM_LEVEL;
			}
			$('.zang-page').css({
				width: viewState.zoomLevel + '%'
			});
		});

		$('.zoom-out-btn').click(function(e){
			var func = ns + '[zoom-out-btn.onClick]';
			console.info(func, 'begin');
			viewState.zoomLevel -= ZOOM_LEVEL_TICK;
			if(viewState.zoomLevel<=0){
				viewState.zoomLevel = ZOOM_LEVEL_TICK;
			}

			$('.zang-page').css({
				width: viewState.zoomLevel + '%'
			});
		});

		$('.page-display').click(function(e){
			var func = ns + '[page-display.onClick]';
			console.info(func, 'begin');
		});

		$('.fullscreen-btn').click(function(e){
			var func = ns + '[page-display.onClick]';

			if(!$('body').hasClass('zang-viewer-fullscreen')){
				$('body').addClass('zang-viewer-fullscreen');
				var elem = document.body;
				if (elem.requestFullscreen) {
					elem.requestFullscreen();
				} else if (elem.msRequestFullscreen) {
					elem.msRequestFullscreen();
				} else if (elem.mozRequestFullScreen) {
					elem.mozRequestFullScreen();
				} else if (elem.webkitRequestFullscreen) {
					elem.webkitRequestFullscreen();
				}
			}
			else{
				$('body').removeClass('zang-viewer-fullscreen');
				//var elem = document.body;
				//if (elem.exitFullscreen) {
				//	elem.exitFullscreen();
				//} else if (document.msExitFullscreen) {
				//	elem.msExitFullscreen();
				//} else if (document.mozCancelFullScreen) {
				//	elem.mozCancelFullScreen();
				//} else if (document.webkitExitFullscreen) {
				//	elem.webkitExitFullscreen();
				//}
			}



		});

	}

	function moveScrollOnDrag(){
		var func = ns + '[moveScrollOnDrag]';
		var clicked = false, clickY, clickX;
		$(document).on({
			'mousemove': function(evt) {
				clicked && updateScrollPos(evt);
			},
			'mousedown': function(evt) {
				//console.info(func + '[mousedown]', evt);
				evt.preventDefault();
				clicked = true;
				clickY = evt.pageY;
				clickX = evt.pageX;
			},
			'mouseup': function(evt) {
				//console.info(func + '[mouseup]', evt);
				clicked = false;
				$('html').css('cursor', 'auto');
			}
		});

		var updateScrollPos = function(evt) {
			console.info(func + '[updateScrollPos]', evt);
			evt.preventDefault();
			$('html').css('cursor', 'hand');
			$(window).scrollTop($(window).scrollTop() + (clickY - evt.pageY));
			$(window).scrollLeft($(window).scrollLeft() + (clickX - evt.pageX));
		}
	}

	function watchPageScroll(){
		var _watch = [];

		function monitor( element, options ) {
			var item = { element: element, options: options, invp: false };
			_watch.push(item);
			return item;
		}

		var $window = $(window),
			_buffer = null;

		function test($el) {
			var docViewTop = $window.scrollTop(),
				docViewBottom = docViewTop + $window.height(),
				elemTop = $el.offset().top,
				elemBottom = elemTop + $el.height();

			return ((elemBottom >= docViewTop) && (elemTop <= docViewBottom)
			&& (elemBottom <= docViewBottom) &&  (elemTop >= docViewTop) );
		}

		function isScrolledIntoView(elem)
		{
			var $elem = $(elem);
			var $window = $(window);

			var docViewTop = $window.scrollTop();
			var docViewBottom = docViewTop + $window.height();

			var elemTop = $elem.offset().top;
			var elemBottom = elemTop + $elem.height();

			return ((elemTop <= docViewBottom) && (elemTop >= docViewTop));//(elemBottom <= docViewBottom) &&
		}

		function checkInView( e ) {
			var func = ns + '[checkInView]';
			var bPageFound = false;
			//if scroll direction is down check pages visiblity from bottom
			//if scroll is up check items from top.
			function checkActive(index, page) {
				var elm = $(page);
				if(currentScrollDirection == 'top'){
					viewState.currentPage = 1;
					console.info(func, 'reached top', currentScrollDirection);
					setTotalNumberOfPages(viewState.totalPages);
				}
				else if(currentScrollDirection == 'bottom'){
					viewState.currentPage = viewState.totalPages;
					console.info(func, 'reached top', currentScrollDirection);
					setTotalNumberOfPages(viewState.totalPages);
				}
				else if(isScrolledIntoView(page) && !bPageFound){
					viewState.currentPage = index;
					console.info(func, 'direction:', currentScrollDirection, 'visible page:', index);
					setTotalNumberOfPages(viewState.totalPages);
					bPageFound = true;
				}
				//if ( test( page ) ) {
				//	viewState.currentPage = index + 1;
				//	setTotalNumberOfPages(viewState.totalPages);
				//	//if ( !page.invp ) {
				//	//	page.invp = true;
				//	//	if ( page.options.scrolledin ) page.options.scrolledin.call( page.element, e );
				//	//	page.element.trigger( 'scrolledin', e );
				//	//}
				//} else if ( page.invp ) {
				//	//page.invp = false;
				//	//if ( page.options.scrolledout ) page.options.scrolledout.call( page.element, e );
				//	//page.element.trigger( 'scrolledout', e );
				//}
			}

			$('.zang-page').each(function(index, page){
				checkActive(index + 1, page);
			});

			return;

			if(currentScrollDirection == 'down'){

			}
			else {
				$('.zang-page').reverse().each(function(index, page){
					checkActive(viewState.totalPages - index, page);
				});
			}
		}

		var lastScrollTop = 0;
		var currentScrollDirection = '';
		function setScrollDirection(){
			currentScrollDirection = 'up';
			var pos = $(this).scrollTop();

			if (pos == 0) {
				currentScrollDirection = 'top';
			}
			else if($(this).scrollTop() + $(this).innerHeight() >= $(this)[0].scrollHeight) {
				currentScrollDirection = 'bottom';
			}
			else if (pos > lastScrollTop){
				// downscroll code
				currentScrollDirection = 'down';
			}


			lastScrollTop = pos;
		}
		$window.on('scroll', function ( e ) {

			if ( !_buffer ) {
				_buffer = setTimeout(function () {
					setScrollDirection();
					checkInView( e );

					_buffer = null;

				}, 300);
			}

		});
	}
	
	function initControls(){
		if(config.controls === "0"){
			$('.controls-container').css('display', 'none');
		}
	}

	$(document).ready(function(){
		var func = ns + '[document.ready]';
		initControls();
		setTotalNumberOfPages(0);
		fetchFileAllViewUrls();
		bindButtons();
		moveScrollOnDrag();
		watchPageScroll();
	});

	$.fn.reverse = function() {
		return this.pushStack(this.get().reverse(), arguments);
	};

}( jQuery ));