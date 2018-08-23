//############################################################################
// web push test
//							(C)2017 nabe@abk
//############################################################################
//[TAB=8]  require jQuery
//
'use strict';
var serviceWorkerScript = 'js/push.js';

$(function(){
//////////////////////////////////////////////////////////////////////////////
//●初期化処理
//////////////////////////////////////////////////////////////////////////////
var myself = $('#js-myself').text();
var $log   = $('#log');
$('#push-regist').click(init_push);
$('#push-unregist').click(unregist_push);
$('#update-regist').click(update_registration);
$('#reset').click(function(){
	$log.text('');
});
$('#send-form').submit(send_push);

function log(key, str) {
	$log.text( $log.text() + key + (str != null ? ': ' + str : '') + "\n" );
	$log.scrollTop( $log.prop('scrollHeight') );
}
//////////////////////////////////////////////////////////////////////////////
navigator.serviceWorker.ready.then(function(reg){
	log('serviceWorker ready');
});
function init_push() {
	log('');
	if (!navigator.serviceWorker) return;

	Notification.requestPermission( function(permission) {
		log('requestPermission', permission);
		if (permission !== 'granted') return;

		if ('supportedContentEncodings' in PushManager) {
			log('supportedContentEncodings', PushManager.supportedContentEncodings.join(' '));
		}

		navigator.serviceWorker.register(serviceWorkerScript).then( function(registration) {
			regist_push(registration);
		}).catch(function(error) {
			log(error);
		});
	});
}

function regist_push(registration) {
	log('regist_push()');
	registration.pushManager.getSubscription().then(function(subscription){
		log('getSubscription()');

		if (!subscription) {
			var ary = $('#spub').text().match(/.{2}/g).map(function(x) {
				return parseInt(x, 16);
			});
			var spub = new Uint8Array(ary);

			registration.pushManager.subscribe({
				userVisibleOnly: true,
				applicationServerKey: spub
			}).then(setSubscription);
			return;
		}
		setSubscription(subscription);
	});
}

function unregist_push(evt) {
	log('');
	log('unregist_push()');
	navigator.serviceWorker.getRegistration(serviceWorkerScript).then(function(registration){
		if (!registration)
			return log('Do not registration!');
		registration.unregister().then(function(flag) {
			if (!flag) log('unregister() failed!');
		});
	});
}

function update_registration() {
	log('');
	log('update_registration()');
	navigator.serviceWorker.getRegistration(serviceWorkerScript).then(function(registration){
		if (!registration)
			return log('Do not registration!');
		registration.update();
	});
}

function setSubscription(subscription) {
	var key  = arybuf2bin( subscription.getKey('p256dh') );
	var auth = arybuf2bin( subscription.getKey('auth')   );

	log('');
	log(subscription.endpoint);
	log('client key', base64(key)  );
	log('serverKey ', base64( arybuf2str(subscription.options.applicationServerKey || []) ) );
	log('auth      ', base64(auth) );

	var form = new FormData();
	form.append('action', 'regist');
	form.append('endpoint', subscription.endpoint);
	form.append('key_hex',  b2hex(key)  );
	form.append('auth_hex', b2hex(auth) );

	fetch(myself, {
		credentials: 'include',		// cookie
		method: 'POST',
		body: form
	});
}

function resetSubscription(subscription) {
	log('subscription failed!');
}

function send_push(evt) {
	var form = new FormData(evt.target);

	fetch(myself, {
		credentials: 'include',		// cookie
		method: 'POST',
		body: form
	}).then(res => {
		if (res.status != 200) throw('HTTP Error : Status ' + res.status);
		return res.text();
	}).then(text => {
		text = text.replace(/\n+$/, '');
		log('');
		log(text);
	}).catch(err => {
		log('');
		log('error!');
		log(err);
	})
	return false;
}

function arybuf2str(arybuf) {
	return String.fromCharCode.apply(null, new Uint8Array(arybuf));
}
function arybuf2bin(arybuf) {
	return String.fromCharCode.apply(null, new Uint8Array(arybuf));
}
function b2hex(bin) {
	var hex='';
	bin = bin.toString();
	for(var i=0; i<bin.length; i++) {
		var h = '0' + bin.substr(i,1).charCodeAt().toString(16);
		hex += h.substr(-2);
	}
	return hex;
}

function base64(bin) {
	var str = btoa(bin).replace(/=+$/, '');
	return str.replace(/\+/g,'-').replace(/\//g,'_');
}

//////////////////////////////////////////////////////////////////////////////
});
