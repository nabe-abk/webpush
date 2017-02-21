self.addEventListener('push', function(evt) {
	if (!evt.data) return;
	var data = evt.data.json();

	evt.waitUntil(
		self.registration.showNotification(data.title, data )
		/*	icon: アイコンパス
			body: 通知メッセージ
			tag:  識別用タグ
			data: { <datahash> }		*/
	);
}, false);

self.addEventListener('notificationclick', function(evt) {
  evt.waitUntil(
  	clients.matchAll({ type: 'window' }).then(function(clist) {
  		// location.href = 'push.js' web path
  		var data = evt.notification.data || {};
		var url  = data.url || location.href.replace(/[^\/]*\/[^\/]*$/, '');

		for(var i=0; i<clist.length; i++) {
			var c = clist[i];
			if (c.url == url) return c.focus();
		}
		clients.openWindow(url);
	})
  );
}, false);

