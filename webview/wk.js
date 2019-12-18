Interceptor.attach(ObjC.classes.WKUserContentController['- addScriptMessageHandler:name:'].implementation, {
	onEnter: function(args) {
		const handler = new ObjC.Object(args[2])
		const name = new ObjC.Object(args[3])
		console.log(name, '->', handler.$className)
	}
})

Interceptor.attach(ObjC.classes.WKWebView['- evaluateJavaScript:completionHandler:'].implementation, {
	onEnter: function(args) {
		const script = new ObjC.Object(args[2]).toString()
		const handler = new ObjC.Block(args[3])
		console.log('script:', script)
		console.log('callback:', handler.implementation)
	}
})