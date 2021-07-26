var ws = require("nodejs-websocket");
var fs = require('fs');
var join = require('path').join;
var wport = 1234;




console.log("Websocket on Port",wport)

var server = ws.createServer(function(conn){
    conn.on("text", function (str) {
        var jsObj = JSON.parse(str);
        console.log(jsObj);
    })
    conn.on("close", function (code, reason) {
        // console.log("close");
    });
    conn.on("error", function (code, reason) {
        // console.log("error");
    });
}).listen(wport)


function socketFrame(main,sub,pack){
    this.main = main;
    this.sub = sub;
    this.pack = pack;
}

