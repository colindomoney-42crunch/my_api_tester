'use strict';

var Address4 = require('ip-address').Address4;

console.log('>>> Starting test now');

var res = ping_ip_address('192.168.16.1; ls -al')
console.log('>>> res: ' + res);

var res = ping_ip_address('192.168.16.1')
console.log('>>> res: ' + res);

function ping_ip_address(ipAddress) {
    console.log('Running ing_ip_address()');

    try {
        var myIp = new Address4(ipAddress)
        return myIp.address
    }
    catch (err) {
        console.log('>>> Failed to convert IP address: ' + err);
        return null
    }
}