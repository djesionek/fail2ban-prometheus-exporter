const args = require('minimist')(process.argv.slice(2));
const geoip = require('geoip-lite');
const fs = require('fs');
const readline = require('readline');
var exec = require('child_process').exec;

var file = args.f;
const out = args.o;
const jail = args.j;

if (!out){
    console.log("Specify output -o")
    return;
}

if (file === undefined){
    exec('fail2ban-client status ' + jail, function callback(error, stdout, stderr){
        if (error){
            console.log("could not execute fail2ban-client. Install it or provide a file with -f")
            process.exit(1);
        }
        writeFile(".tmp", stdout)
        file = ".tmp"

        startRead();
    });
} else {
    startRead();
}

var ret = "";

function startRead(){
    var lineReader = readline.createInterface({
        input: require('fs').createReadStream(file)
    });

    lineReader.on('line', function (line) {
        if (line.includes("Total banned")){
            ret += 'fail2ban_banned_total ' + line.replace(/.*Total banned:\s/, "").trim() + '\n';
        } else if (line.includes("Currently banned")){
            ret += 'fail2ban_banned_current ' + line.replace(/.*Currently banned:\s/, "").trim() + '\n';
        } else if (line.includes("Total failed")){
            ret += 'fail2ban_failed_total ' + line.replace(/.*Total failed:\s/, "").trim() + '\n';
        } else if (line.includes("Currently failed")){
            ret += 'fail2ban_failed_current ' + line.replace(/.*Currently failed:\s/, "").trim() + '\n';
        } else if (line.includes("Banned IP list")){
            ret += handleIPList(line.replace(/.*Banned IP list:\s/, "").split(" ")) + '\n';
        }   
    });
    
    lineReader.on('close', function (line) {
        writeFile(out, ret);
    });
}

function handleIPList(list){

    var map = {};
    var ret = "";

    list.forEach(ip => {
        var cc = geoip.lookup(ip).country;

        if (!map[cc]){
            map[cc] = 1;
        } else {
            map[cc]++;
        }
    });

    for (var k in map){
        if (map.hasOwnProperty(k)) {
            ret += 'fail2ban_banned_location{country="' + k + '"} ' + map[k] + '\n';
        }
    }

    return ret;
}

function writeFile(path, text){
    fs.writeFile(path, text, function(err) {
        if(err) {
            return console.log(err);
        }
    }); 
}