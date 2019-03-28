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

    var tags = '{jail="' + jail + '"}'

    var lineReader = readline.createInterface({
        input: require('fs').createReadStream(file)
    });

    lineReader.on('line', function (line) {
        if (line.includes("Total banned")){
            ret += 'fail2ban_banned_total' + tags + ' ' + line.replace(/.*Total banned:\s/, "").trim() + '\n';
        } else if (line.includes("Currently banned")){
            ret += 'fail2ban_banned_current' + tags + ' ' + line.replace(/.*Currently banned:\s/, "").trim() + '\n';
        } else if (line.includes("Total failed")){
            ret += 'fail2ban_failed_total' + tags + ' ' + line.replace(/.*Total failed:\s/, "").trim() + '\n';
        } else if (line.includes("Currently failed")){
            ret += 'fail2ban_failed_current' + tags + ' ' + line.replace(/.*Currently failed:\s/, "").trim() + '\n';
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
            ret += 'fail2ban_banned_location{country="' + k + '",jail="' + jail + '"} ' + map[k] + '\n';
        }
    }

    return ret;
}

function writeFile(path, text){
    writeFileTransactional(path, text, function(err) {
        if(err) {
            return console.log(err);
        }
    }); 
}

function writeFileTransactional (path, content, cb) {
    // The replacement file must be in the same directory as the
    // destination because rename() does not work across device
    // boundaries.

    // This simple choice of replacement filename means that this
    // function must never be called concurrently with itself for the
    // same path value. Also, properly guarding against other
    // processes tyring to use the same temporary path would make this
    // function more complicated. If that is a concern, a proper
    // temporary file strategy should be used. However, this
    // implementation ensures that any files left behind during an 
    //unclean termination will be cleaned up on a future run.
    let temporaryPath = `${path}.new`;
    fs.writeFile(temporaryPath, content, function (err) {
        if (err) {
            return cb(err);
        }

        fs.rename(temporaryPath, path, cb);
    });
};
