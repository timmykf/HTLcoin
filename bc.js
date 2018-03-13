
'use strict';
var CryptoJS = require("crypto-js");
var express = require("express");
var bodyParser = require('body-parser');
var WebSocket = require("ws");
var cors = require("cors");
var jsonfl = require('jsonfile');
var cron = require('node-cron');
var fs = require('fs');
var ip = require('ip');
var session = require('express-session');
var nodeRSA = require('node-rsa');
var cpu = require('os');
var NodeRSA = require('node-rsa');
var os = require('os');
var crypto = require('crypto');
var aescryp = require('node-cryptojs-aes')
var http = require('http')

http.globalAgent.maxSockets = 20;


var bcfile = './tmp/coinsafe.json';
var debugfl = './tmp/hcoinsave.txt';
var peersfl = './tmp/standpeers.json';

let countdbginfo;
var task = cron.schedule('*/3 * * * *',function(){
    console.log("tmpsave"+":"+countdbginfo+'   '+new Date().getTime() / 1000);
});

task.start();

var http_port = process.env.HTTP_PORT || 3001;
var p2p_port = process.env.P2P_PORT || 6001;
var initialPeers = process.env.PEERS ? process.env.PEERS.split(',') : [];

class Block {
    constructor(index, previousHash, timestamp, data , hash) {
        this.index = index;
        this.previousHash = previousHash.toString();
        this.timestamp = timestamp;
        this.data = data;
        this.hash = hash.toString();
    }
}

var sockets = [];
var MessageType = {
    QUERY_LATEST: 0,
    QUERY_ALL: 1,
    RESPONSE_BLOCKCHAIN: 2,
    RESPONSE_USERDATA: 3,
    RESPONSE_TRANSACTION: 4
};

var UserID = 0;

var urlencodedParser = bodyParser.urlencoded({extended:false});

var getGenesisBlock = () => {
    return new Block(0, "0", 0, "thestartofeverythingis7", "816534932c2b7154836da6afc367695e6337db8a921823784c14378abed4f7d7");
};

var transactions = [];

var usersalthash = [];

var blockchain = [getGenesisBlock()];

var initHttpServer = () => {
    var app = express();
    app.engine('html', require('ejs').renderFile);
    app.engine('htm', require('ejs').renderFile);
    app.use(express.static('public'));
    app.use(bodyParser.json());
    app.use(cors());
    app.get('/blocks', function(req, res) { 
        res.send(JSON.stringify(blockchain));
    });
    app.get('/',(req,res)=>{
        console.log('Requested Site:'+ JSON.stringify(req.headers))
        res.render('homepage.html');
    })
    app.post('/CreateUser',urlencodedParser , (req,res)=>{
        var pass = req.body.passwort;
        //create key value pair
        nodeRSAKey((err,key)=>{
            if(err)throw err;
           // console.log(key);
            createPassphrase(pass,(err,passdata) => {
                //console.log(passdata);
                encryptPrivKey(passdata.key,key.exportKey('pkcs8'),(err,encPrivKey)=>{
                    if(err)throw err;
                    var encPrivdudu = JSON.parse(encPrivKey);
                    var pk = key.exportKey('pkcs8-public');
                    var publicComp = key.exportKey('components-public');
                    var add = getaddress(pass);
                    usersalthash.push({
                        salt:add.salt,
                        hash:add.Hash
                    });
                    var userinfo = {
                        address:add,
                        cash:1000
                    }
                    var publicK = {
                        PublicKey:pk,
                        publicComponents:publicComp
                    }
                    var userJson = {
                        publicKey:publicK,
                        User:userinfo,
                        PassData:{ 
                            salt:passdata.salt,
                            ilteration:passdata.ilter,
                            keyByteLength:passdata.keybyteLength
                        },
                        encPrivKeyData:encPrivdudu,
                    }
                    var sign = createSign(key,userJson);
                    var fulluserJson = {
                        userSRC:userJson,
                        Usersign:sign
                    }
                    //console.log(fulluserJson);
                    getfilepath(add.Hash,(err,path)=>{
                        if(err)throw err;
                        console.log(path);
                        writeintojson(path,fulluserJson,(err)=>{
                            console.log('User:  '+add.Hash+' saved!!!');
                            broadcast(responsenewUser(fulluserJson));
                            res.send(add.Hash);
                        })
                    });
                })
            }
        )})
    })

    app.post('/cU',urlencodedParser, (req,res)=>{
        //to who and how much + password to json file
        console.log('---------------------------------------------------------------')
        checkaddress(req.body.password,(err,hash)=>{
            if(err){
                console.log('PW incorrect!!!°.°');
            };
            console.log('Spender:   '+hash)
            ckcrechash(req.body.address,(err)=>{
                if(err)throw err;
                getsamejson(hash,(err,obj)=>{
                    if(err)throw err;
                    let xcask = obj.userSRC.User.cash
                    let cnt=0;
                    transactions.forEach((t)=>{
                        if(t.spender === hash){
                            let c = parseInt(t.hm,10)
                            cnt+=c;
                        }
                    })
                    let wmon = parseInt(req.body.cash)
                    if((wmon+cnt)<=xcask){
                        //cnt = 0;
                        if(transactions.length<10){
                            console.log('Curr Coin:             '+(xcask-cnt))
                            console.log('Already Trans Cash:    '+(cnt+wmon))
                            transactions.push({
                                spender:hash,
                                rec:req.body.address,
                                hm:req.body.cash
                            })
                            //f
                            console.log('1NEW TRANSACTION:\n\rSPENDER---- '+hash+'\n\rREC----     '+req.body.address+'\n\rHM----      '+req.body.cash)
                            broadcast(responseTrans({
                                spender:hash,
                                rec:req.body.address,
                                hm:req.body.cash
                            }))
                            res.send('Ja');
                        }else{
                            
                            console.log('Curr Coin:             '+(xcask-cnt))
                            cnt =0;
                            console.log('Already Trans Cash:    '+(cnt+wmon))
                            //console.log(transactions)
                            let cunBlck = generateNextBlock(transactions);
                            addBlock(cunBlck);
                            console.log('BLOCK ADDED: '+JSON.stringify(cunBlck))
                            broadcast(responseLatestMsg());
                            if(err)throw err;
                                //console.log('guc')
                                transactions.length=0;
                                transactions.push({
                                    spender:hash,
                                    rec:req.body.address,
                                    hm:req.body.cash
                                })
                                console.log('NEW TRANSACTION:\n\rSPENDER---- '+hash+'\n\rREC----     '+req.body.address+'\n\rHM----      '+req.body.cash)
                                broadcast(responseTrans({
                                    spender:hash,
                                    rec:req.body.address,
                                    hm:req.body.cash,
                                    index:transactions.length
                                }))
                        }
                    }else{
                        console.log('noe')
                        res.send('Noe dat ged nid');
                    }
                })
            })
        })
    })



    app.post('/ididitanddidnothingelseinmylife',urlencodedParser, (req,res)=>{
        //gets Data(hash, transaction, time when created)
        //controll if succescfull 
        //if succesfull sends someonedidit!
    })

    /*app.post('/mineBlock',urlencodedParser, (req, res) => {
        console.log(req.body.name);
        var newBlock = generateNextBlock(req.body.name +":"+req.body.val);
        addBlock(newBlock);
        broadcast(responseLatestMsg());
        console.log('block added: ' + JSON.stringify(newBlock));
        res.send("DONE");
    });*/
    app.get('/peers', (req, res) => {
        res.send(sockets.map(s => '-------'+s._socket.remoteAddress + ':' + s._socket.remotePort  + '-------\n\r'));
        console.log(sockets.map(s => s._socket.remoteAddress + ':' + s._socket.remotePort));
    });
    app.post('/addPeer',urlencodedParser, (req, res) => {
        var peeradd = req.body.address;
        console.log(peeradd);
        var tpr = 'ws://'+peeradd;
        console.log(tpr);
        connectToPeers([tpr]);
        res.send("DONE");
    });
    app.listen(http_port,ip.address(), () => console.log('Listening on: '+ip.address()+':'+ http_port));
};


var createnewUserFile = (recobj)=>{
    getfilepath(recobj.userSRC.User.address.hash,(err,path)=>{
        if(err)throw err;
        console.log(path);
        writeintojson(path,recobj,(err)=>{
            console.log('User:  '+recobj.userSRC.User.address.hash+' saved!!!');
        })
    });
}


var transthethis = (tr) =>{
    for(let i=0;i<tr.length;i++){
        getsamejson(tr[i].spender,(err,speobj)=>{
            if(err)throw err;
            let y = parseInt(speobj.userSRC.User.cash) - parseInt(tr[i].hm)
            console.log(y+'spent')
            speobj.userSRC.User.cash = y

            writeintojson('./user/user_'+tr[i].spender+'.json',speobj,(err)=>{
                if(err)console.log(err);
                console.log('ges')
            })
        })
        getsamejson(tr[i].rec,(err,recobj)=>{
            if(err)throw err;
            let y = parseInt(recobj.userSRC.User.cash) + parseInt(tr[i].hm)
            console.log(y+'gained')
            recobj.userSRC.User.cash = y

            //console.log(recobj.userSRC.User.cash)

            writeintojson('./user/user_'+tr[i].rec+'.json',recobj,(err)=>{
                if(err)throw err;
                console.log('ges')
            })
        })
    }
}



var ckcrechash = (recHash,cb)=>{
    usersalthash.forEach((ousr)=>{
        if(ousr.hash===recHash){
            console.log('REC:       '+ousr.hash);
            cb(null);
            return;
        }
    })
}



var checkaddress=(password,cb)=>{
    usersalthash.forEach((curs,indx)=>{
        let zws = CryptoJS.SHA256(password + curs.salt).toString()
        if(curs.hash === zws){
            cb(null,zws);
            return;
        }
    })
}

var getsamejson=(addhash,cb)=>{
    let path = './user/user_'+addhash+'.json'
    //console.log(path)
    readfromjson(path,(err,obj)=>{
        if(err){cb('xD');return;}
        cb(null,obj);
        return;
    })
    
}

var checkalldata = (receiveduserData)=>{
    var addhash = receiveduserData.userSRC.userinfo.address.Hash;
    getsamejson(addhash,(err,obj)=>{
        if(err)throw err;
        if(JSON.stringify(receiveduserData)===JSON.stringify(obj)){
            return false;
        }else{
            if(receiveduserData.userSRC.userinfo.cash!==obj.userSRC.userinfo.cash){
                return false;
            }else{
                return false;
            }
        }
    });
}

var checkifnew = (address)=>{
    for(let i=0;i<usersalthash.length;i++){
        if(usersalthash[i]===address){
            return false;
        }
    }
    return true;
}

var verifyKey = (pubKey,sign,data)=>{
    var key = new NodeRSA();
    if(key.isEmpty()){
        key.importKey(pubKey);
        console.log(key);
        if(key.verify(JSON.stringify(CryptoJS.SHA256(data).toString()),sign)){
            return true;
        }else{
            return false;
        }
    }
}

var decryptedPrivKey = (encrypted_json_str, passphrase)=>{
    var r_pass_base64 = passphrase.toString("base64");
    var CryptoJS = aescryp.CryptoJS;
    var JsonFormatter = aescryp.JsonFormatter;
    var decrypted = CryptoJS.AES.decrypt(encrypted_json_str, r_pass_base64, { format: JsonFormatter });
    console.log(decrypted); 
    var decrypted_str = CryptoJS.enc.Utf8.stringify(decrypted);
    console.log("decrypted string: " + decrypted_str);
}
var makekeyPrivAgain = (privateStr)=>{
    var upkey = new NodeRSA(privateStr);
}

var createSign = (key,userJson) =>{
    return key.sign(JSON.stringify(CryptoJS.SHA256(userJson).toString()));
}

var getaddress = (password) =>{
    var salt = crypto.randomBytes(16).toString();
    return {
        Hash:CryptoJS.SHA256(password + salt).toString(),
        salt:salt
    }
}

var nodeRSAKey = (cb) => {
    var key =new NodeRSA({b: 512});
    cb(null,key);
} 

var createPassphrase = (passphrase,cb) => {

    var salt = crypto.randomBytes(16);

    var iterations = 137;
    var keyByteLength = 32; 
    var x;

    crypto.pbkdf2(passphrase, salt, iterations, keyByteLength, 'sha256', function (err, bytes) {
        x = bytes.toString('hex')
        var passdata = { 
            key:x,
            salt:salt,
            ilter:iterations,
            keybyteLength:keyByteLength,
        };
        cb(null,passdata)
    });
}


var encryptPrivKey = (keyphrase,privatKey,cb) => {

    var r_pass_base64 = keyphrase.toString("base64");
    console.log(r_pass_base64);
    var JsonFormatter = aescryp.JsonFormatter;
    var CryptoJS = aescryp.CryptoJS;
    var encrypted = CryptoJS.AES.encrypt(privatKey, r_pass_base64, { format: JsonFormatter });
    var encrypted_json_str = encrypted.toString();
    cb(null,encrypted_json_str);
}


var initP2PServer = () => {
    var server = new WebSocket.Server({port: p2p_port});
    server.on('connection', ws => initConnection(ws));
    console.log('listening websocket p2p port on: ' + p2p_port);

};

var initConnection = (ws) => {
    sockets.push(ws);
    initMessageHandler(ws);
    initErrorHandler(ws);
    write(ws, queryChainLengthMsg());
    writepeers((err)=>{
        if(err) throw err;
        console.log("Peer saved");
    })
};

var initMessageHandler = (ws) => {
    ws.on('message', (data) => {
        var message = JSON.parse(data);
        console.log('Received message' + JSON.stringify(message));
        switch (message.type) {
            case MessageType.QUERY_LATEST:
                write(ws, responseLatestMsg());
                break;
            case MessageType.QUERY_ALL:
                write(ws, responseChainMsg());
                break;
            case MessageType.RESPONSE_BLOCKCHAIN:
                handleBlockchainResponse(message);
                break;
            case MessageType.RESPONSE_USERDATA:
                handleUserdataResponse(message);
                break;
            case MessageType.RESPONSE_TRANSACTION:
                handleTransactionResponse(message)
                break;
        }
    });
};

var initErrorHandler = (ws) => {
    var closeConnection = (ws) => {
        console.log('connection failed to peer: ' + ws.url);
        sockets.splice(sockets.indexOf(ws), 1);
    };
    ws.on('close', () => closeConnection(ws));
    ws.on('error', () => closeConnection(ws));
};


var generateNextBlock = (blockData) => {
    var previousBlock = getLatestBlock();
    var nextIndex = previousBlock.index + 1;
    var nextTimestamp = new Date().getTime() / 1000;
    var nextHash = calculateHash(nextIndex, previousBlock.hash, nextTimestamp, blockData);
    return new Block(nextIndex, previousBlock.hash, nextTimestamp, blockData, nextHash);
};


var calculateHashForBlock = (block) => {
    return calculateHash(block.index, block.previousHash, block.timestamp, block.data);
};

var calculateHash = (index, previousHash, timestamp, data) => {
    return CryptoJS.SHA256(index + previousHash + timestamp + data).toString();
};

var addBlock = (newBlock) => {
    if (isValidNewBlock(newBlock, getLatestBlock())) {
        blockchain.push(newBlock);
        writedebug("Block:  " + newBlock.index + "     chained at " + new Date().getTime() / 1000 + "from User: "+ip.address());
        writecontentbcf((err)=>{
            console.log("Blockchain saved");
        });
    }
};

var isValidNewBlock = (newBlock, previousBlock) => {
    if (previousBlock.index + 1 !== newBlock.index) {
        console.log('invalid index');
        return false;
    } else if (previousBlock.hash !== newBlock.previousHash) {
        console.log('invalid previoushash');
        return false;
    } else if (calculateHashForBlock(newBlock) !== newBlock.hash) {
        console.log(typeof (newBlock.hash) + ' ' + typeof calculateHashForBlock(newBlock));
        console.log('invalid hash: ' + calculateHashForBlock(newBlock) + ' ' + newBlock.hash);
        return false;
    }
    return true;
};

var connectToPeers = (newPeers) => {
    newPeers.forEach((peer) => {
        var ws = new WebSocket(peer);
        ws.on('open', () => initConnection(ws));
        ws.on('error', () => {
            console.log('connection failed');
        });
    });
};

var handleTransactionResponse = (message) =>{
    var receivedTrans = JSON.parse(message.data);
    if(transactions.length<receivedTrans.index){
        ckcrechash(receivedTrans.spender,(err)=>{
            if(err)throw err;
            ckcrechash(receivedTrans.rec,(err)=>{
                if(err)throw err;
                getsamejson(receivedTrans.spender,(err,spobj)=>{
                    if(err)throw err;
                    let xcask = obj.userSRC.User.cash
                    if(receivedTrans.hm<=xcask){
                        transactions.push({
                            receivedTrans
                        })}})})})}}

var handleUserdataResponse = (message) => {
    //              verify file
    var receiveduserData = JSON.parse(message.data);
    console.log(receiveduserData);
    //look if data correct
    if(checkifnew(receiveduserData.userSRC.User.address)){
        if(verifyKey(receiveduserData.userSRC.publicKey.PublicKey,receiveduserData.Usersign,receiveduserData.userSRC)){
            if(receiveduserData.userSRC.User.cash===0){
                createnewUserFile(receiveduserData);
                broadcast(responsenewUser(receiveduserData))
            }else{
                console.log('cash not good')
            }
        }else{
            console.log('Signature not good');
        }
    }else{ 
        console.log('Received Userdata already existing or corrupted. Do nothing');
    }
}


var handleBlockchainResponse = (message) => {
    var receivedBlocks = JSON.parse(message.data).sort((b1, b2) => (b1.index - b2.index));
    var latestBlockReceived = receivedBlocks[receivedBlocks.length - 1];
    var latestBlockHeld = getLatestBlock();
    if (latestBlockReceived.index > latestBlockHeld.index) {
        console.log('blockchain possibly behind. We got: ' + latestBlockHeld.index + ' Peer got: ' + latestBlockReceived.index);
        if (latestBlockHeld.hash === latestBlockReceived.previousHash) {
            console.log("We can append the received block to our chain");
            blockchain.push(latestBlockReceived);
            broadcast(responseLatestMsg());
            writecontentbcf((err)=>{
                console.log("Blockchain saved");
            });
            writedebug("Blockchain:  " + latestBlockReceived.index + "     appended at " + new Date().getTime() / 1000 + "to Chain");
        } else if (receivedBlocks.length === 1) {
            console.log("We have to query the chain from our peer");
            broadcast(queryAllMsg());
            writedebug("Blockchain:  " + getLatestBlock.index + "     sent at " + new Date().getTime() / 1000 + "to All User");
        } else {
            console.log("Received blockchain is longer than current blockchain");
            replaceChain(receivedBlocks);
            writecontentbcf((err)=>{
                console.log("Blockchain saved");
            });
        }
    } else {
        console.log('received blockchain is not longer than received blockchain. Do nothing');
    }
};

var replaceChain = (newBlocks) => {
    if (isValidChain(newBlocks) && newBlocks.length > blockchain.length) {
        console.log('Received blockchain is valid. Replacing current blockchain with received blockchain');
        blockchain = newBlocks;
        broadcast(responseLatestMsg());
    } else {
        console.log('Received blockchain invalid');
    }
};

var isValidChain = (blockchainToValidate) => {
    if (JSON.stringify(blockchainToValidate[0]) !== JSON.stringify(getGenesisBlock())) {
        return false;
    }
    var tempBlocks = [blockchainToValidate[0]];
    for (var i = 1; i < blockchainToValidate.length; i++) {
        if (isValidNewBlock(blockchainToValidate[i], tempBlocks[i - 1])) {
            tempBlocks.push(blockchainToValidate[i]);
        } else {
            return false;
        }
    }
    return true;
};



var getLatestBlock = () => blockchain[blockchain.length - 1];
var queryChainLengthMsg = () => ({'type': MessageType.QUERY_LATEST});
var queryAllMsg = () => ({'type': MessageType.QUERY_ALL});
var responseChainMsg = () =>({
    'type': MessageType.RESPONSE_BLOCKCHAIN, 'data': JSON.stringify(blockchain)
});
var responseLatestMsg = () => ({
    'type': MessageType.RESPONSE_BLOCKCHAIN,
    'data': JSON.stringify([getLatestBlock()])
});

var responsenewUser = (userInfo) => ({
    'type': MessageType.RESPONSE_USERDATA,
    'data': JSON.stringify(userInfo)
})

var responseTrans = (trans)=>({
    'type': MessageType.RESPONSE_TRANSACTION,
    'data': JSON.stringify(trans)
})

var write = (ws, message) => ws.send(JSON.stringify(message));
var broadcast = (message) => sockets.forEach(socket => write(socket, message));


var getfilepath = (address,cb) =>{
    var path = './user/user_'+address+'.json';
    console.log(path);
    fs.writeFile(path,"",(err)=>{
        if(err)throw err;
        console.log("File created");
        cb(null,path);
    })
}

var craetefile = (path,cb)=>{
    fs.writeFile(path,'',(err)=>{
        if(err)cb(err);return;
        cb(null,path)
    })
}

var readcontdebug = (cb) =>{
    fs.readFile('./tmp/hcoinsave.txt',(err,data)=> {
        if(err) throw err;
        cb(null,data);
    })
}
var writedebug = (data) => fs.appendFile(debugfl,data + "\r\n",(err)=> {
    if(err) throw err;
    console.log("Debugfile upduted")
})

var writepeers = (canbok) =>{
    var zw = sockets.map(s => "ws://"+ s._socket.remoteAddress + ':' + s._socket.remotePort);
    console.log(zw);
    jsonfl.writeFile(peersfl, zw ,(err)=>{
        if(err) throw err;
        canbok(null);
    })
}

var readpeers = (snobu)=>{
    jsonfl.readFile(peersfl,(err,obj)=>{
        if(err)throw err;
        snobu(null,obj);
    })
}
 
var readcontentbcf = (cb) =>{
    jsonfl.readFile(bcfile,(err,obj)=>{
        if(err) cb(err);
        cb(null,obj);
    })
}
var writecontentbcf = (collbuk)=>{
    jsonfl.writeFile(bcfile,blockchain,(err)=>{
        if(err) {
            console.log('create bcfile');

        }
        collbuk(null);
    })
}

var writeintojson = (filepath,data,cb)=>{
    jsonfl.writeFile(filepath,data,{spaces: 2, EOL: '\r\n'},(err)=>{
        if(err)cb(err);
        console.log("super")
        cb(null);
        return;
    })
} 

var readfromjson = (filepath,cb) =>{
    jsonfl.readFile(filepath,(err,obj)=>{
        if(err)throw err;
        cb(null,obj);
    })
}

var readAllFiles = (dirname, onFileContent, onError)=> {
    fs.readdir(dirname, function(err, filenames) {
      if (err) {
        onError(err);
        return;
      }
      filenames.forEach(function(filename) {
        fs.readFile(dirname + filename,'utf-8', function(err, content) {
          if (err) {
            onError(err);
            return;
          }
          onFileContent(filename, content);
        });
      });
    });
}

connectToPeers(initialPeers);
initHttpServer();
initP2PServer();

/*readcontentbcf((err,data)=>{
    if(err)craetefile(bcfile,(err)=>{
        if(err)throw err;
    })
    if(data===''){return}
    blockchain = data;
    console.log(blockchain)
})*/

/*readpeers((err,obj)=>{
    if(err){throw err};
    console.log(obj.length);
    console.log(obj[0]);
    if(obj.length===0){console.log("no peers found!")}
        else{for(var i= 0; i < obj.length;i++){
            console.log(obj[i]);
            connectToPeers([obj[i]]);
        }}
})*/

readAllFiles('./user/', (filename,content)=>{
    //console.log(filename);
    var UJ = JSON.parse(content);
    let me = UJ.userSRC.User.address
    usersalthash.push({
        salt:me.salt,
        hash:me.Hash
    })
},(err,content) =>{
    throw err;
})



