// The encryption potion of the code was written by meixler, you can find it here https://github.com/meixler/web-browser-based-file-encryption-decryption
// All cryptography operations are implemented using using the Web Crypto API. Files are encrypted using AES-CBC 256-bit symmetric encryption. The encryption key is derived from the password and a random salt using PBKDF2 derivation with 10000 iterations of SHA256 hashing.

var mode = null;
var objFile = null;
var encryptemessagemode = false;
var originalfilename = "plaintext.txt";
var plaintext = null;
var downloadedcipherbytes = {};
var anchorkey = window.location.hash.substring(1);
// In tunnel mode tempkey is anchorkey derived from tunnelid
var tempkey = anchorkey;
var downloadurl = null;
var infected = false;
var tunnelid = "";

// Set onclick events for our page so we can lock it down using CSP.
btnDivEncMes.onclick = function(){switchdiv('encryptmessage')};
btnDivEncrypt.onclick = function(){switchdiv('encryptfile')};
btnDivDecrypt.onclick = function(){switchdiv('decrypt')};
btnRefresh.onclick = function(){
    divDecryptInfo.style.display = "";
    divDecryptResult.style.display = "none";
    refreshfilelist()
};
btnEncrypt.onclick = function(){encryptfile()};
textareaEncryptmessage.onfocus = function(){btnEncrypt.disabled=false};
encdropzone.ondrop = function(){drop_handler(event)};
encdropzone.ondragover=function(){dragover_handler(event)};
encdropzone.ondragend=function(){dragend_handler(event)};
adropzone.onclick=function(){encfileElem.click()};
encfileElem.onchange = function(){selectfile(this.files)};
txtFilename.onchange = function(){originalfilename=txtFilename.value.replace(/[^A-Za-z0-9\-\_\.]/g, '')};
bShowExtraInfo.onclick = function(){showmoredecryptioninfo()};
bCopyText.onclick = function(){copytextarea()};
imgDecryptImage.onclick = function(){divImageModal.style.display = "block";}
divImageModal.onclick = function(){divImageModal.style.display = "none";}

switchdiv('decrypt');
/*-------------------------------NAVIGATE THE APP GUI--------------------------------*/

function switchdiv(t) {
    if (t == 'encryptfile') {
        divEncryptResult.style.display = 'none';
        divEncrypt.style.display = 'block';
        divDecrypt.style.display = 'none';
        encryptemessagemode = false;

        divEncryptMessage.style.display = 'none';
        divEncryptFile.style.display = 'block';
        divFilename.style.display = '';
        divMsgTitle.style.display = "none";
        if (txtFilename.value != ""){
            originalfilename=txtFilename.value.replace(/[^A-Za-z0-9\-\_\.]/g, '')
        } else {
            originalfilename = "plaintext.txt";
        }
        btnDivEncrypt.disabled = true;
        btnDivDecrypt.disabled = false;
        btnDivEncMes.disabled = false;
        mode = 'encrypt';
    } else if (t == 'encryptmessage') {
        divEncryptResult.style.display = 'none';
        divEncrypt.style.display = 'block';
        divDecrypt.style.display = 'none';
        encryptemessagemode = true;

        divEncryptMessage.style.display = 'block';
        divEncryptFile.style.display = 'none';
        divFilename.style.display = 'none';
        divMsgTitle.style.display = "";
        originalfilename = "messageinbrowser.txt"

        btnDivEncrypt.disabled = false;
        btnDivDecrypt.disabled = false;
        btnDivEncMes.disabled = true;
        mode = 'encrypt';
    } else if (t == 'decrypt') {
        divEncryptResult.style.display = 'none';
        divEncrypt.style.display = 'none';
        divDecrypt.style.display = 'block';
        encryptemessagemode = false;
        originalfilename = "plaintext.txt";
        btnDivEncrypt.disabled = false;
        btnDivDecrypt.disabled = true;
        btnDivEncMes.disabled = false;
        mode = 'decrypt';
    }
}

/*---------------------------------CREATE/LOAD A TUNNEL------------------------------------*/
tunnelid = getUrlVars()["tunnelid"]
if (tunnelid == undefined) {
    tunnelid = ""
    while (tunnelid.length < 8) {
        tunnelid=prompt("Enter tunnel name (Min 8 characters)")
        if (tunnelid == null){
            var body = document.body;
            body.classList.add("loading");
            modalstatus.innerHTML="<h1>ERROR - No tunnel is created</h1>";
        }
    }
    sha256(tunnelid).then(function(tmpkey){
        sha256(tmpkey).then(function(tun){
            tun=tun.substring(0,16)
            window.location.href=window.location.href.split("?")[0]+"?tunnelid="+tun+"#"+tmpkey
        })
    }
    )
    
} else {
    // populate filelist
    refreshfilelist();
}

/*-------------------------------------Utilities functions----------------------------------*/


function uuidv4() {
    return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
        (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
    );
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

async function sha256(str) {
    // Get the string as arraybuffer.
    var buffer = new TextEncoder("utf-8").encode(str)
    hash = await crypto.subtle.digest("SHA-256", buffer);
    return buf2hex(hash);
  }

async function sha1(data) {
    hash = await crypto.subtle.digest('SHA-1', data);
    return buf2hex(hash);
  }

function showmoredecryptioninfo(){
    divExtraDecResult.style.display="block";
    bShowExtraInfo.style.display="none";
}

function getUrlVars() {
    var vars = {};
    var parts = window.location.href.replace(/[?&]+([^=&]+)=([^&]*)/gi, function (m, key, value) {
        vars[key] = value;
    });
    return vars;
}

function copyURI(evt) {
    evt.preventDefault();
    navigator.clipboard.writeText(downloadurl).then(() => {
        /* clipboard successfully set */
    }, () => {
        alert("Failed to copy to clipboard! Please try manually copying it!");
        /* clipboard write failed */
    });
}

function copytextarea() {
    let textarea = document.getElementById("textareaDecryptmessage");
    textarea.select();
    document.execCommand("copy");
}


function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
 }

/*---------------------------------------------------------------------------------------*/

async function refreshfilelist(){
    filelist = await gettunnelfilelist(tunnelid);
    old_tbody = document.getElementById("filelist");
    tbody = document.createElement('tbody');
    tbody.id = "filelist";
    filelist.forEach(function(f){
        console.log(f)
        var row = tbody.insertRow(0);
        filename=row.insertCell(0);
        downloadtd = row.insertCell(1);
        deteletd = row.insertCell(2);
        filename.innerText = escapeHtml(f.objname);
        downloadbutton = document.createElement("BUTTON");
        downloadbutton.innerText = "Download"
        downloadbutton.onclick = function(){decryptfile(f.key,f.objname)};
        deletebutton = document.createElement("BUTTON");
        deletebutton.innerText = "Delete"
        deletebutton.onclick = function(){deletefile(f.key)};
        downloadtd.append(downloadbutton);
        deteletd.append(deletebutton);
    });
    old_tbody.parentNode.replaceChild(tbody, old_tbody)
}

async function getMetadata(objkey) {
    let url = lambdaurl + objkey;
    response = await fetch(url);
    if (response.status == 404) {
        return
    }
    data = await response.json();
    originalfilename = data.objname.replace(/[^A-Za-z0-9\-\_\.]/g, '');
    return data;
}

async function checkforvirus(filehash) {
    let url = lambdaurl + "/sha1/"+filehash;
    response = await fetch(url);
    data = await response.json();
    vtlink = data.vtlink
    if (data.detect){
        console.log("Virus total detected!");
        spnDecstatus.classList.remove("greenspan");
        spnDecstatus.classList.add("redspan");
        spnDecstatus.innerHTML = "<h3 style='color:red'>VIRUS DETECTED</h3> <a target='_blank' href='"+vtlink+"'>Visit virustotal result("+data.positives+"/"+data.total+" detected)</a>"
        document.body.style.background="#ff9966";
        bDownloadDecFile.innerText = "Ignore & Download anyway"
        infected = true;
    } else {
        spnDecstatus.classList.remove("redspan");
        spnDecstatus.classList.add("greenspan");
        spnDecstatus.innerText = "File is clean!"
        console.log("This file is clean!");
    }
}

async function gettunnelfilelist(tunnelid) {
    let url = lambdaurl + "/listtunnel/"+tunnelid;
    response = await fetch(url);
    data = await response.json();
    return data;
}

async function uploadToS3(expire, bytearray) {
    var body = document.body;
    body.classList.add("loading");
    modalstatus.innerText="Getting presigned s3 URL for upload.";
    var url = lambdaurl + 'gettunnel/'+ tunnelid;
    var filemetadata = {
        name:originalfilename,
        deleteondownload:inputdeleteondownload.checked
    }
    try {
        response = await fetch(url);
        data = await response.json();             
        // var b64blob = base64ArrayBuffer(bytearray);
        blob = new Blob([bytearray], { type: 'application/octet-stream' });
        const formData = new FormData();
        formData.append("Content-Type", "text/plain");
        formData.append("x-amz-meta-tag",(JSON.stringify(filemetadata)))
        Object.entries(data.fields).forEach(function([k, v]) {
            formData.append(k, v);
        });
        formData.append("file", blob);
        modalstatus.innerText="Uploading encrypted blob";
        response = await fetch(data.url, {
            method: "POST",
            body: formData,
        })
        if (response.status == 204) {
            spnEncstatus.classList.add("greenspan");
            spnEncstatus.innerHTML = '<p>Upload file successfully. Check Decrypt tab.</p>';
            refreshfilelist()
        } else {
            spandownloadurl.innerText = "Failed to upload the file to S3";
            spnEncstatus.classList.remove("greenspan");
            spnEncstatus.classList.add("redspan");
            spnEncstatus.innerHTML = '<p>Failed to upload.</p>';
        }
    }
    catch(error) {
        console.log("Failed to upload"); // This is where you run code if the server returns any errors
        console.log(err);
        body.classList.remove("loading");
    }
}

function Uint8ToString(u8a){
    var CHUNK_SZ = 0x8000;
    var c = [];
    for (var i=0; i < u8a.length; i+=CHUNK_SZ) {
      c.push(String.fromCharCode.apply(null, u8a.subarray(i, i+CHUNK_SZ)));
    }
    return c.join("");
  }

function updateimgtag(extension,plaintextbytes){
    var b64encoded = btoa(Uint8ToString(plaintextbytes));
    divDecryptImage.style.display = "block";
    imgDecryptImage.src = "data:image/"+extension+";base64,"+b64encoded;
    imgDecryptImageModal.src = "data:image/"+extension+";base64,"+b64encoded;
}

async function downloadFromS3(objkey) {
    var objmetadata = await getMetadata(objkey);
    console.log(objmetadata)
    var url = objmetadata.signedurl;
    const response = await fetch(url);
    
    if (response.status != 200) {
        spnDecstatus.innerText = "FAILED to download"
        return
    }
    console.log(response.headers.get("x-amz-meta-tag"))
    try {
        filemetadata = JSON.parse(response.headers.get("x-amz-meta-tag"));
    } catch (error) {
        filemetadata = {name:"plain.dec",deleteondownload:false};
    }
    if (filemetadata.name != "") {
        originalfilename = filemetadata.name.replace(/[^A-Za-z0-9\-\_\.]/g, '');;
    }
    deleteondownload = filemetadata.deleteondownload;

    buff = await response.arrayBuffer();
    downloadedcipherbytes[objkey] = new Uint8Array(buff)
    modalstatus.innerText="Decrypting binary blob";
    return [downloadedcipherbytes[objkey],deleteondownload]
}

async function deletefile(objkey) {
    var deleteurl = lambdaurl + "delete/" + objkey
    const response = await fetch(deleteurl)

    if (response.status != 200) {
        spnDecstatus.classList.remove("greenspan");
        spnDecstatus.classList.add("redspan");
        spnDecstatus.innerHTML += "Failed to delete object";
        return
    } else {
        spnDecstatus.innerHTML = "Deleted object";
    }
    refreshfilelist();
}


//drag and drop functions:
//https://developer.mozilla.org/en-US/docs/Web/API/HTML_Drag_and_Drop_API/File_drag_and_drop
function drop_handler(ev) {
    console.log("Drop");
    ev.preventDefault();
    // If dropped items aren't files, reject them
    var dt = ev.dataTransfer;
    if (dt.items) {
        // Use DataTransferItemList interface to access the file(s)
        for (var i = 0; i < dt.items.length; i++) {
            if (dt.items[i].kind == "file") {
                var f = dt.items[i].getAsFile();
                console.log("... file[" + i + "].name = " + f.name);
                objFile = f;
            }
        }
    } else {
        // Use DataTransfer interface to access the file(s)
        for (var i = 0; i < dt.files.length; i++) {
            console.log("... file[" + i + "].name = " + dt.files[i].name);
        }
        objFile = file[0];
    }
    displayfile()
}

function dragover_handler(ev) {
    console.log("dragOver");
    // Prevent default select and drag behavior
    ev.preventDefault();
}

function dragend_handler(ev) {
    console.log("dragEnd");
    // Remove all of the drag data
    var dt = ev.dataTransfer;
    if (dt.items) {
        // Use DataTransferItemList interface to remove the drag data
        for (var i = 0; i < dt.items.length; i++) {
            dt.items.remove(i);
        }
    } else {
        // Use DataTransfer interface to remove the drag data
        ev.dataTransfer.clearData();
    }
}

function selectfile(Files) {
    objFile = Files[0];
    displayfile()
}

function displayfile() {
    originalfilename = objFile.name.replace(/[^A-Za-z0-9\-\_\.]/g, '');;
    txtFilename.value = objFile.name;
    var s;
    var sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    var bytes = objFile.size;
    var i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    if (i == 0) { s = bytes + ' ' + sizes[i]; } else { s = (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + sizes[i]; }

    if (mode == 'encrypt') {
        spnencfilename.textContent = objFile.name + ' (' + s + ')';
    } else if (mode == 'decrypt') {
        spndecfilename.textContent = objFile.name + ' (' + s + ')';
    }
    btnEncrypt.disabled = false;
}

function readfile(file) {
    return new Promise((resolve, reject) => {
        var fr = new FileReader();
        fr.onload = () => {
            resolve(fr.result)
        };
        fr.readAsArrayBuffer(file);
    });
}

/*----------------------------------ENCRYPT FILE-------------------------------------*/
async function encryptfile() {
    var body = document.body;
    // In 
    tempkey = anchorkey
    body.classList.add("loading");
    modalstatus.innerText="Encrypting file with AES using tempkey and user provided password."
    btnEncrypt.disabled = true;
    var plaintextbytes = null;

    if (encryptemessagemode){
        var plaintextbytes = new TextEncoder("utf-8").encode(textareaEncryptmessage.value)
        if (msgtitle.value != "") {
            originalfilename = msgtitle.value.replace(/[^A-Za-z0-9\-\_\.]/g)+".txt"
        }
    } else {
        var plaintextbytes = await readfile(objFile)
            .catch(function (err) {
                console.error(err);
                body.classList.remove("loading");
            });
        var plaintextbytes = new Uint8Array(plaintextbytes);
    }
    
    if (plaintextbytes.length == 0){
        spnEncstatus.classList.add("redspan");
        spnEncstatus.innerHTML = '<p>There is nothing to encrypt...</p>';
        return
    }
    var pbkdf2iterations = 10000;
    var passphrasebytes = new TextEncoder("utf-8").encode(txtEncpassphrase.value + tempkey);
    var pbkdf2salt = window.crypto.getRandomValues(new Uint8Array(8));

    var passphrasekey = await window.crypto.subtle.importKey('raw', passphrasebytes, { name: 'PBKDF2' }, false, ['deriveBits'])
        .catch(function (err) {
            console.error(err);
            body.classList.remove("loading");
        });
    console.log('passphrasekey imported');

    var pbkdf2bytes = await window.crypto.subtle.deriveBits({ "name": 'PBKDF2', "salt": pbkdf2salt, "iterations": pbkdf2iterations, "hash": 'SHA-256' }, passphrasekey, 384)
        .catch(function (err) {
            console.error(err);
            body.classList.remove("loading");
        });
    console.log('pbkdf2bytes derived');
    pbkdf2bytes = new Uint8Array(pbkdf2bytes);

    keybytes = pbkdf2bytes.slice(0, 32);
    ivbytes = pbkdf2bytes.slice(32);

    var key = await window.crypto.subtle.importKey('raw', keybytes, { name: 'AES-CBC', length: 256 }, false, ['encrypt'])
        .catch(function (err) {
            console.error(err);
            body.classList.remove("loading");
        });
    console.log('key imported');

    var cipherbytes = await window.crypto.subtle.encrypt({ name: "AES-CBC", iv: ivbytes }, key, plaintextbytes)
        .catch(function (err) {
            console.error(err);
            body.classList.remove("loading");
        });

    if (!cipherbytes) {
        spnEncstatus.classList.add("redspan");
        spnEncstatus.innerHTML = '<p>Error encrypting file.  See console log.</p>';
        return;
    }

    console.log('plaintext encrypted');
    cipherbytes = new Uint8Array(cipherbytes);

    var resultbytes = new Uint8Array(cipherbytes.length + 16)
    resultbytes.set(new TextEncoder("utf-8").encode('Salted__'));
    resultbytes.set(pbkdf2salt, 8);
    resultbytes.set(cipherbytes, 16);

    var blob = new Blob([resultbytes], { type: 'application/download' });
    var blobUrl = URL.createObjectURL(blob);
    var exp = 1;
    await uploadToS3(exp, resultbytes)
    body.classList.remove("loading");
    // aEncsavefile.href = blobUrl;
    // aEncsavefile.download = objFile.name + '.enc';
    // aEncsavefile.hidden = false;
}


/*----------------------------------DECRYPT FILE-------------------------------------*/

async function decryptfile(objkey,filename) {
    var body = document.body;
    body.classList.add("loading");
    if (downloadedcipherbytes[objkey] != undefined){
        var cipherbytes = downloadedcipherbytes[objkey];
    } else {
        modalstatus.innerText="Downloading from S3";
        var [cipherbytes,deleteondownload] = await downloadFromS3(objkey);
    }
    modalstatus.innerText="Decrypting file using anchor key and user provided key";
    var pbkdf2iterations = 10000;
    var passphrasebytes = new TextEncoder("utf-8").encode(txtDecpassphrase.value + anchorkey);
    var pbkdf2salt = cipherbytes.slice(8, 16);

    var passphrasekey = await window.crypto.subtle.importKey('raw', passphrasebytes, { name: 'PBKDF2' }, false, ['deriveBits'])
        .catch(function (err) {
            console.error(err);
            body.classList.remove("loading");

        });
    console.log('passphrasekey imported');

    var pbkdf2bytes = await window.crypto.subtle.deriveBits({ "name": 'PBKDF2', "salt": pbkdf2salt, "iterations": pbkdf2iterations, "hash": 'SHA-256' }, passphrasekey, 384)
        .catch(function (err) {
            console.error(err);
            body.classList.remove("loading");
        });
    console.log('pbkdf2bytes derived');
    pbkdf2bytes = new Uint8Array(pbkdf2bytes);

    keybytes = pbkdf2bytes.slice(0, 32);
    ivbytes = pbkdf2bytes.slice(32);
    cipherbytes = cipherbytes.slice(16);

    var key = await window.crypto.subtle.importKey('raw', keybytes, { name: 'AES-CBC', length: 256 }, false, ['decrypt'])
        .catch(function (err) {
            console.error(err);
            body.classList.remove("loading");
        });
    console.log('key imported');

    var plaintextbytes = await window.crypto.subtle.decrypt({ name: "AES-CBC", iv: ivbytes }, key, cipherbytes)
        .catch(function (err) {
            // console.error(err);
            body.classList.remove("loading");
        });

    if (!plaintextbytes) {
        spnDecstatus.classList.remove("greenspan");
        spnDecstatus.classList.add("redspan");
        spnDecstatus.innerHTML = '<p>Error decrypting file.  Password may be incorrect.</p>';
        return;
    }

    console.log('ciphertext decrypted');
    plaintextbytes = new Uint8Array(plaintextbytes);
    divDecryptImage.style.display = "none";
    divDecryptmessage.style.display = "none";

    var blob = new Blob([plaintextbytes], { type: 'application/download' });
    var blobUrl = URL.createObjectURL(blob);
    aDecsavefile.href = blobUrl;
    aDecsavefile.download = originalfilename;
    spnDecstatus.classList.remove("redspan");
    spnDecstatus.classList.add("greenspan");
    spnDecstatus.innerHTML = '<p>File decrypted.</p>';
    divDecsavefile.hidden = false;
    modalstatus.innerText="Checking SHA1 hash of the file with Virustotal";
    filehash= await sha1(plaintextbytes);
    await checkforvirus(filehash);
    // If this is a message send in browser, show it.
    body.classList.remove("loading");
    divDecryptInfo.style.display = "none";
    divDecryptResult.style.display = ""
    bDeleteFile.onclick = function(){deletefile(objkey)};
    if (filename.endsWith("txt"))
    {
        textareaDecryptmessage.value =  new TextDecoder("utf-8").decode(plaintextbytes);
        bCopyText.hidden = false;
        divDecryptmessage.style.display = "";
    }

    fileextension = originalfilename.substr(-4)
    
    switch (fileextension) {
        case ".png":
            updateimgtag("png",plaintextbytes);
            break;
        case ".jpg":
            updateimgtag("jpg",plaintextbytes);
            break;
        case "jpeg":
            updateimgtag("jpeg",plaintextbytes);
            break;
        case ".gif":
            updateimgtag("gif",plaintextbytes);
            break;
        
    }
    if (deleteondownload){
        deletefile(objkey);
    }
}



