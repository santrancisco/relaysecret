// The encryption potion of the code was written by meixler, you can find it here https://github.com/meixler/web-browser-based-file-encryption-decryption
// All cryptography operations are implemented using using the Web Crypto API. Files are encrypted using AES-CBC 256-bit symmetric encryption. The encryption key is derived from the password and a random salt using PBKDF2 derivation with 10000 iterations of SHA256 hashing.

var mode = null;
var objFile = null;
var originalfilename = "plain.dec";
var deleteondownload = false;
var objurl = null;
var plaintext = null;
var downloadedcipherbytes = null;
var tempkey = uuidv4();
var anchorkey = window.location.hash.substring(1);
var objmetadata = null;
var downloadurl = null;

switchdiv('encrypt');
try {
    objurl = getUrlVars()["obj"]
    if (objurl != undefined) {
        switchdiv('decrypt');
        getMetadata(objurl);
    }
} catch{ }


function uuidv4() {
    return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
        (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
    );
}


function getUrlVars() {
    var vars = {};
    var parts = window.location.href.replace(/[?&]+([^=&]+)=([^&]*)/gi, function (m, key, value) {
        vars[key] = value;
    });
    return vars;
}

function getMetadata(objurl) {
    var body = document.body;
    body.classList.add("loading");
    let url = lambdaurl + objurl;
    fetch(url)
        .then(function (response) {
            body.classList.remove("loading");
            if (response.status == 404) {
                filesize.innerText = "Failed to fetch metadata - File may no longer exist.";
                return
            }
            response.json().then(
                function (data) {
                    objmetadata = data;
                    ss = String(objmetadata.objsize) + " Bytes"
                    if ((objmetadata.objsize / 1048576) > 1) {
                        ss = String((objmetadata.objsize / 1048576).toFixed(0)) + " Mb";
                    } else if ((objmetadata.objsize / 1024) > 1) {
                        ss = String((objmetadata.objsize / 1024).toFixed(0)) + " Kb"
                    }
                    filesize.innerText = ss;
                }
            )


        })

}

function uploadToS3(expire, bytearray) {
    var body = document.body;
    body.classList.add("loading");
    modalstatus.innerText="Getting presigned s3 URL for upload.";
    var url = lambdaurl + 'gettoken/' + expire;
    var filemetadata = {
        name:txtFilename.value,
        deleteondownload:inputdeleteondownload.checked
    }
    fetch(url)
        .then(response => response.json())
        .then(
            function (data) {
                var b64blob = base64ArrayBuffer(bytearray);
                const formData = new FormData();
                formData.append("Content-Type", "text/plain");
                formData.append("x-amz-meta-tag",(JSON.stringify(filemetadata)))
                Object.entries(data.fields).forEach(([k, v]) => {
                    formData.append(k, v);
                });
                formData.append("file", b64blob);
                modalstatus.innerText="Uploading encrypted blob";
                fetch(data.url, {
                    method: "POST",
                    body: formData,
                }).then(function (response) {
                    console.log(response.status)
                    body.classList.remove("loading");
                    if (response.status == 204) {
                        downloadurl = document.location.protocol + "//" + document.location.host + "?obj=" + data.fields.key + "#" + tempkey;
                        decoratedeurl = "<span>" + document.location.protocol + "//" + document.location.host + "?obj=</span>"
                            + "<span style='color: #0074D9;'>" + data.fields.key + "</span>"
                            + "#"
                            + "<span style='color: #FF851B;'>" + tempkey + "</span>"
                            spandownloadurl.innerHTML = "<a style='color:#303030' href='" + downloadurl + "' onclick='copyURI(event)'>" + decoratedeurl + "</a> (Click to copy)"
                        span_objname.innerText = data.fields.key
                        span_keymat.innerText = tempkey
                        divEncryptResult.style.display = "block";
                        divEncryptfile.style.display = "none";
                    } else {
                        spandownloadurl.innerText = "Failed to upload the file to S3";
                        spnEncstatus.classList.remove("greenspan");
                        spnEncstatus.classList.add("redspan");
                        spnEncstatus.innerHTML = '<p>Failed to upload.</p>';
                    }
                });
            })
        .catch(function (err) {
            console.log("Failed to upload"); // This is where you run code if the server returns any errors
            console.log(err);
            body.classList.remove("loading");
        });
}

async function downloadFromS3() {
    var url = objmetadata.signedurl
    const response = await fetch(url)
    
    if (response.status != 200) {
        spnDecstatus.innerText = "FAILED to download"
        return
    }
    console.log(response.headers.get("x-amz-meta-tag"))
    try {
        filemetadata = JSON.parse(response.headers.get("x-amz-meta-tag"));
    } catch {
        filemetadata = {name:"plain.dec",deleteondownload:false};
    }
    originalfilename = filemetadata.name;
    deleteondownload = filemetadata.deleteondownload;
    modalstatus.innerText="Decoding object from base64 to binary...";
    text = await response.text()

    downloadedcipherbytes = new Uint8Array(atob(text).split("").map(function (c) {
        return c.charCodeAt(0);
    }));
    modalstatus.innerText="Decrypting binary blob";
    return downloadedcipherbytes
}



async function deletefile() {
    var deleteurl = lambdaurl + "delete/" + objurl
    const response = await fetch(deleteurl)

    if (response.status != 200) {
        spnDecstatus.classList.remove("greenspan");
        spnDecstatus.classList.add("redspan");
        spnDecstatus.innerText = "<p>Failed to delete object</p>"
        return
    } else {
        spnDecstatus.classList.remove("redspan");
        spnDecstatus.classList.add("greenspan");
        spnDecstatus.innerHTML = "<p>Deleted object</p>"
    }
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

function switchdiv(t) {
    if (t == 'encrypt') {
        divEncryptfile.style.display = 'block';
        divDecryptfile.style.display = 'none';
        btnDivEncrypt.disabled = true;
        btnDivDecrypt.disabled = false;
        mode = 'encrypt';
    } else if (t == 'decrypt') {
        divEncryptfile.style.display = 'none';
        divDecryptfile.style.display = 'block';
        btnDivEncrypt.disabled = false;
        btnDivDecrypt.disabled = true;
        mode = 'decrypt';
    }
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
    txtFilename.value = objFile.name;
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

async function encryptfile() {
    modalstatus.innerText="Encrypting file with AES using tempkey and user provided password."
    btnEncrypt.disabled = true;

    var plaintextbytes = await readfile(objFile)
        .catch(function (err) {
            console.error(err);
        });
    var plaintextbytes = new Uint8Array(plaintextbytes);

    var pbkdf2iterations = 10000;
    var passphrasebytes = new TextEncoder("utf-8").encode(txtEncpassphrase.value + tempkey);
    var pbkdf2salt = window.crypto.getRandomValues(new Uint8Array(8));

    var passphrasekey = await window.crypto.subtle.importKey('raw', passphrasebytes, { name: 'PBKDF2' }, false, ['deriveBits'])
        .catch(function (err) {
            console.error(err);
        });
    console.log('passphrasekey imported');

    var pbkdf2bytes = await window.crypto.subtle.deriveBits({ "name": 'PBKDF2', "salt": pbkdf2salt, "iterations": pbkdf2iterations, "hash": 'SHA-256' }, passphrasekey, 384)
        .catch(function (err) {
            console.error(err);
        });
    console.log('pbkdf2bytes derived');
    pbkdf2bytes = new Uint8Array(pbkdf2bytes);

    keybytes = pbkdf2bytes.slice(0, 32);
    ivbytes = pbkdf2bytes.slice(32);

    var key = await window.crypto.subtle.importKey('raw', keybytes, { name: 'AES-CBC', length: 256 }, false, ['encrypt'])
        .catch(function (err) {
            console.error(err);
        });
    console.log('key imported');

    var cipherbytes = await window.crypto.subtle.encrypt({ name: "AES-CBC", iv: ivbytes }, key, plaintextbytes)
        .catch(function (err) {
            console.error(err);
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
    var exp = expiretime[expiretime.selectedIndex].value;
    uploadToS3(exp, resultbytes)
    // aEncsavefile.href = blobUrl;
    // aEncsavefile.download = objFile.name + '.enc';
    // aEncsavefile.hidden = false;
    spnEncstatus.classList.add("greenspan");
    spnEncstatus.innerHTML = '<p>File encrypted.</p>';
 
}

async function decryptfile() {
    var body = document.body;
    body.classList.add("loading");
    modalstatus.innerText="Downloading from S3";
    var cipherbytes = await downloadFromS3();
    modalstatus.innerText="Decrypting file using anchor key and user provided key";
    var pbkdf2iterations = 10000;
    var passphrasebytes = new TextEncoder("utf-8").encode(txtDecpassphrase.value + anchorkey);
    var pbkdf2salt = cipherbytes.slice(8, 16);


    var passphrasekey = await window.crypto.subtle.importKey('raw', passphrasebytes, { name: 'PBKDF2' }, false, ['deriveBits'])
        .catch(function (err) {
            console.error(err);

        });
    console.log('passphrasekey imported');

    var pbkdf2bytes = await window.crypto.subtle.deriveBits({ "name": 'PBKDF2', "salt": pbkdf2salt, "iterations": pbkdf2iterations, "hash": 'SHA-256' }, passphrasekey, 384)
        .catch(function (err) {
            console.error(err);
        });
    console.log('pbkdf2bytes derived');
    pbkdf2bytes = new Uint8Array(pbkdf2bytes);

    keybytes = pbkdf2bytes.slice(0, 32);
    ivbytes = pbkdf2bytes.slice(32);
    cipherbytes = cipherbytes.slice(16);

    var key = await window.crypto.subtle.importKey('raw', keybytes, { name: 'AES-CBC', length: 256 }, false, ['decrypt'])
        .catch(function (err) {
            console.error(err);
        });
    console.log('key imported');

    var plaintextbytes = await window.crypto.subtle.decrypt({ name: "AES-CBC", iv: ivbytes }, key, cipherbytes)
        .catch(function (err) {
            console.error(err);
        });

    if (!plaintextbytes) {
        spnDecstatus.classList.remove("greenspan");
        spnDecstatus.classList.add("redspan");
        spnDecstatus.innerHTML = '<p>Error decrypting file.  Password may be incorrect.</p>';
        return;
    }

    console.log('ciphertext decrypted');
    plaintextbytes = new Uint8Array(plaintextbytes);

    var blob = new Blob([plaintextbytes], { type: 'application/download' });
    var blobUrl = URL.createObjectURL(blob);
    aDecsavefile.href = blobUrl;
    aDecsavefile.download = originalfilename;
    spnDecstatus.classList.remove("redspan");
    spnDecstatus.classList.add("greenspan");
    spnDecstatus.innerHTML = '<p>File decrypted.</p>';
    aDecsavefile.hidden = false;
    body.classList.remove("loading");
}

function postdownloadaction(){
    if (deleteondownload) {
        deletefile();
        return
    } else {
        aDeleteFile.hidden = false;
    }
}
