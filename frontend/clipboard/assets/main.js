// Get encrypted cloudflare KV stored clipboard data to local clipboard
var currentclipboard = "";
const getButton = document.getElementById('get');

getButton.addEventListener('click', async () => {
    var body = document.body;
    body.classList.add("loading");
    document.getElementById("status").innerText = "Getting latest clipboard ...";
    getcurrentclipboard().then(plaintext => {
        if (plaintext.startsWith("ClipboardError:")) {
            document.getElementById("status").innerText = "Failed to get latest clipboard." + plaintext;
            body.classList.remove("loading");
            return
        }
        navigator.clipboard.writeText(plaintext).then(() => {
            document.getElementById("status").innerText = "Successfully pull latest clipboard value";
            body.classList.remove("loading");
        }).catch(err => {
            document.getElementById("status").innerText = "Failed to get latest clipboard due to: " + err.toString();
            body.classList.remove("loading");
        })

    }).catch(err => {
        document.getElementById("status").innerText = "Failed to get latest clipboard due to: " + err.toString();
        body.classList.remove("loading");
    })



})

// Update cloudflare KV stored clipboard's content
const updateButton = document.getElementById('update')
updateButton.addEventListener('click', async () => {
    var body = document.body;
    body.classList.add("loading");
    document.getElementById("status").innerText = "Updating ...";
    navigator.clipboard.readText().then(text => {
        updateclipboard(text).then(encryptedbytes => {
            body.classList.remove("loading");
        }).catch(err => {
            document.getElementById("status").innerText = "Failed updating clipboard due to: " + err.toString();
            body.classList.remove("loading");
        })

    }).catch(err => {
        document.getElementById("status").innerText = "Failed updating clipboard due to: " + err.toString();
        body.classList.remove("loading");
    })


})


// The encryption potion of the code was written by meixler, you can find it here https://github.com/meixler/web-browser-based-file-encryption-decryption
// All cryptography operations are implemented using using the Web Crypto API. Files are encrypted using AES-CBC 256-bit symmetric encryption. The encryption key is derived from the password and a random salt using PBKDF2 derivation with 10000 iterations of SHA256 hashing.

var downloadedcipherbytes = {};
var anchorkey = window.location.hash.substring(1);
// In tunnel mode tempkey is anchorkey derived from clipboardid
var tempkey = anchorkey;
var body = document.body;


/*---------------------------------CREATE/LOAD A TUNNEL------------------------------------*/
var clipboardid = "";
clipboardid = getUrlVars()["clipboardid"]
if (clipboardid == undefined) {
    clipboardid = ""
    while (clipboardid.length < 8) {
        clipboardid = prompt("Enter tunnel name (Min 8 characters)")
        if (clipboardid == null) {
            body.classList.add("loading");
            modalstatus.innerHTML = "<h1>ERROR - No tunnel is created</h1>";
        }
    }
    sha256(clipboardid).then(function (tmpkey) {
        sha256(tmpkey).then(function (tun) {
            tun = tun.substring(0, 16)
            window.location.href = window.location.href.split("?")[0] + "?clipboardid=" + tun + "#" + tmpkey
        })
    }
    )

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

function showmoredecryptioninfo() {
    divExtraDecResult.style.display = "block";
    bShowExtraInfo.style.display = "none";
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

function fromHexString(hexString) {
    return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function toHexString(bytes) {
    return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

function Uint8ToString(u8a) {
    var CHUNK_SZ = 0x8000;
    var c = [];
    for (var i = 0; i < u8a.length; i += CHUNK_SZ) {
        c.push(String.fromCharCode.apply(null, u8a.subarray(i, i + CHUNK_SZ)));
    }
    return c.join("");
}


/*----------------------------------UPDATE KV DATA-------------------------------------*/

async function uploadencryptedclipboard(bytearray) {
    var body = document.body;
    modalstatus.innerText = "Upload encrypted clipboard";
    var url = clipboardurl + 'update/' + clipboardid;
    try {
        encryptedhexstring = toHexString(bytearray)
        modalstatus.innerText = "Uploading encrypted blob";
        response = await fetch(url, {
            method: "POST",
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ "data": encryptedhexstring }),
        })
        if (response.status == 200) {
            document.getElementById("status").innerText = "Successfully update clipboard.";
        } else {
            document.getElementById("status").innerText = "Failed to update clipboard.";
        }
    }
    catch (err) {
        console.log("Failed to upload"); // This is where you run code if the server returns any errors
        console.log(err);
        document.getElementById("status").innerText = "Failed to update clipboard.";
        body.classList.remove("loading");
    }
}

async function updateclipboard(data) {
    tempkey = anchorkey
    modalstatus.innerText = "Encrypting file with AES using tempkey and user provided password."
    var plaintextbytes = new TextEncoder("utf-8").encode(data)
    if (plaintextbytes.length == 0) {
        return "ClipboardError: Nothing in clipboard"
    }
    var pbkdf2iterations = 10000;
    var passphrasebytes = new TextEncoder("utf-8").encode(txtEncpassphrase.value + tempkey);
    var pbkdf2salt = window.crypto.getRandomValues(new Uint8Array(8));
    var passphrasekey = await window.crypto.subtle.importKey('raw', passphrasebytes, { name: 'PBKDF2' }, false, ['deriveBits'])
        .catch(function (err) {
            body.classList.remove("loading");
        });

    var pbkdf2bytes = await window.crypto.subtle.deriveBits({ "name": 'PBKDF2', "salt": pbkdf2salt, "iterations": pbkdf2iterations, "hash": 'SHA-256' }, passphrasekey, 384)
        .catch(function (err) {
            body.classList.remove("loading");
        });
    pbkdf2bytes = new Uint8Array(pbkdf2bytes);

    keybytes = pbkdf2bytes.slice(0, 32);
    ivbytes = pbkdf2bytes.slice(32);

    var key = await window.crypto.subtle.importKey('raw', keybytes, { name: 'AES-CBC', length: 256 }, false, ['encrypt'])
        .catch(function (err) {
            body.classList.remove("loading");
        });

    var cipherbytes = await window.crypto.subtle.encrypt({ name: "AES-CBC", iv: ivbytes }, key, plaintextbytes)

    if (!cipherbytes) {
        throw "Cannot encrypt file"
    }

    cipherbytes = new Uint8Array(cipherbytes);

    var resultbytes = new Uint8Array(cipherbytes.length + 16)
    resultbytes.set(new TextEncoder("utf-8").encode('Salted__'));
    resultbytes.set(pbkdf2salt, 8);
    resultbytes.set(cipherbytes, 16);

    // Upload encrypted clipboard to cloudflare worker
    uploadencryptedclipboard(resultbytes)
    // Localtest: currentclipboard = toHexString(resultbytes)
    // currentclipboard = toHexString(resultbytes)

    // await uploadToS3(exp, resultbytes)
    return resultbytes
}


/*----------------------------------DOWNLOAD KV DATA-------------------------------------*/


async function downloadencryptedclipboard(clipboardid) {
    modalstatus.innerText = "Decrypting file using anchor key and user provided key";
    var url = clipboardurl + "get/" + clipboardid;
    const response = await fetch(url);
    if (response.status != 200) {
        return ""
    }
    jsondata = await response.json()
    return fromHexString(jsondata["data"])
}

async function getcurrentclipboard() {
    // Download encrypted clipboard here
    cipherbytes = await downloadencryptedclipboard(clipboardid)
    if (cipherbytes == "") {
        return "ClipboardError: Fail to download latest clipboard"
    }

    // Local test: cipherbytes = fromHexString(currentclipboard)
    // cipherbytes = fromHexString(currentclipboard)
    modalstatus.innerText = "Decrypting file using anchor key and user provided key";
    var pbkdf2iterations = 10000;
    var passphrasebytes = new TextEncoder("utf-8").encode(txtEncpassphrase.value + anchorkey);
    var pbkdf2salt = cipherbytes.slice(8, 16);

    var passphrasekey = await window.crypto.subtle.importKey('raw', passphrasebytes, { name: 'PBKDF2' }, false, ['deriveBits'])
        .catch(function (err) {
            body.classList.remove("loading");
            return "ClipboardError: " + err.toString()
        });

    var pbkdf2bytes = await window.crypto.subtle.deriveBits({ "name": 'PBKDF2', "salt": pbkdf2salt, "iterations": pbkdf2iterations, "hash": 'SHA-256' }, passphrasekey, 384)
        .catch(function (err) {
            console.log(err);
            body.classList.remove("loading");
            return "ClipboardError: " + err.toString()
        });
    pbkdf2bytes = new Uint8Array(pbkdf2bytes);

    keybytes = pbkdf2bytes.slice(0, 32);
    ivbytes = pbkdf2bytes.slice(32);
    cipherbytes = cipherbytes.slice(16);

    var key = await window.crypto.subtle.importKey('raw', keybytes, { name: 'AES-CBC', length: 256 }, false, ['decrypt'])
        .catch(function (err) {
            body.classList.remove("loading");
            return "ClipboardError: " + err.toString()
        });

    var plaintextbytes = await window.crypto.subtle.decrypt({ name: "AES-CBC", iv: ivbytes }, key, cipherbytes)
        .catch(function (err) {
            body.classList.remove("loading");
            return null
        });

    if (!plaintextbytes) {
        return "ClipboardError: Wrong password?"
    }

    plaintextbytes = new Uint8Array(plaintextbytes);

    return new TextDecoder("utf-8").decode(plaintextbytes);

}



