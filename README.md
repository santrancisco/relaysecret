## Why another file sharing app?

Several reasons:

 - Because firefoxsend was taken down and the walkthrough to deploy it is too complicated. 
 - Magicwormhole is great but needs client app installed
 - Some solutions look amazing but turn out the plaintext is sent to the server and all encryption are done on the server side
 - Many solutions are well written, looks great but the code are complex, some even use websocket, others use webrtc ... with tons of dependency which make it impossible to review and prone to supply chain attack on each rebuild.
 - Other issues such as 3rd party tracking cookie is found, too much backend code that may be proned to attacks

 What relaysecret aim for:
  - Extremely simple code to handle api calls (1 lambda function)
  - File upload/download operation is all done by S3 signed url means no maintainance whatsover or worry about RCE on your server.
  - Extremely simple frontend code with minimal javascript and no 3rd party dependency (everything is done using standard webcrypto)
  - No complicated websocket, webrtc... no need for realtime refresh ... there is literally a button to refresh the list of files in room mode.

How do you "scan for virus" ? Do you send my files to Virustotal?

After decrypting the content, a sha1 hash of the data is computed and send back to our lambda to fetch Virustotal scan result for that hash. So PLEASE PLEASE PLEASE do not put a single line with your ultimate 5 characters long AD password in it if you worry someone may MITM your traffic, discover the sha1 and run bruteforce on it. 

## Relay Secret

Visit [https://www.relaysecret.com/](https://www.relaysecret.com/) to try it out.

This project has 3 parts:

 - The simple backend lambda function to generate signed url for user to upload, download and delete files from S3 
 - The frontend with half of the code took from [this project writen by meixler](https://github.com/meixler/web-browser-based-file-encryption-decryption/blob/master/web-browser-based-file-encryption-decryption.html) with some extra fetch calls sprinkel ontop to handle ajax calls to the lambda and upload/download from s3
 - The terraform code which deploy a lambda function, an api gateway and our encrypted s3 bucket with special CORs policy and expire rules to make it all work ;)


## Room mode

Visit [https://www.relaysecret.com/tunnel](https://www.relaysecret.com/tunnel) to try it out.

This mode let you create a "room". By visiting the URL above in another broser or device, entering the same room name, users can share and decrypt files from the same room. Note that all files in room will expire after 1 day.

Room mode does not generate a random temporary key material which you will find after the hash (#) in the URL. The key material here is simply the sha256 of the roomname itself so in a way, the roomname IS THE DEFAULT PASSWORD for files (if no extra password is used). Of course, same as before, the roomname or the tempkey stays in browser and do not go back to the server.

Users are encouraged to add password for extra protection. This password, same as before, will be used together with the sha256 value of the room name to make it much harder to bruteforce.

## Process flow

### Upload file

 - Frontend code visits lambda function to get a S3 signed POST url for file upload
 - Frontend code encrypt the data and upload encrypted blob to S3 bucket + tag object with original filename (this is still in plaintext)
 - Frontend code generates download url

### Retrieve file

 - User visits `https://{server}/{object-key}#{key-material}`. Note that the key-material never leaves browser because it is behind anchor tag. User can choose to add his own password for extra security
 - Frontend code get signed url for the encrypted blob from the lambda
 - Frontend code download the encrypted blob and use key-material, combine with user provided password (if needed) to decrypt the blob and retrieve the plaintext content

### Expire/Delete file

 - object-key is in the format: {numberofdaytilexpired}/{uniqueID} . The s3 bucket lifecycle policy is configured base on prefix "numberofdaytilexpired" and thus we can trust s3 to do its clean up automatically.
 - If the object is tagged with "deleteondownload", the delete ajax calls is triggered automatically after user click download the file
 - Users always have option to delete the file manually after every download if deleteondownload is not set.


## Cryptography

All cryptography operations are implemented using using the Web Crypto API. Files are encrypted using AES-CBC 256-bit symmetric encryption. The encryption key is derived from the password and a random salt using PBKDF2 derivation with 10000 iterations of SHA256 hashing.

## Deploy your own

Backend can be deployed with terraform:
    - Go into `./terraform/` and copy terraform.tfvars.example to terraform.tfvars and add your own Virtus Total key as well as your AWS account ID
    - run `terraform apply` 
    - Note down the output which contains the API address for our frontend.
    - Modify `./frontend/assets/config.js` with the API address above

Now you just need to test it by hosting the frontend code somewhere. Note that webcrypto is ONLY AVAILABLE from "secure origin". Chrome requires the page to be loaded in "https" or from "localhost". to quickly test everything, you can try using python to host it locally `python3 -m http.server 8888` and visit localhost:8888 in the browser.


## License
This project is licensed under the GPL-3.0 open source license.


