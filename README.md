## Relay Secret

Visit [https://relaysecret.surge.sh/](https://relaysecret.surge.sh/) to try it out.

This project has 3 parts:

 - The simple backend lambda function to generate signed url for user to upload, download and delete files from S3 
 - The frontend with half of the code took from [this project writen by meixler](https://github.com/meixler/web-browser-based-file-encryption-decryption/blob/master/web-browser-based-file-encryption-decryption.html) with some extra fetch calls sprinkel ontop to handle ajax calls to the lambda and upload/download from s3
 - The terraform code which deploy a lambda function, an api gateway and our encrypted s3 bucket with special CORs policy and expire rules to make it all work ;)

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


## License
This project is licensed under the GPL-3.0 open source license.


