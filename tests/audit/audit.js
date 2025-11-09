var CryptoJS = require("crypto-js");
var fs = require('fs');
var crypto = require('crypto');
const { exec } = require("child_process");

var key = CryptoJS.enc.Hex.parse("19af00f22368200dd52e17b21f02f782");
var iv = CryptoJS.enc.Hex.parse("60d271cf6d949194e2ab66347b286ddf");
// chemins — modifiez selon vos besoins ou utilisez process.argv[2]/[3]
var inputPath = process.argv[2] || './test2.bin';
var outputPath = process.argv[3] || './test2.bin.enc';

// lire le fichier en Buffer

// génère un fichier de la taille demandée rempli d'octets aléatoires
function generateRandomFile(path, sizeBytes) {
    var buf = crypto.randomBytes(sizeBytes);
    fs.writeFileSync(path, buf);
}

// si le fichier d'entrée n'existe pas, on le crée avec 1 Mo d'aléatoire (modifiable via argv[4])
if (!fs.existsSync(inputPath)) {
    var size = 1020 * 1024;
    generateRandomFile(inputPath, size);
}
else {
    generateRandomFile(inputPath, 1020 * 36);
}
var inputBuf = fs.readFileSync(inputPath);
// convertir Buffer en CryptoJS WordArray
function bufferToWordArray(buf) {
    var words = [], i = 0, len = buf.length;
    while (i < len) {
        words.push(
            ((buf[i    ] << 24) | ((buf[i+1]||0) << 16) | ((buf[i+2]||0) << 8) | (buf[i+3]||0)) >>> 0
        );
        i += 4;
    }
    return CryptoJS.lib.WordArray.create(words, len);
}

var wordArray = bufferToWordArray(inputBuf);

// chiffrer le contenu du fichier
var encrypted = CryptoJS.AES.encrypt(wordArray, key, {
    iv: iv,
    mode: CryptoJS.mode.CTR,
    padding: CryptoJS.pad.Pkcs7
});

// convertir CryptoJS WordArray en Buffer Node.js
function wordArrayToBuffer(wordArray) {
    var words = wordArray.words;
    var sigBytes = wordArray.sigBytes;
    var buf = Buffer.alloc(sigBytes);
    for (var i = 0; i < sigBytes; i++) {
        var word = words[i >>> 2];
        buf[i] = (word >>> (24 - (i % 4) * 8)) & 0xFF;
    }
    return buf;
}

// obtenir le ciphertext (WordArray) et l'écrire en octets bruts
var ciphertextWA = encrypted.ciphertext;
var ciphertextBuf = wordArrayToBuffer(ciphertextWA);
fs.writeFileSync(outputPath, ciphertextBuf);

exec("../../build/AES_CPP --encode --chaining=CTR --file='./test2.bin' --output='./test2_.bin.enc' --iv '60d271cf6d949194e2ab66347b286ddf' --key '19af00f22368200dd52e17b21f02f782' --meta")
//console.log(encrypted.toString()); // résultat en base64