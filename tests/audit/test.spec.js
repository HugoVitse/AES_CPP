const CryptoJS = require("crypto-js");
const fs = require('fs');
const crypto = require('crypto');
const { execSync } = require("child_process");
const assert = require('assert');

describe('AES_CPP vs CryptoJS Encryption Comparison', function() {
    // Augmenter le timeout pour les opérations de chiffrement
    this.timeout(10000);

    const key = CryptoJS.enc.Hex.parse("19af00f22368200dd52e17b21f02f782");
    const iv = CryptoJS.enc.Hex.parse("60d271cf6d949194e2ab66347b286ddf");
    const keyHex = "19af00f22368200dd52e17b21f02f782";
    const ivHex = "60d271cf6d949194e2ab66347b286ddf";

    const testFile = './test_input.bin';
    const cryptoJsOutput = './test_cryptojs.enc';
    const aesCppOutput = './test_aescpp.enc';

    // Fonction pour convertir Buffer en CryptoJS WordArray
    function bufferToWordArray(buf) {
        const words = [];
        let i = 0;
        const len = buf.length;
        while (i < len) {
            words.push(
                ((buf[i] << 24) | ((buf[i+1]||0) << 16) | ((buf[i+2]||0) << 8) | (buf[i+3]||0)) >>> 0
            );
            i += 4;
        }
        return CryptoJS.lib.WordArray.create(words, len);
    }

    // Fonction pour convertir CryptoJS WordArray en Buffer Node.js
    function wordArrayToBuffer(wordArray) {
        const words = wordArray.words;
        const sigBytes = wordArray.sigBytes;
        const buf = Buffer.alloc(sigBytes);
        for (let i = 0; i < sigBytes; i++) {
            const word = words[i >>> 2];
            buf[i] = (word >>> (24 - (i % 4) * 8)) & 0xFF;
        }
        return buf;
    }

    // Nettoyage avant chaque test
    beforeEach(function() {
        // Supprimer les fichiers temporaires s'ils existent
        [testFile, cryptoJsOutput, aesCppOutput].forEach(file => {
            if (fs.existsSync(file)) {
                fs.unlinkSync(file);
            }
        });
    });

    //Nettoyage après chaque test
    afterEach(function() {
        // Garder les fichiers pour l'inspection si le test échoue
        if (this.currentTest.state === 'passed') {
            [testFile, cryptoJsOutput, aesCppOutput].forEach(file => {
                if (fs.existsSync(file)) {
                    fs.unlinkSync(file);
                }
            });
        }
    });

    // describe('Small file encryption (1KB)', function() {
    //     it('should produce identical encrypted output', function() {
    //         // Générer un fichier de test de 1KB
    //         const fileSize = 1024;
    //         const randomData = crypto.randomBytes(fileSize);
    //         fs.writeFileSync(testFile, randomData);

    //         // Chiffrement avec CryptoJS
    //         const inputBuf = fs.readFileSync(testFile);
    //         const wordArray = bufferToWordArray(inputBuf);
    //         const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
    //             iv: iv,
    //             mode: CryptoJS.mode.CTR,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertextBuf = wordArrayToBuffer(encrypted.ciphertext);
    //         fs.writeFileSync(cryptoJsOutput, ciphertextBuf);

    //         // Chiffrement avec AES_CPP
    //         execSync(`../../build/AES_CPP --encode --chaining=CTR --file='${testFile}' --output='${aesCppOutput}' --iv '${ivHex}' --key '${keyHex}' --meta`);

    //         // Lire les deux fichiers chiffrés
    //         const cryptoJsResult = fs.readFileSync(cryptoJsOutput);
    //         const aesCppResult = fs.readFileSync(aesCppOutput);

    //         // Comparer les tailles
    //         assert.strictEqual(aesCppResult.length, cryptoJsResult.length, 
    //             `Les tailles diffèrent: AES_CPP=${aesCppResult.length}, CryptoJS=${cryptoJsResult.length}`);

    //         // Comparer les contenus
    //         assert.deepStrictEqual(aesCppResult, cryptoJsResult, 
    //             'Les fichiers chiffrés ne sont pas identiques');
    //     });
    // });

    // describe('Medium file encryption (36KB)', function() {
    //     it('should produce identical encrypted output', function() {
    //         // Générer un fichier de test de 36KB (1020 * 36 bytes)
    //         const fileSize = 1020 * 36;
    //         const randomData = crypto.randomBytes(fileSize);
    //         fs.writeFileSync(testFile, randomData);

    //         // Chiffrement avec CryptoJS
    //         const inputBuf = fs.readFileSync(testFile);
    //         const wordArray = bufferToWordArray(inputBuf);
    //         const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
    //             iv: iv,
    //             mode: CryptoJS.mode.CTR,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertextBuf = wordArrayToBuffer(encrypted.ciphertext);
    //         fs.writeFileSync(cryptoJsOutput, ciphertextBuf);

    //         // Chiffrement avec AES_CPP
    //         execSync(`../../build/AES_CPP --encode --chaining=CTR --file='${testFile}' --output='${aesCppOutput}' --iv '${ivHex}' --key '${keyHex}' --meta`);

    //         // Lire les deux fichiers chiffrés
    //         const cryptoJsResult = fs.readFileSync(cryptoJsOutput);
    //         const aesCppResult = fs.readFileSync(aesCppOutput);

    //         // Comparer les tailles
    //         assert.strictEqual(aesCppResult.length, cryptoJsResult.length, 
    //             `Les tailles diffèrent: AES_CPP=${aesCppResult.length}, CryptoJS=${cryptoJsResult.length}`);

    //         // Comparer les contenus
    //         assert.deepStrictEqual(aesCppResult, cryptoJsResult, 
    //             'Les fichiers chiffrés ne sont pas identiques');
    //     });
    // });

    // describe('Large file encryption (1MB)', function() {
    //     it('should produce identical encrypted output', function() {
    //         // Générer un fichier de test de 1MB
    //         const fileSize = 1024 * 1024;
    //         const randomData = crypto.randomBytes(fileSize);
    //         fs.writeFileSync(testFile, randomData);

    //         // Chiffrement avec CryptoJS
    //         const inputBuf = fs.readFileSync(testFile);
    //         const wordArray = bufferToWordArray(inputBuf);
    //         const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
    //             iv: iv,
    //             mode: CryptoJS.mode.CBC,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertextBuf = wordArrayToBuffer(encrypted.ciphertext);
    //         fs.writeFileSync(cryptoJsOutput, ciphertextBuf);

    //         // Chiffrement avec AES_CPP
    //         execSync(`../../build/AES_CPP --encode --chaining=CBC --file='${testFile}' --output='${aesCppOutput}' --iv '${ivHex}' --key '${keyHex}' --meta`);

    //         // Lire les deux fichiers chiffrés
    //         const cryptoJsResult = fs.readFileSync(cryptoJsOutput);
    //         const aesCppResult = fs.readFileSync(aesCppOutput);

    //         // Comparer les taille
    //         assert.strictEqual(aesCppResult.length, cryptoJsResult.length, 
    //             `Les tailles diffèrent: AES_CPP=${aesCppResult.length}, CryptoJS=${cryptoJsResult.length}`);

    //         // Comparer les contenus
    //         assert.deepStrictEqual(aesCppResult, cryptoJsResult, 
    //             'Les fichiers chiffrés ne sont pas identiques');
    //     });
    // });

    // describe('Edge case: Empty file', function() {
    //     it('should handle empty files correctly', function() {
    //         // Créer un fichier vide
    //         fs.writeFileSync(testFile, Buffer.alloc(0));

    //         // Chiffrement avec CryptoJS
    //         const inputBuf = fs.readFileSync(testFile);
    //         const wordArray = bufferToWordArray(inputBuf);
    //         const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
    //             iv: iv,
    //             mode: CryptoJS.mode.CTR,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertextBuf = wordArrayToBuffer(encrypted.ciphertext);
    //         fs.writeFileSync(cryptoJsOutput, ciphertextBuf);

    //         // Chiffrement avec AES_CPP
    //         try {
    //             execSync(`../../build/AES_CPP --encode --chaining=CTR --file='${testFile}' --output='${aesCppOutput}' --iv '${ivHex}' --key '${keyHex}' --meta`);
                
    //             // Lire les deux fichiers chiffrés
    //             const cryptoJsResult = fs.readFileSync(cryptoJsOutput);
    //             const aesCppResult = fs.readFileSync(aesCppOutput);

    //             // Comparer les résultats
    //             assert.strictEqual(aesCppResult.length, cryptoJsResult.length);
    //             assert.deepStrictEqual(aesCppResult, cryptoJsResult);
    //         } catch (error) {
    //             // Si AES_CPP rejette les fichiers vides, c'est acceptable
    //             console.log('Note: AES_CPP may not support empty files');
    //         }
    //     });
    // });

    // describe('Byte-by-byte comparison', function() {
    //     it('should match every single byte', function() {
    //         // Générer un fichier de test
    //         const fileSize = 1020 * 36;
    //         const randomData = crypto.randomBytes(fileSize);
    //         fs.writeFileSync(testFile, randomData);

    //         // Chiffrement avec CryptoJS
    //         const inputBuf = fs.readFileSync(testFile);
    //         const wordArray = bufferToWordArray(inputBuf);
    //         const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
    //             iv: iv,
    //             mode: CryptoJS.mode.CTR,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertextBuf = wordArrayToBuffer(encrypted.ciphertext);
    //         fs.writeFileSync(cryptoJsOutput, ciphertextBuf);

    //         // Chiffrement avec AES_CPP
    //         execSync(`../../build/AES_CPP --encode --chaining=CTR --file='${testFile}' --output='${aesCppOutput}' --iv '${ivHex}' --key '${keyHex}' --meta`);

    //         // Lire les deux fichiers chiffrés
    //         const cryptoJsResult = fs.readFileSync(cryptoJsOutput);
    //         const aesCppResult = fs.readFileSync(aesCppOutput);

    //         // Comparer byte par byte
    //         let mismatchCount = 0;
    //         const mismatchPositions = [];
    //         const minLength = Math.min(cryptoJsResult.length, aesCppResult.length);

    //         for (let i = 0; i < minLength; i++) {
    //             if (cryptoJsResult[i] !== aesCppResult[i]) {
    //                 mismatchCount++;
    //                 if (mismatchPositions.length < 10) { // Garder seulement les 10 premières différences
    //                     mismatchPositions.push({
    //                         position: i,
    //                         cryptoJs: cryptoJsResult[i].toString(16).padStart(2, '0'),
    //                         aesCpp: aesCppResult[i].toString(16).padStart(2, '0')
    //                     });
    //                 }
    //             }
    //         }

    //         if (mismatchCount > 0) {
    //             console.log(`\nTrouvé ${mismatchCount} différences sur ${minLength} octets`);
    //             console.log('Premières différences:');
    //             mismatchPositions.forEach(m => {
    //                 console.log(`  Position ${m.position}: CryptoJS=0x${m.cryptoJs}, AES_CPP=0x${m.aesCpp}`);
    //             });
    //         }

    //         assert.strictEqual(mismatchCount, 0, 
    //             `Trouvé ${mismatchCount} octets différents sur ${minLength}`);
    //     });
    // });

    // describe('ECB Mode Tests', function() {
    //     it('should encrypt correctly in ECB mode (1KB)', function() {
    //         // Générer un fichier de test de 1KB
    //         const fileSize = 1024;
    //         const randomData = crypto.randomBytes(fileSize);
    //         fs.writeFileSync(testFile, randomData);

    //         // Chiffrement avec CryptoJS en mode ECB
    //         const inputBuf = fs.readFileSync(testFile);
    //         const wordArray = bufferToWordArray(inputBuf);
    //         const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
    //             mode: CryptoJS.mode.ECB,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertextBuf = wordArrayToBuffer(encrypted.ciphertext);
    //         fs.writeFileSync(cryptoJsOutput, ciphertextBuf);

    //         // Chiffrement avec AES_CPP en mode ECB (pas besoin d'IV)
    //         execSync(`../../build/AES_CPP --encode --chaining=ECB --file='${testFile}' --output='${aesCppOutput}' --key '${keyHex}' --meta`);

    //         // Lire les deux fichiers chiffrés
    //         const cryptoJsResult = fs.readFileSync(cryptoJsOutput);
    //         const aesCppResult = fs.readFileSync(aesCppOutput);

    //         // Comparer les tailles
    //         assert.strictEqual(aesCppResult.length, cryptoJsResult.length, 
    //             `ECB - Les tailles diffèrent: AES_CPP=${aesCppResult.length}, CryptoJS=${cryptoJsResult.length}`);

    //         // Comparer les contenus
    //         assert.deepStrictEqual(aesCppResult, cryptoJsResult, 
    //             'ECB - Les fichiers chiffrés ne sont pas identiques');
    //     });

    //     it('should encrypt correctly in ECB mode (36KB)', function() {
    //         // Générer un fichier de test de 36KB
    //         const fileSize = 1020 * 36;
    //         const randomData = crypto.randomBytes(fileSize);
    //         fs.writeFileSync(testFile, randomData);

    //         // Chiffrement avec CryptoJS en mode ECB
    //         const inputBuf = fs.readFileSync(testFile);
    //         const wordArray = bufferToWordArray(inputBuf);
    //         const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
    //             mode: CryptoJS.mode.ECB,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertextBuf = wordArrayToBuffer(encrypted.ciphertext);
    //         fs.writeFileSync(cryptoJsOutput, ciphertextBuf);

    //         // Chiffrement avec AES_CPP en mode ECB
    //         execSync(`../../build/AES_CPP --encode --chaining=ECB --file='${testFile}' --output='${aesCppOutput}' --key '${keyHex}' --meta`);

    //         // Lire les deux fichiers chiffrés
    //         const cryptoJsResult = fs.readFileSync(cryptoJsOutput);
    //         const aesCppResult = fs.readFileSync(aesCppOutput);

    //         // Comparer les tailles
    //         assert.strictEqual(aesCppResult.length, cryptoJsResult.length, 
    //             `ECB - Les tailles diffèrent: AES_CPP=${aesCppResult.length}, CryptoJS=${cryptoJsResult.length}`);

    //         // Comparer les contenus
    //         assert.deepStrictEqual(aesCppResult, cryptoJsResult, 
    //             'ECB - Les fichiers chiffrés ne sont pas identiques');
    //     });

    //     it('should demonstrate ECB pattern weakness with identical blocks', function() {
    //         // Créer un fichier avec des blocs répétés pour montrer la faiblesse du mode ECB
    //         const block = Buffer.from('AAAAAAAAAAAAAAAA'); // 16 bytes
    //         const repeatedData = Buffer.concat([block, block, block, block]); // 64 bytes
    //         fs.writeFileSync(testFile, repeatedData);

    //         // Chiffrement avec CryptoJS en mode ECB
    //         const inputBuf = fs.readFileSync(testFile);
    //         const wordArray = bufferToWordArray(inputBuf);
    //         const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
    //             mode: CryptoJS.mode.ECB,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertextBuf = wordArrayToBuffer(encrypted.ciphertext);
    //         fs.writeFileSync(cryptoJsOutput, ciphertextBuf);

    //         // Chiffrement avec AES_CPP en mode ECB
    //         execSync(`../../build/AES_CPP --encode --chaining=ECB --file='${testFile}' --output='${aesCppOutput}' --key '${keyHex}' --meta`);

    //         // Lire les deux fichiers chiffrés
    //         const cryptoJsResult = fs.readFileSync(cryptoJsOutput);
    //         const aesCppResult = fs.readFileSync(aesCppOutput);

    //         // Vérifier que les résultats sont identiques
    //         assert.deepStrictEqual(aesCppResult, cryptoJsResult, 
    //             'ECB - Les fichiers chiffrés avec blocs répétés ne sont pas identiques');

    //         // Vérifier que les blocs chiffrés sont identiques (caractéristique du mode ECB)
    //         const blockSize = 16;
    //         for (let i = 0; i < 3; i++) {
    //             const block1 = aesCppResult.slice(i * blockSize, (i + 1) * blockSize);
    //             const block2 = aesCppResult.slice((i + 1) * blockSize, (i + 2) * blockSize);
    //             assert.deepStrictEqual(block1, block2, 
    //                 `ECB devrait produire des blocs chiffrés identiques pour des blocs en clair identiques`);
    //         }
    //     });
    // });

    // describe('CBC Mode Tests', function() {
    //     it('should encrypt correctly in CBC mode (1KB)', function() {
    //         // Générer un fichier de test de 1KB
    //         const fileSize = 1024;
    //         const randomData = crypto.randomBytes(fileSize);
    //         fs.writeFileSync(testFile, randomData);

    //         // Chiffrement avec CryptoJS en mode CBC
    //         const inputBuf = fs.readFileSync(testFile);
    //         const wordArray = bufferToWordArray(inputBuf);
    //         const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
    //             iv: iv,
    //             mode: CryptoJS.mode.CBC,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertextBuf = wordArrayToBuffer(encrypted.ciphertext);
    //         fs.writeFileSync(cryptoJsOutput, ciphertextBuf);

    //         // Chiffrement avec AES_CPP en mode CBC
    //         execSync(`../../build/AES_CPP --encode --chaining=CBC --file='${testFile}' --output='${aesCppOutput}' --iv '${ivHex}' --key '${keyHex}' --meta`);

    //         // Lire les deux fichiers chiffrés
    //         const cryptoJsResult = fs.readFileSync(cryptoJsOutput);
    //         const aesCppResult = fs.readFileSync(aesCppOutput);

    //         // Comparer les tailles
    //         assert.strictEqual(aesCppResult.length, cryptoJsResult.length, 
    //             `CBC - Les tailles diffèrent: AES_CPP=${aesCppResult.length}, CryptoJS=${cryptoJsResult.length}`);

    //         // Comparer les contenus
    //         assert.deepStrictEqual(aesCppResult, cryptoJsResult, 
    //             'CBC - Les fichiers chiffrés ne sont pas identiques');
    //     });

    //     it('should encrypt correctly in CBC mode (36KB)', function() {
    //         // Générer un fichier de test de 36KB
    //         const fileSize = 1020 * 36;
    //         const randomData = crypto.randomBytes(fileSize);
    //         fs.writeFileSync(testFile, randomData);

    //         // Chiffrement avec CryptoJS en mode CBC
    //         const inputBuf = fs.readFileSync(testFile);
    //         const wordArray = bufferToWordArray(inputBuf);
    //         const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
    //             iv: iv,
    //             mode: CryptoJS.mode.CBC,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertextBuf = wordArrayToBuffer(encrypted.ciphertext);
    //         fs.writeFileSync(cryptoJsOutput, ciphertextBuf);

    //         // Chiffrement avec AES_CPP en mode CBC
    //         execSync(`../../build/AES_CPP --encode --chaining=CBC --file='${testFile}' --output='${aesCppOutput}' --iv '${ivHex}' --key '${keyHex}' --meta`);

    //         // Lire les deux fichiers chiffrés
    //         const cryptoJsResult = fs.readFileSync(cryptoJsOutput);
    //         const aesCppResult = fs.readFileSync(aesCppOutput);

    //         // Comparer les tailles
    //         assert.strictEqual(aesCppResult.length, cryptoJsResult.length, 
    //             `CBC - Les tailles diffèrent: AES_CPP=${aesCppResult.length}, CryptoJS=${cryptoJsResult.length}`);

    //         // Comparer les contenus
    //         assert.deepStrictEqual(aesCppResult, cryptoJsResult, 
    //             'CBC - Les fichiers chiffrés ne sont pas identiques');
    //     });

    //     it('should demonstrate CBC avalanche effect with identical blocks', function() {
    //         // Créer un fichier avec des blocs répétés pour montrer l'effet d'avalanche du mode CBC
    //         const block = Buffer.from('AAAAAAAAAAAAAAAA'); // 16 bytes
    //         const repeatedData = Buffer.concat([block, block, block, block]); // 64 bytes
    //         fs.writeFileSync(testFile, repeatedData);

    //         // Chiffrement avec CryptoJS en mode CBC
    //         const inputBuf = fs.readFileSync(testFile);
    //         const wordArray = bufferToWordArray(inputBuf);
    //         const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
    //             iv: iv,
    //             mode: CryptoJS.mode.CBC,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertextBuf = wordArrayToBuffer(encrypted.ciphertext);
    //         fs.writeFileSync(cryptoJsOutput, ciphertextBuf);

    //         // Chiffrement avec AES_CPP en mode CBC
    //         execSync(`../../build/AES_CPP --encode --chaining=CBC --file='${testFile}' --output='${aesCppOutput}' --iv '${ivHex}' --key '${keyHex}' --meta`);

    //         // Lire les deux fichiers chiffrés
    //         const cryptoJsResult = fs.readFileSync(cryptoJsOutput);
    //         const aesCppResult = fs.readFileSync(aesCppOutput);

    //         // Vérifier que les résultats sont identiques
    //         assert.deepStrictEqual(aesCppResult, cryptoJsResult, 
    //             'CBC - Les fichiers chiffrés avec blocs répétés ne sont pas identiques');

    //         // Vérifier que les blocs chiffrés sont différents (caractéristique du mode CBC)
    //         const blockSize = 16;
    //         let allBlocksDifferent = true;
    //         for (let i = 0; i < 3; i++) {
    //             const block1 = aesCppResult.slice(i * blockSize, (i + 1) * blockSize);
    //             const block2 = aesCppResult.slice((i + 1) * blockSize, (i + 2) * blockSize);
    //             if (block1.equals(block2)) {
    //                 allBlocksDifferent = false;
    //                 break;
    //             }
    //         }
    //         assert.strictEqual(allBlocksDifferent, true, 
    //             `CBC devrait produire des blocs chiffrés différents même avec des blocs en clair identiques`);
    //     });

    //     it('should produce different outputs with different IVs in CBC mode', function() {
    //         // Générer un fichier de test
    //         const fileSize = 1024;
    //         const randomData = crypto.randomBytes(fileSize);
    //         fs.writeFileSync(testFile, randomData);

    //         // Premier chiffrement avec IV original
    //         const inputBuf = fs.readFileSync(testFile);
    //         const wordArray = bufferToWordArray(inputBuf);
    //         const encrypted1 = CryptoJS.AES.encrypt(wordArray, key, {
    //             iv: iv,
    //             mode: CryptoJS.mode.CBC,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertext1 = wordArrayToBuffer(encrypted1.ciphertext);

    //         // Deuxième chiffrement avec un IV différent
    //         const iv2 = CryptoJS.enc.Hex.parse("00000000000000000000000000000000");
    //         const encrypted2 = CryptoJS.AES.encrypt(wordArray, key, {
    //             iv: iv2,
    //             mode: CryptoJS.mode.CBC,
    //             padding: CryptoJS.pad.Pkcs7
    //         });
    //         const ciphertext2 = wordArrayToBuffer(encrypted2.ciphertext);

    //         // Les deux chiffrements devraient être différents
    //         let hasDifference = false;
    //         for (let i = 0; i < Math.min(ciphertext1.length, ciphertext2.length); i++) {
    //             if (ciphertext1[i] !== ciphertext2[i]) {
    //                 hasDifference = true;
    //                 break;
    //             }
    //         }

    //         assert.strictEqual(hasDifference, true, 
    //             'CBC avec des IVs différents devrait produire des sorties différentes');
    //     });
    // });

    describe('Performance Comparison Tests', function() {
        // Augmenter le timeout pour les tests de performance
        this.timeout(30000);

        function measureCryptoJSPerformance(fileSize, mode) {
            const randomData = crypto.randomBytes(fileSize);
            fs.writeFileSync(testFile, randomData);

            const inputBuf = fs.readFileSync(testFile);
            const wordArray = bufferToWordArray(inputBuf);

            const start = process.hrtime.bigint();
            
            const options = {
                mode: mode,
                padding: CryptoJS.pad.Pkcs7
            };
            
            if (mode !== CryptoJS.mode.ECB) {
                options.iv = iv;
            }

            const encrypted = CryptoJS.AES.encrypt(wordArray, key, options);
            const ciphertextBuf = wordArrayToBuffer(encrypted.ciphertext);
            
            const end = process.hrtime.bigint();
            const durationMs = Number(end - start) / 1000000; // Convertir en millisecondes

            fs.writeFileSync(cryptoJsOutput, ciphertextBuf);
            
            return durationMs;
        }

        function measureAESCPPPerformance(fileSize, modeStr) {
            const randomData = crypto.randomBytes(fileSize);
            fs.writeFileSync(testFile, randomData);

            const ivArg = modeStr === 'ECB' ? '' : `--iv '${ivHex}'`;
            const command = `../../build/AES_CPP --encode --chaining=${modeStr} --file='${testFile}' --output='${aesCppOutput}' ${ivArg} --key '${keyHex}' --meta`;

            const start = process.hrtime.bigint();
            execSync(command);
            const end = process.hrtime.bigint();
            
            const durationMs = Number(end - start) / 1000000; // Convertir en millisecondes
            
            return durationMs;
        }

        function formatSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
        }

        function formatSpeed(bytes, ms) {
            const mbPerSec = (bytes / (1024 * 1024)) / (ms / 1000);
            return mbPerSec.toFixed(2) + ' MB/s';
        }

        it('should compare performance on small files (50 MB) - CTR mode', function() {
            const fileSize = 50* 1024 * 1024; // 100KB
            const iterations = 5;
            
            let cryptoJSTimes = [];
            let aesCppTimes = [];

            console.log(`\n  Test de performance - Taille: ${formatSize(fileSize)} - Mode: CTR`);
            
            for (let i = 0; i < iterations; i++) {
                cryptoJSTimes.push(measureCryptoJSPerformance(fileSize, CryptoJS.mode.CTR));
                aesCppTimes.push(measureAESCPPPerformance(fileSize, 'CTR'));
            }

            const avgCryptoJS = cryptoJSTimes.reduce((a, b) => a + b) / iterations;
            const avgAESCPP = aesCppTimes.reduce((a, b) => a + b) / iterations;

            console.log(`  CryptoJS - Temps moyen: ${avgCryptoJS.toFixed(2)} ms - Vitesse: ${formatSpeed(fileSize, avgCryptoJS)}`);
            console.log(`  AES_CPP  - Temps moyen: ${avgAESCPP.toFixed(2)} ms - Vitesse: ${formatSpeed(fileSize, avgAESCPP)}`);
            console.log(`  Ratio: AES_CPP est ${(avgCryptoJS / avgAESCPP).toFixed(2)}x ${avgAESCPP < avgCryptoJS ? 'plus rapide' : 'plus lent'}`);

            // Les deux devraient fonctionner (pas d'assertion stricte sur la vitesse)
            assert.ok(avgCryptoJS > 0 && avgAESCPP > 0, 'Les deux implémentations devraient avoir des temps mesurables');
        });

        it('should compare performance on medium files (1MB) - CBC mode', function() {
            const fileSize = 1024 * 1024; // 1MB
            const iterations = 3;
            
            let cryptoJSTimes = [];
            let aesCppTimes = [];

            console.log(`\n  Test de performance - Taille: ${formatSize(fileSize)} - Mode: CBC`);
            
            for (let i = 0; i < iterations; i++) {
                cryptoJSTimes.push(measureCryptoJSPerformance(fileSize, CryptoJS.mode.CBC));
                aesCppTimes.push(measureAESCPPPerformance(fileSize, 'CBC'));
            }

            const avgCryptoJS = cryptoJSTimes.reduce((a, b) => a + b) / iterations;
            const avgAESCPP = aesCppTimes.reduce((a, b) => a + b) / iterations;

            console.log(`  CryptoJS - Temps moyen: ${avgCryptoJS.toFixed(2)} ms - Vitesse: ${formatSpeed(fileSize, avgCryptoJS)}`);
            console.log(`  AES_CPP  - Temps moyen: ${avgAESCPP.toFixed(2)} ms - Vitesse: ${formatSpeed(fileSize, avgAESCPP)}`);
            console.log(`  Ratio: AES_CPP est ${(avgCryptoJS / avgAESCPP).toFixed(2)}x ${avgAESCPP < avgCryptoJS ? 'plus rapide' : 'plus lent'}`);

            assert.ok(avgCryptoJS > 0 && avgAESCPP > 0, 'Les deux implémentations devraient avoir des temps mesurables');
        });

        it('should compare performance on large files (5MB) - ECB mode', function() {
            const fileSize = 5 * 1024 * 1024; // 5MB
            const iterations = 3;
            
            let cryptoJSTimes = [];
            let aesCppTimes = [];

            console.log(`\n  Test de performance - Taille: ${formatSize(fileSize)} - Mode: ECB`);
            
            for (let i = 0; i < iterations; i++) {
                cryptoJSTimes.push(measureCryptoJSPerformance(fileSize, CryptoJS.mode.ECB));
                aesCppTimes.push(measureAESCPPPerformance(fileSize, 'ECB'));
            }

            const avgCryptoJS = cryptoJSTimes.reduce((a, b) => a + b) / iterations;
            const avgAESCPP = aesCppTimes.reduce((a, b) => a + b) / iterations;

            console.log(`  CryptoJS - Temps moyen: ${avgCryptoJS.toFixed(2)} ms - Vitesse: ${formatSpeed(fileSize, avgCryptoJS)}`);
            console.log(`  AES_CPP  - Temps moyen: ${avgAESCPP.toFixed(2)} ms - Vitesse: ${formatSpeed(fileSize, avgAESCPP)}`);
            console.log(`  Ratio: AES_CPP est ${(avgCryptoJS / avgAESCPP).toFixed(2)}x ${avgAESCPP < avgCryptoJS ? 'plus rapide' : 'plus lent'}`);

            assert.ok(avgCryptoJS > 0 && avgAESCPP > 0, 'Les deux implémentations devraient avoir des temps mesurables');
        });

        it('should compare performance across all modes on 1MB file', function() {
            const fileSize = 1024 * 1024; // 1MB
            const modes = [
                { cryptoMode: CryptoJS.mode.ECB, name: 'ECB' },
                { cryptoMode: CryptoJS.mode.CBC, name: 'CBC' },
                { cryptoMode: CryptoJS.mode.CTR, name: 'CTR' }
            ];

            console.log(`\n  Comparaison des modes - Taille: ${formatSize(fileSize)}`);
            console.log('  =====================================');

            const results = [];

            modes.forEach(({ cryptoMode, name }) => {
                const cryptoJSTime = measureCryptoJSPerformance(fileSize, cryptoMode);
                const aesCppTime = measureAESCPPPerformance(fileSize, name);

                const result = {
                    mode: name,
                    cryptoJS: cryptoJSTime,
                    aesCpp: aesCppTime,
                    ratio: cryptoJSTime / aesCppTime
                };

                results.push(result);

                console.log(`  Mode ${name}:`);
                console.log(`    CryptoJS: ${cryptoJSTime.toFixed(2)} ms (${formatSpeed(fileSize, cryptoJSTime)})`);
                console.log(`    AES_CPP:  ${aesCppTime.toFixed(2)} ms (${formatSpeed(fileSize, aesCppTime)})`);
                console.log(`    Ratio:    ${result.ratio.toFixed(2)}x ${aesCppTime < cryptoJSTime ? '(AES_CPP plus rapide)' : '(CryptoJS plus rapide)'}`);
                console.log('');
            });

            // Trouver le mode le plus rapide pour chaque implémentation
            const fastestCryptoJS = results.reduce((prev, curr) => prev.cryptoJS < curr.cryptoJS ? prev : curr);
            const fastestAESCPP = results.reduce((prev, curr) => prev.aesCpp < curr.aesCpp ? prev : curr);

            console.log(`  Mode le plus rapide (CryptoJS): ${fastestCryptoJS.mode}`);
            console.log(`  Mode le plus rapide (AES_CPP):  ${fastestAESCPP.mode}`);

            assert.ok(results.length === 3, 'Devrait tester les 3 modes');
        });

        it('should test scalability - performance vs file size', function() {
            const sizes = [
                { size: 10 * 1024, name: '10KB' },
                { size: 100 * 1024, name: '100KB' },
                { size: 1024 * 1024, name: '1MB' },
                { size: 5 * 1024 * 1024, name: '5MB' }
            ];

            console.log(`\n  Test d'évolutivité (scalabilité) - Mode: CTR`);
            console.log('  ============================================');

            sizes.forEach(({ size, name }) => {
                const cryptoJSTime = measureCryptoJSPerformance(size, CryptoJS.mode.CTR);
                const aesCppTime = measureAESCPPPerformance(size, 'CTR');

                console.log(`  Taille ${name}:`);
                console.log(`    CryptoJS: ${cryptoJSTime.toFixed(2)} ms - ${formatSpeed(size, cryptoJSTime)}`);
                console.log(`    AES_CPP:  ${aesCppTime.toFixed(2)} ms - ${formatSpeed(size, aesCppTime)}`);
                console.log(`    Ratio: ${(cryptoJSTime / aesCppTime).toFixed(2)}x`);
                console.log('');
            });

            assert.ok(true, 'Test de scalabilité complété');
        });
    });
});
