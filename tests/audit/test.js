// test.js
const { File, Key, ChainingMethod, Padding } = require('../../build/aescpp_node.node'); // chemin vers ton .node

// Crée un fichier à encoder
const inputPath = 'test.txt';
const outputPath = 'test.enc';

// Crée un Key
const key = new Key('19af00f22368200dd52e17b21f02f782');

// Crée le wrapper File
const file = new File(inputPath, outputPath);

// Encode le fichier
file.encode(key, 'CBC');
console.log('Fichier encodé !');

// Decode le fichier
file.decode(key);
console.log('Fichier décodé !');

// Utilisation des enums
console.log('Chaining CBC:', ChainingMethod.CBC);
console.log('Padding PKcs7:', Padding.PKcs7);
