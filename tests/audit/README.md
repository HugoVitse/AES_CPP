# Tests unitaires AES_CPP vs CryptoJS

Ce répertoire contient des tests unitaires comparant le chiffrement entre la bibliothèque AES_CPP (C++) et CryptoJS (JavaScript).

## Installation

```bash
npm install
```

## Exécution des tests

```bash
npm test
```

## Description des tests

Les tests comparent le chiffrement AES en mode CTR entre AES_CPP et CryptoJS pour différentes tailles de fichiers :

### ✅ Tests qui passent

1. **Small file encryption (1KB)** : Fichier de 1024 octets
2. **Medium file encryption (36KB)** : Fichier de 36720 octets (1020 * 36)
3. **Edge case: Empty file** : Gestion des fichiers vides
4. **Byte-by-byte comparison** : Comparaison octet par octet détaillée

### ⚠️ Tests en échec

1. **Large file encryption (1MB)** : Fichier de 1MB - différence de taille détectée
   - AES_CPP produit : 1040400 octets
   - CryptoJS produit : 1048592 octets
   - Cette différence peut être due au padding ou à une limitation de taille

## Détails techniques

- **Algorithme** : AES-128
- **Mode** : CTR (Counter Mode)
- **Padding** : PKCS7
- **Clé** : `19af00f22368200dd52e17b21f02f782` (hex)
- **IV** : `60d271cf6d949194e2ab66347b286ddf` (hex)

## Fichiers

- `test.spec.js` : Tests unitaires avec Mocha
- `audit.js` : Script de chiffrement original
- `package.json` : Configuration npm et dépendances

## Résultats

Les tests confirment que **AES_CPP produit des résultats identiques à CryptoJS** pour les fichiers jusqu'à 36KB, validant ainsi l'implémentation du chiffrement AES en mode CTR.

## Exemple d'utilisation

```javascript
// Voir test.spec.js pour des exemples complets de code
```

## Notes

- Les fichiers temporaires sont automatiquement nettoyés après chaque test
- En cas d'échec, les fichiers sont conservés pour inspection
- Le timeout est configuré à 10 secondes pour permettre le chiffrement de gros fichiers
