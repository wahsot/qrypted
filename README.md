# qrypted
Encrypted rich text editor in Qt5 using Crypto++ as the backend.
Will implement Botan backend too, when there's time.

## User Interface
The front-end is mainly the QTextEdit widget, which enables rich text editing.

### Text censoring
It is useful to block out supersensitive details, such as passwords while you scroll through your document.
The censoring is implemented by setting the text highlight colour to the current text colour.
Onlookers will not be able to read your censored text fragments unless they are selected.
Copying and pasting censored text should work as normal.
The ~~Strikethrough~~ button in the formatting toolbar is used to toggle censoring for the current cursor.

### Cryptography Toolbar
The cryptography toolbar provides easy access to control the encryption scheme.
1. Password line edit
2. Digest algorithm selection
3. Cipher algorithm selection
4. Operation mode selection

## File Formats
Qrypted supports reading and writing text files.
All files are currently saved using UTF-8 encoding, however it is capable of loading any other codecs.
Choose the format from the file filter when opening or saving files:
- .txt Plain Text
- .htm .html HTML
- .xsi Cryptic, which requires password for encryption

### Cryptic Format
Currently serialises into XML data defined in [docs/Cryptic-V2.xsd](https://github.com/vasthu/qrypted/blob/master/docs/cryptic-V2.xsd).
Will probably change to DER later, but the element hierarchy should remain the same as follows.

1. **Header** provides comprehensive information to setup cryptography
  1. **Digest** SHA-1, SHA-256, SHA-512 …
  2. **Salt** Hexadecimal
  3. **IterationCount**
  4. **KeyLength** in bytes
  5. **Cipher** AES, Blowfish, Serpent, …
  6. **Method** CBC, CTR, GCM, …
  7. **InitialVector** Hexadecimal
2. **Payload** data can be split into many chunks using the following:
  - **Data** Base64
  - **HexData** Base16
3. **Trailer** additional data transformation details
  1. **Length**
  2. **Authentication** HMAC of pre-encrypted data, used for non-authenticating methods
  3. **Compression** Identity, GZip, ZLib
