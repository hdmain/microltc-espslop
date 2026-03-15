# LTC Wallet – ESP32 key storage

This Arduino sketch runs on an **ESP32** and stores your Litecoin wallet key in **permanent memory (NVS)**. The key is encrypted with a password; data is only sent to the PC when the correct password is given.

## Hardware

- Any ESP32 board (e.g. ESP32-DevKitC) connected via USB.

## Setup

1. Install [Arduino IDE](https://www.arduino.cc/en/software) or [PlatformIO](https://platformio.org/).
2. Install the **ESP32** board support (e.g. **esp32 by Espressif**).
3. Open `esp32_ltc_wallet.ino`, select your ESP32 board and the correct COM port, then **Upload**.

## Serial protocol (115200 baud)

- **SAVE,`<base64_password>`,`<hex64_key>`**  
  Stores the 32-byte key encrypted with the password. Replies `OK` or `ERR,message`.

- **LOAD,`<base64_password>`**  
  If the password matches, decrypts the key and sends **KEY,`<hex64>`**. Otherwise `ERR,wrong password` or `ERR,no wallet stored`.

The PC app (LTC Wallet) sends the password as base64 so that special characters do not break the protocol.

## Usage with LTC Wallet app

1. Connect the ESP32 by USB and note the COM port (e.g. `COM3` on Windows, `/dev/ttyUSB0` on Linux). Close the Arduino Serial Monitor (or any other app using that port) before using the wallet app.
2. **Create wallet** in the app, then open **"ESP32 key storage"** → enter password → **Save to ESP32**. The key is stored on the ESP32 only after you do this.
3. To load on another PC (or after reinstalling): open **"Load wallet from ESP32"** → select COM port → enter the **same password** → **Load from ESP32**.

Security: the key is encrypted with AES-256-CBC (key = SHA256(password)); the password is never stored, only its hash for verification.
