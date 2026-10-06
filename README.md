# About this program

Unpacks the contents of a PKCS #12 file (certificates and private keys) and automatically place them at the correct place for use with the StrongSwan NetworkManager plugin on Fedora.

This tool is intended specifically for use with the StrongSwan NetworkManager plugin on Fedora only. Other configurations and distributions are not supported.

## How to use

1. Run `strongswan-certinstall <path to PKCS #12 file>` and enter the password when prompted.
2. Run `nm-connection-editor` and add a new StrongSwan connection.
3. Press the "Certificate file" chooser button under the Client section. In the file chooser dialog, press CTRL+L and paste the full path of the corresponding certificate (displayed during certificate installation) in the Location text box, then press Enter.
3. Repeat the previous step to select the private key.
