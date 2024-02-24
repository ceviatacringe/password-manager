## Basics
This is a fully locally hosted password manager.
The user has to input a master password and a PIN to proceed.
Those two generate an encryption key that is used to securely store passwords.
That key is only stored in memory (while the script is running) for security reasons.
The passwords are stored in a file and location that the user chooses, in plaintext in a .txt format.
All of the passwords are encrypted and unusable right out of the txt file, they need to be decrypted.
If the master password + PIN is correct, the user can extract the passwords for a given service that they stored.

# UI Features
- An interactive menu input-based UI
- Added colors and console clearing for a better looking experience

## Security measures
- Uses AES in CFB (Cipher Feedback) mode for robust symmetric encryption, ensuring that your service passwords are securely encrypted before storage.
- Salt and pin added to combat rainbow tables
- Increased 'n' Factor computational complexity, having longer loading time in order to prevent brute forcing.
- Hides user password and pin input in the terminal, instead of displaying it as it's typed.

## Purpose and usage
I made this as a learning experiment and project to display my knowledge.
You can take my encryption and storage functions and alter the user interactions, in order to make the following:
- Website username + password combination manager
- Game log-in manager for clients like Riot Client, Steam, Epic games etc
- Automatic log-ins through APIs and macros

Some easy-to-add features would be:
- Copying the selected password to the clipboard
- Perhaps removing it from the clipboard once pasted
- Automatic log in with a macro (wait for a hotkey to be pressed then type user, tab, type password, enter)
