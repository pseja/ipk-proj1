# IPK Layer 4 Scanner - Changelog

## Implemented functionality
### TCP and UDP port scanning
- Supports scanning both TCP and UDP.
- Handles both IPv4 and IPv6 addresses.
- Outputs the status of the current scanner port.

### Command-line argument parsing
I implemented all the needed specifications.

### Network interface and address/ip handling
- Thanks to the networking functions, I implemented validation functions for all address types (functions `network_utils.h/isValid*`) instead of regex.
- Thanks to some of these functions I created a very good-looking interface printing function, which can be displayed by `./ipk-l4-scan`.

### Error handling
Because I took the IJC class last year, I could take my implementation of `error.c` and `error.h`, improve it, and use it for this assignment to print pretty error messages.

### Testing
Made an `argest.sh` script that can help me validate the program (README.md for a tutorial on how to run it).

## Known limitations
### Implementation by itself
Because I want to be able to use this project in the future, I didn't combine the TCP/UDP IPv4/IPv6 into one single function to make it all look pretty and perfect because I wanted to be able to look into the project and put the implementations side by side and see the differences between each implementation, this might get some points taken from me because of the duplicate code, but I think that it's better this way for learning and later coming back to this project and reminding myself of how it's done.

### TCP and UDP port scanning
- I couldn't figure out how to get the localhost scanning working. In Wireshark I could see the messages coming back to me with the correct response, but my program somehow didn't catch the messages with recvfrom().
- When scanning over the internet, the program somehow misrepresents some ports as filtered. But when the program is run for the second time, it catches all the ports with their correct status.

### Testing
- I didn't figure out how to implement automated testing for the scanning and make it reliable, so I didn't do it and did the scanning tests by myself with the help of Wireshark.

## Future improvements
- Add support for parallel scanning using threads for faster scanning.
- Automated scanning tests.
