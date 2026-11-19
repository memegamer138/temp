#include "accounts.h"
#include "command_shell.h"
#include "vfs_interfaces.h"

#include <exception>
#include <iostream>

int main(int argc, char* argv[]) {
    // argc counts the program name too. For ./fileserver alice_keyfile,
    // argc is 2 and argv[1] holds the path to Alice's keyfile.
    accounts::Session session;
    try {
        // || stops at the first true condition, so argv[1] is only read
        // after we know a single argument was supplied.
        if (argc != 2 || argv[1][0] == '\0') {
            std::cout << "Invalid keyfile\n";
            return 1;
        }
        session = accounts::login(argv[1]);
    } catch (const std::exception&) {
        // Any login error ends the program before the command loop starts.
        std::cout << "Invalid keyfile\n";
        return 1;
    }

    std::cout << "Logged in as " << session.username << '\n';
    shell::run(session, std::cin, std::cout,
               [](accounts::Session& active, const shell::Command& command) {
                   return vfs::execute(active, command);
               });
}
