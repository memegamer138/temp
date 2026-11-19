#include "command_shell.h"

#include <cassert>
#include <sstream>
#include <stdexcept>

int main() {
    const auto file = shell::parse_command("mkfile notes.txt   hello world  ");
    assert(file && file->contents == "  hello world  ");
    assert(shell::parse_command("mkfile empty")->contents.empty());
    assert(!shell::parse_command("share file"));
    assert(!shell::parse_command("pwd extra"));
    assert(!shell::parse_command("exit extra"));
    assert(!shell::parse_command("mkfile file content\twith-tab"));
    assert(!shell::parse_command(""));

    accounts::Session user;
    user.username = "alice";
    assert(!user.is_admin() && user.current_directory.empty());
    std::string written;
    int calls = 0;
    const shell::FilesystemHandler filesystem = [&](accounts::Session& session, const shell::Command& command) {
        ++calls;
        switch (command.operation) {
        case shell::Operation::cd:
            session.current_directory = {"personal"};
            return shell::Result{};
        case shell::Operation::pwd:
            return shell::Result{shell::Status::ok, "/personal"};
        case shell::Operation::mkfile:
            written = command.contents;
            return shell::Result{};
        case shell::Operation::cat:
            return shell::Result{shell::Status::missing_file, {}};
        case shell::Operation::share:
            return shell::Result{shell::Status::missing_user, {}};
        default:
            throw std::runtime_error("Storage error");
        }
    };
    std::istringstream commands(
        "cd /personal\npwd\nmkfile file   hello  \ncat missing\nshare file bob\n"
        "ls\nadduser mallory\nexit\n");
    std::ostringstream output;
    shell::run(user, commands, output, filesystem);
    assert(written == "  hello  ");
    assert(user.current_directory == std::vector<std::string>{"personal"});
    assert(output.str().find("/personal\nmissing doesn't exist\nUser bob doesn't exist\n") != std::string::npos);
    assert(output.str().find("Could not complete command\nInvalid Command\n") != std::string::npos);

    accounts::Session admin;
    admin.username = "admin";
    const int calls_before = calls;
    std::istringstream forbidden("mkdir dir\nmkfile file data\nshare file alice\nexit\n");
    std::ostringstream denied;
    shell::run(admin, forbidden, denied, filesystem);
    assert(calls == calls_before + 3);
    assert(denied.str().find("mkdir <directory_name>\n") != std::string::npos);
    assert(written == "data");
}
