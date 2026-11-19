#include "command_shell.h"

#include <algorithm>
#include <exception>
#include <istream>
#include <ostream>
#include <sstream>
#include <utility>

namespace shell {
namespace {

void print_result(const Command& command, const Result& result, std::ostream& output) {
    switch (result.status) {
    case Status::ok:
        if (!result.output.empty()) {
            output << result.output;
            if (result.output.back() != '\n') {
                output << '\n';
            }
        }
        break;
    case Status::missing_file:
        if (command.operation == Operation::share) {
            output << "File ";
        }
        output << command.name << " doesn't exist\n";
        break;
    case Status::missing_user:
        output << "User " << command.target << " doesn't exist\n";
        break;
    case Status::directory_exists:
        output << "Directory already exists\n";
        break;
    case Status::forbidden:
        output << "Forbidden\n";
        break;
    case Status::storage_error:
        output << "Could not complete command\n";
        break;
    }
}

}  // namespace

std::optional<Command> parse_command(const std::string& line) {
    std::istringstream input(line);
    std::string word;
    input >> word;
    Command command{};
    if (word == "cd") {
        command.operation = Operation::cd;
    } else if (word == "pwd") {
        command.operation = Operation::pwd;
    } else if (word == "ls") {
        command.operation = Operation::ls;
    } else if (word == "cat") {
        command.operation = Operation::cat;
    } else if (word == "mkdir") {
        command.operation = Operation::mkdir;
    } else if (word == "mkfile") {
        command.operation = Operation::mkfile;
    } else if (word == "share") {
        command.operation = Operation::share;
    } else if (word == "adduser") {
        command.operation = Operation::adduser;
    } else if (word == "exit") {
        command.operation = Operation::exit;
    } else {
        return std::nullopt;
    }

    const bool takes_name = command.operation != Operation::pwd &&
        command.operation != Operation::ls && command.operation != Operation::exit;
    if (takes_name && !(input >> command.name)) {
        return std::nullopt;
    }
    if (command.operation == Operation::mkfile) {
        // getline preserves spaces in file contents. Remove the single
        // separator after the filename and keep any further spaces as data.
        std::getline(input, command.contents);
        if (!command.contents.empty()) {
            command.contents.erase(0, 1);
        }
        if (!std::all_of(command.contents.begin(), command.contents.end(), [](unsigned char c) {
                return c >= 32 && c <= 126;
            })) {
            return std::nullopt;
        }
        return command;
    }
    if (command.operation == Operation::share && !(input >> command.target)) {
        return std::nullopt;
    }
    std::string extra;
    if (input >> extra) {
        return std::nullopt;
    }
    return command;
}

void run(accounts::Session& session, std::istream& input, std::ostream& output,
         const FilesystemHandler& filesystem) {
    output << "Available commands\n";
    if (filesystem) {
        output << "cd <directory>\npwd\nls\ncat <filename>\n";
        output << "mkdir <directory_name>\nmkfile <filename> <contents>\n"
               << "share <filename> <username>\n";
    }
    if (session.is_admin()) {
        output << "adduser <username>\n";
    }
    output << "exit\n";

    for (std::string line; std::getline(input, line);) {
        const auto command = parse_command(line);
        if (!command) {
            output << "Invalid Command\n";
            continue;
        }
        if (command->operation == Operation::exit) {
            return;
        }
        if (command->operation == Operation::adduser) {
            if (!session.is_admin() || !accounts::valid_username(command->name)) {
                output << "Invalid Command\n";
                continue;
            }
            try {
                if (!accounts::add_user(session, command->name)) {
                    output << "User " << command->name << " already exists\n";
                }
            } catch (const std::exception&) {
                output << "Could not create user\n";
            }
            continue;
        }
        if (!filesystem) {
            output << "Invalid Command\n";
            continue;
        }
        try {
            print_result(*command, filesystem(session, *command), output);
        } catch (const std::exception&) {
            output << "Could not complete command\n";
        }
    }
}

}  // namespace shell
