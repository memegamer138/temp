#pragma once

#include "accounts.h"

#include <functional>
#include <iosfwd>
#include <optional>
#include <string>

namespace shell {

enum class Operation { cd, pwd, ls, cat, mkdir, mkfile, share, adduser, exit };

struct Command {
    Operation operation;
    std::string name;
    std::string target;
    std::string contents;
};

enum class Status { ok, missing_file, missing_user, directory_exists, forbidden, storage_error };

struct Result {
    Status status = Status::ok;
    std::string output;
};

// The filesystem team connects its implementation through this function.
// It receives validated command syntax and checks paths and object permissions.
using FilesystemHandler = std::function<Result(accounts::Session&, const Command&)>;

std::optional<Command> parse_command(const std::string& line);
void run(accounts::Session& session, std::istream& input, std::ostream& output,
         const FilesystemHandler& filesystem = {});

}  // namespace shell
