CXX ?= g++
CPPFLAGS += -ICode -ICode/third_party
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic -Werror
LDFLAGS += -static
LDLIBS += -lcrypto -ldl -pthread

SOURCES = Code/accounts.cpp Code/command_shell.cpp Code/crypto_store.cpp Code/fs_schema.cpp Code/storage.cpp Code/vfs.cpp
OBJECTS = $(SOURCES:Code/%.cpp=.build/%.o)
UNIT_TESTS = schema_test storage_test wrap_test

.PHONY: all test clean
all: fileserver

fileserver: .build/main.o $(OBJECTS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

.build/%.o: Code/%.cpp
	@mkdir -p .build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

.build/%_test: Code/tests/%_test.cpp $(OBJECTS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

test: $(UNIT_TESTS:%=.build/%)
	@for test in $(UNIT_TESTS); do .build/$$test || exit $$?; done
	python3 -m unittest discover -s Code/tests -p 'test_*.py' -v

clean:
	rm -rf .build fileserver

-include .build/*.d
