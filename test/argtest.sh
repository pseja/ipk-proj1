#!/bin/bash
#
# Tests for 1. IPK project [2025]
# author: pseja
# Usage:
#     (1) Download the gist to your IPK projects test directory
#     (2) Then (for adding permission): chmod u+x test/argtest.sh
#     (3) Execute this command:         ./test/argtest.sh
#     (4) Debug :D

#     For Makefile enjoyers:
#     (3-1) Add this to your Makefile:  TARGET=ipk-l4-scan
#                                       test: $(TARGET)
#	                                        @./test/argtest.sh
#     (3-2) Run this command for compile and tests: make test

# color codes
GREEN="\033[0;32m"
RED="\033[0;31m"
NORMAL="\033[0m"

IPK_L4_SCAN="./ipk-l4-scan"
test_count=0
correct=0

run_test() {
    test_desc=$1
    test_args=$2
    expected_exit_code=$3

    echo -n -e "${test_count}. Running: ${IPK_L4_SCAN} ${test_args}\n" 

    $IPK_L4_SCAN $test_args >/dev/null 2>&1
    your_exit_code=$?
    
    if [[ "$your_exit_code" == "$expected_exit_code" ]]; then
        echo -e "${GREEN}[PASS]${NORMAL} ${test_desc}"
        correct=$((correct + 1))
    else
        echo -e "${RED}[FAIL]${NORMAL} ${test_desc}"
        echo "   Expected exit code: $expected_exit_code"
        echo "   Got exit code:      $actual_exit_code"
    fi
    test_count=$((test_count + 1))
}

# tests
run_test "List active interfaces" "-i" 0
run_test "Valid interface input but no target" "-i eth0" 1
run_test "Valid long option interface but no target" "--interface eth0" 1
run_test "Scan specific UDP ports" "-u 53,67 127.0.0.1" 0
run_test "Scan multiple TCP ports" "-t 80,443,8080 www.vutbr.cz" 0
run_test "Scan both TCP & UDP" "--pt 22 --pu 1-65535 2001:67c:1220:809::93e5:917" 0
run_test "Missing domain or IP" "-w 3000" 1
run_test "Invalid flag" "-i eth0 --invalidflag" 1

# print test results
if [[ "$correct" == "$test_count" ]]; then
    echo -e "\nPassed $correct / $test_count 🎉"
else
    echo -e "\nPassed $correct / $test_count"
fi

