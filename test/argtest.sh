#!/bin/bash
#
# Tests for 1. IPK project [2025]
# author: pseja
# Usage:
#     (1) Download the gist to your IPK projects test directory
#     (2) Then (for adding permission): chmod u+x test/argtest.sh
#     (3) Execute this command:         ./test/argtest.sh
#     (4) Debug :D
#
#     For Makefile enjoyers:
#     (3-1) Add this to your Makefile:  TARGET=ipk-l4-scan
#                                       test: $(TARGET)
#	                                        @./test/argtest.sh
#     (3-2) Run this command for compile and tests: make test

# color codes
GREEN="\033[0;32m"
RED="\033[0;31m"
NORMAL="\033[0m"

# change this based on your valid interface
VALID_INTERFACE="wlo1"

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
        echo "   Expected exit code: ${expected_exit_code}"
        echo "   Got exit code:      ${your_exit_code}"
    fi
    test_count=$((test_count + 1))
}

# tests
## assignment tests
run_test "Execution Examples 1" "--interface ${VALID_INTERFACE} -u 53,67 2001:67c:1220:809::93e5:917" 0
run_test "Execution Examples 2" "-i ${VALID_INTERFACE} -w 1000 -t 80,443,8080 www.vutbr.cz" 0

run_test "Functionality Illustration" "-i ${VALID_INTERFACE} --pt 21,22,143 --pu 53,67 localhost" 0

## basic tests
run_test "List active interfaces - no parameters" "" 0
run_test "List active interfaces - interface flag without an argument" "-i" 0

run_test "Valid interface input but no target" "-i ${VALID_INTERFACE}" 1
run_test "Valid long option interface but no target" "--interface ${VALID_INTERFACE}" 1

run_test "Scan specific UDP ports - interface not specified" "-u 53,67 127.0.0.1" 1
run_test "Scan multiple TCP ports - interface not specified" "-t 80,443,8080 www.vutbr.cz" 1
run_test "Scan specific UDP ports" "-i ${VALID_INTERFACE} -u 53,67 127.0.0.1" 0
run_test "Scan multiple TCP ports" "-i ${VALID_INTERFACE} -t 80,443,8080 www.vutbr.cz" 0

run_test "Scan specific long option UDP ports - interface not specified" "--pu 53,67 127.0.0.1" 1
run_test "Scan multiple long option TCP ports - interface not specified" "--pt 80,443,8080 www.vutbr.cz" 1
run_test "Scan specific long option UDP ports" "-i ${VALID_INTERFACE} --pu 53,67 127.0.0.1" 0
run_test "Scan multiple long option TCP ports" "-i ${VALID_INTERFACE} --pt 80,443,8080 www.vutbr.cz" 0
run_test "Scan both TCP & UDP" "-i ${VALID_INTERFACE} --pt 22 --pu 1-65535 2001:67c:1220:809::93e5:917" 0

run_test "Missing domain or IP" "-i ${VALID_INTERFACE} -w 3000 -u 80,443" 1
run_test "Extra domain or IP" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 www.fit.cz www.vut.cz" 1

run_test "Invalid timeout - negative value" "-i ${VALID_INTERFACE} -w -3000 -u 80,443 www.fit.cz" 1
run_test "Invalid timeout - zero value" "-i ${VALID_INTERFACE} -w 0 -u 80,443 www.fit.cz" 1
run_test "Invalid timeout - no value" "-i ${VALID_INTERFACE} -w -u 80,443 www.fit.cz" 1

run_test "Invalid flag" "-i ${VALID_INTERFACE} --invalidflag -u 80,443 www.vut.cz" 1
run_test "Invalid long flag" "-i ${VALID_INTERFACE} -x -u 80,443 www.vut.cz" 1

run_test "Different argument sequence 1" "-u 53,67 -i ${VALID_INTERFACE} 127.0.0.1" 0
run_test "Different argument sequence 2" "127.0.0.1 -i ${VALID_INTERFACE} -u 53,67" 0
run_test "Different argument sequence 3" "-t 80,443,8080 -i ${VALID_INTERFACE} www.vutbr.cz" 0
run_test "Different argument sequence 4" "www.vutbr.cz -i ${VALID_INTERFACE} -t 80,443,8080" 0

## advanced tests
### IPv4
#### valid
run_test "Valid IPv4 - standard" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 192.168.1.1" 0
run_test "Valid IPv4 - broadcast" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 255.255.255.255" 0
run_test "Valid IPv4 - loopback" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 127.0.0.1" 0
run_test "Valid IPv4 - loopback as text" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 localhost" 0
run_test "Valid IPv4 - zero Address" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 0.0.0.0" 0

#### invalid
run_test "Invalid IPv4 - too many octets" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 192.168.1.1.1" 1
run_test "Invalid IPv4 - octet out of range" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 256.100.50.25" 1
run_test "Invalid IPv4 - negative value" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 -1.0.0.1" 1
run_test "Invalid IPv4 - missing octets" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 192.168.1" 1
run_test "Invalid IPv4 - letters in address" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 192.abc.1.1" 1

### IPv6
#### valid
run_test "Valid IPv6 address - full, standard notation" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 2001:0db8:85a3:0000:0000:8a2e:0370:7334" 0
run_test "Valid IPv6 address - compressed notation" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 2001:db8:85a3::8a2e:370:7334" 0
run_test "Valid IPv6 address - loopback address, fully compressed" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 ::1" 0
run_test "Valid IPv6 address - unspecified address, fully compressed" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 ::" 0
run_test "Valid IPv6 address - link-local address" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 fe80::1ff:fe23:4567:890a" 0
run_test "Valid IPv6 address - mix of compressed and expanded notation" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 2001:0:9d38:6ab8:27:0:abcd:1234" 0
run_test "Valid IPv6 address - IPv4-mapped address" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 ::ffff:192.168.1.1" 0

#### invalid
run_test "Invalid IPv6 address - too many colons together" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 2001:db8:85a3:::8a2e:370:7334" 1
run_test "Invalid IPv6 address - multiple double colons 1" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 2001::85a3::8a2e:370:7334" 1
run_test "Invalid IPv6 address - multiple double colons 2" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 1200::AB00:1234::2552:7777:1313" 1
run_test "Invalid IPv6 address - invalid hex character \"gggg\"" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 2001:db8:85a3:gggg:0000:8a2e:0370:7334" 1
run_test "Invalid IPv6 address - segment has more than four hex digits" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 12345::1" 1
run_test "Invalid IPv6 address - too many segments (more than 8)" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 2001:db8:85a3:0000:0000:8a2e:0370:7334:1234" 1
run_test "Invalid IPv6 address - invalid IPv4 part, \"999\" is out of range 0-255" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 ::192.168.1.999" 1

### URL
#### valid
run_test "Valid URL - standard HTTP" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 http://example.com" 0
run_test "Valid URL - standard HTTPS" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 https://example.com" 0
run_test "Valid URL - subdomain" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 https://sub.example.com" 0
run_test "Valid URL - with port" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 https://example.com:8080" 0
run_test "Valid URL - with path" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 https://example.com/path/to/page" 0
run_test "Valid URL - with query params" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 https://example.com/search?q=test" 0

#### invalid
run_test "Invalid URL - missing TLD" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 http://example" 1
run_test "Invalid URL - spaces in URL" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 http://exa mple.com" 1
run_test "Invalid URL - no scheme" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 example.com" 1
run_test "Invalid URL - invalid characters" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 http://exa*ample.com" 1
run_test "Invalid URL - empty URL" "-i ${VALID_INTERFACE} -w 3000 -u 80,443 " 1

# print test results
if [[ "$correct" == "$test_count" ]]; then
    echo -e "\nPassed $correct / $test_count 🎉"
else
    echo -e "\nPassed $correct / $test_count"
fi

