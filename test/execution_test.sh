#!/bin/bash

# Testing read_write program
# Wrong input
./read_write -n -1 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Wrong input
./read_write -n 2 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Parameter not recognised
./read_write -n -1 -f error > /dev/null 2>&1
if [ $? -ne 254 ]; then
    echo "Error: result not expected a not recognised parameter"
    exit -1
fi

# Correct execution
./read_write -n 8 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: result not expected trying correct input 1"
    exit -1
fi

# Testing generate_hash program
# Wrong input
./generate_hash -f non_existing_file.txt > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Parameter not recognised
./generate_hash -n -1 > /dev/null 2>&1
if [ $? -ne 254 ]; then
    echo "Error: result with a not expected a not recognised parameter"
    exit -1
fi

# Correct execution
./generate_hash -f test.txt > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: result not expected trying correct input 2"
    exit -1
fi

# Correct execution
./generate_hash -t "Generating hash of current text" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: result with a not expected trying correct input"
    exit -1
fi

# Testing asymmetric program
# Wrong input
./asymmetric -f non_existing_file.txt > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Parameter not recognised
./asymmetric -n -1 > /dev/null 2>&1
if [ $? -ne 254 ]; then
    echo "Error: result not expected with a not recognised parameter"
    exit -1
fi

# Correct execution
./asymmetric -f test.txt > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: result not expected trying correct input 10"
    exit -1
fi

# Correct execution
./asymmetric -t "trying new input to encrypt" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: result not expected trying correct input 3"
    exit -1
fi

# Testing symmetric program
# Wrong input
./symmetric -f non_existing_file.txt > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Parameter not recognised
./symmetric -n -1 > /dev/null 2>&1
if [ $? -ne 254 ]; then
    echo "Error: result not expected with a not recognised parameter 3"
    exit -1
fi

# Can't use additional authenticated data on modes different to ccm or gcm
./symmetric -t "trying new input to encrypt" -m cbc -a test2.txt > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: result not expected trying correct input 4"
    exit -1
fi

# Correct execution
./symmetric -f test.txt -m aes> /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: result not expected trying correct input 11"
    exit -1
fi

./symmetric -t "trying new input to encrypt" -m cmac > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: result not expected trying correct input 5"
    exit -1
fi

./symmetric -t "trying new input to encrypt" -m ccm -d "Trying additional authenticated data" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: result not expected trying correct input 299"
    exit -1
fi

./symmetric -t "trying new input to encrypt" -m gcm -d "Trying additional authenticated data" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: result not expected trying correct input 7"
    exit -1
fi

# Testing pbkdf2 program
# Wrong input
./pbkdf2 -i 500 -n 3 -o 8 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Wrong input
./pbkdf2 -i 1000 -n 10 -o 3 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Error: result not expected trying wrong input 8"
    exit -1
fi

# Wrong input
./pbkdf2 -i 1000 -n 2 -o 6 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Parameter not recognised
./pbkdf2 -i 1000 -n 2 -o 8 -f fail.txt > /dev/null 2>&1
if [ $? -ne 254 ]; then
    echo "Error: result not expected with a not recognised parameter 2"
    exit -1
fi

# Correct execution
./pbkdf2 -i 1000 -n 9 -o 12 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: result not expected trying correct input 9"
    exit -1
fi

# Testing sign_verify program
# Wrong input
./sign_verify -f non_existing_file.txt -n 2 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Wrong input
./sign_verify -f test.txt -n 7 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Parameter not recognised
./sign_verify -f test.txt -i 1000 -n 2 > /dev/null 2>&1
if [ $? -ne 254 ]; then
    echo "Error: result not expected with a not recognised parameter 1"
    exit -1
fi

# Correct execution
./sign_verify -f test.txt -n 2 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: result not expected trying correct input 11"
    exit -1
fi

echo "All test passed succesfully!!"
exit 0
