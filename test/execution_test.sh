#!/bin/bash

# Testing read_write program
# Wrong input
result=$(./../read_write -n -1)
if [ $result -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Parameter not recognised
result=$(./../read_write -n -1 -f error)
if [ $result -ne -2 ]; then
    echo "Error: result not expected a not recognised parameter"
    exit -1
fi

# Correct execution
result=$(./../read_write -n 2)
if [ $result -ne 0 ]; then
    echo "Error: result not expected trying correct input"
    exit -1
fi

# Testing generate_hash program
# Wrong input
result=$(./../generate_hash -f non_existing_file.txt)
if [ $result -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Parameter not recognised
result=$(./../generate_hash -n -1)
if [ $result -ne -2 ]; then
    echo "Error: result with a not expected a not recognised parameter"
    exit -1
fi

# Correct execution
result=$(./../generate_hash -f test.txt)
if [ $result -ne 0 ]; then
    echo "Error: result not expected trying correct input"
    exit -1
fi

# Correct execution
result=$(./../generate_hash -t "Generating hash of current text")
if [ $result -ne 0 ]; then
    echo "Error: result with a not expected trying correct input"
    exit -1
fi

# Testing asymmetric program
# Wrong input
result=$(./../asymmetric -f non_existing_file.txt)
if [ $result -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Parameter not recognised
result=$(./../asymmetric -n -1)
if [ $result -ne -2 ]; then
    echo "Error: result not expected with a not recognised parameter"
    exit -1
fi

# Correct execution
result=$(./../asymmetric -f test.txt)
if [ $result -ne 0 ]; then
    echo "Error: result not expected trying correct input"
    exit -1
fi

# Correct execution
result=$(./../asymmetric -t "trying new input to encrypt")
if [ $result -ne 0 ]; then
    echo "Error: result not expected trying correct input"
    exit -1
fi

# Testing symmetric program
# Wrong input
result=$(./../symmetric -f non_existing_file.txt)
if [ $result -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Parameter not recognised
result=$(./../symmetric -n -1)
if [ $result -ne -2 ]; then
    echo "Error: result not expected with a not recognised parameter"
    exit -1
fi

# Can't use additional authenticated data on modes different to ccm or gcm
result=$(./../symmetric -t "trying new input to encrypt" -m cbc -a test2.txt)
if [ $result -ne -1 ]; then
    echo "Error: result not expected trying correct input"
    exit -1
fi

# Correct execution
result=$(./../symmetric -f test.txt)
if [ $result -ne 0 ]; then
    echo "Error: result not expected trying correct input"
    exit -1
fi

result=$(./../symmetric -t "trying new input to encrypt")
if [ $result -ne 0 ]; then
    echo "Error: result not expected trying correct input"
    exit -1
fi

result=$(./../symmetric -t "trying new input to encrypt" -m ccm -d "Trying additional authenticated data")
if [ $result -ne 0 ]; then
    echo "Error: result not expected trying correct input"
    exit -1
fi

result=$(./../symmetric -t "trying new input to encrypt" -m gcm -d "Trying additional authenticated data")
if [ $result -ne 0 ]; then
    echo "Error: result not expected trying correct input"
    exit -1
fi
# Testing pbkdf2 program
# Wrong input
result=$(./../pbkdf2 -i 500 -n 3 -o 8)
if [ $result -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Wrong input
result=$(./../pbkdf2 -i 1000 -n 10 -o 3)
if [ $result -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Wrong input
result=$(./../pbkdf2 -i 1000 -n 2 -o 6)
if [ $result -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Parameter not recognised
result=$(./../pbkdf2 -i 1000 -n 2 -o 8 -f fail.txt)
if [ $result -ne -2 ]; then
    echo "Error: result not expected with a not recognised parameter"
    exit -1
fi

# Correct execution
result=$(./../pbkdf2 -i 1000 -n 7 -o 12)
if [ $result -ne 0 ]; then
    echo "Error: result not expected trying correct input"
    exit -1
fi

# Testing sign_verify program
# Wrong input
result=$(./../sign_verify -f non_existing_file.txt -n 2)
if [ $result -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Wrong input
result=$(./../sign_verify -f test.txt -n 7)
if [ $result -eq 0 ]; then
    echo "Error: result not expected trying wrong input"
    exit -1
fi

# Parameter not recognised
result=$(./../sign_verify -f test.txt -i 1000 -n 2)
if [ $result -ne -2 ]; then
    echo "Error: result not expected with a not recognised parameter"
    exit -1
fi

# Correct execution
result=$(./../sign_verify -f test.txt -n 2)
if [ $result -ne 0 ]; then
    echo "Error: result not expected trying correct input"
    exit -1
fi

echo "All test passed succesfully!!"
exit 0
