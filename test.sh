#!/bin/bash

for (( i=1; i <= 104857600; i+=1 ))
do
    echo "*******************************"
    echo "File length is $i"
    dd if=/dev/urandom of=test bs=1 count=$i > /dev/null 2>&1
    
    ORIGINAL_SHA=$(sha256sum test)
    
    # test in file mode
    
    ./redupe -e test
    
    rm test
    
    ./redupe -d test.rd
    
    NEW_SHA=$(sha256sum test)
    
    if [ "$ORIGINAL_SHA" == "$NEW_SHA" ]
    then
        echo "FILE MODE OK"
    else
        echo "FILE MODE FAIL"
        break
    fi
    
    # ========================================
    # test in stream mode
    
    cat test | ./redupe -e > test.rd
    
    rm test
    
    cat test.rd | ./redupe -d > test
    
    NEW_SHA=$(sha256sum test)
    
    if [ "$ORIGINAL_SHA" == "$NEW_SHA" ]
    then
        echo "STREAM MODE OK"
    else
        echo "STREAM MODE FAIL"
        break
    fi

    echo "==============================="
    
done
    
rm test
rm test.rd
