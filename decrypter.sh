#!/bin/bash

reciptients=( "bartong2" "fricken" "tjones" "ander551" "dinkels" "clevelj3" "ferreri" )

declare -A keypath

keypath["./keys/dinkels/rsa_public_dinkels.pem"]=dinkels
keypath["./keys/bartong2/rsa_public_bartong2.pem"]=bartong2
keypath["./keys/fricken/rsa_public_fricken.pem"]=fricken
keypath["./keys/tjones/rsa_public_tjones.pem"]=tjones
keypath["./keys/ander551/rsa_public_ander551.pem"]=ander551
keypath["./keys/clevelj3/rsa_public_clevelj3.pem"]=clevelj3
keypath["./keys/ferreri/rsa_public_ferreri.pem"]=ferreri

received_keys=( "fricken_dataset.txt" "tjones_dataset.txt" "ferreri_dataset.txt" "bartong2_dataset.txt"  "clevelj3_dataset.txt" "dinkels_dataset.txt" "ander551_dataset.txt" )

decrypt(){
    for i in ${reciptients[*]}
    do
      if [[ ! -d "./decrypted/$i" ]]
      then
        mkdir ./decrypted
        mkdir ./decrypted/$i
      fi

      for j in ${received_keys[*]}
      do
          #uses regex's to check if the username is in the dataset name then runs this
          if [[ $j =~ .*$i.* ]]
          then
            #grabs my username and key and puts it into parse_temp.txt
            cat ./decrypted/$i/$j | sed -n '/.*dinkels/,/==/p' > ./decrypted/$i/parse_temp.txt

            #grabs the entire key
            cat ./decrypted/$i/parse_temp.txt | cut -d " " -f2 | sed '/ ./,/==/p' > ./decrypted/$i/encodkey.bin.enc

            #grabs the encrypted message
            sed -n '/dinkels/,/--/p' ./decrypted/$i/$j | sed -n '/.*++/,/--/{/--/!p}' | sed 's/++//' | grep -v -e '^[[:space:]]*$' > ./decrypted/$i/encodmessage

            #grabs the hash
            sed -n '/dinkels/,/'\n'==/p' ./decrypted/$i/$j | sed -n '/.*-- /,/==/p' | sed 's/-- //' | sed '1,/==/!d' > ./decrypted/$i/encodhash.dat

            #decodes the key
            openssl base64 -d -in ./decrypted/$i/encodkey.bin.enc -out ./decrypted/$i/enckey.enc

            #unencrypts the key
            openssl rsautl -decrypt -inkey ./my_keys/rsa_private.pem -in ./decrypted/$i/enckey.enc -out ./decrypted/$i/key.bin

            #decodes the message
            openssl base64 -d -in ./decrypted/$i/encodmessage -out ./decrypted/$i/encmessage.enc

            #unencrypts the message
            #put a comment in front of two of these at a time if it doesn't decrypt correctly and step through them
            openssl enc -d -nosalt -aes-256-cbc -md md5 -in ./decrypted/$i/encmessage.enc -pass file:./decrypted/$i/key.bin -out ./decrypted/$i/message.txt
            openssl enc -d -nosalt -aes-256-cbc -in ./decrypted/$i/encmessage.enc -pass file:./decrypted/$i/key.bin -out ./decrypted/$i/message.txt
            openssl enc -d -nosalt -aes-256-cbc -md sha256 -in ./decrypted/$i/encmessage.enc -pass file:./decrypted/$i/key.bin -out ./decrypted/$i/message.txt

            #decodes the hash
            openssl base64 -d -in ./decrypted/$i/encodhash.dat -out ./decrypted/$i/sign.sha256

            #runs through all of the keypaths to find the correct users public key
            for x in ${!keypath[@]}
            do
              #checks for regular expressions in recipients and keypath
              if [[ $x =~ .*$i.* ]]
              then
                  #unencrypts the hash
                  openssl dgst -sha256 -verify $x -signature ./decrypted/$i/sign.sha256 ./decrypted/$i/message.txt
              fi
            done
          fi
        done
    done
}
decrypt
