#!/bin/bash

NOW=$(date "+%m/%d/%Y %R %Z")

reciptients=( "bartong2" "fricken" "tjones" "ander551" "dinkels" "clevelj3" "ferreri" )

declare -A keypath

keypath["./keys/dinkels/rsa_public_dinkels.pem"]=dinkels
keypath["./keys/bartong2/rsa_public_bartong2.pem"]=bartong2
keypath["./keys/fricken/rsa_public_fricken.pem"]=fricken
keypath["./keys/tjones/rsa_public_tjones.pem"]=tjones
keypath["./keys/ander551/rsa_public_ander551.pem"]=ander551
keypath["./keys/clevelj3/rsa_public_clevelj3.pem"]=clevelj3
keypath["./keys/ferreri/rsa_public_ferreri.pem"]=ferreri

encrypt(){
      #opens the file for writing
      exec 3>dataset.txt
      #puts the header in the file
      printf "SecMsGs $NOW\n"  >&3

      #runs for as many usernames are stored in the recipients array
      for j in ${reciptients[*]}
      do
          #creates the text file that recieves the data for each user
          if [ ! -f "./dataset.txt" ] ;
          then
            touch ./dataset.txt
          fi

          #creates the directory structure to store recipients data for parsing into the dataset.txt
          if [[ ! -d "./keys" ]] && [[ ! -d "./keys/$j" ]]
          then
              mkdir ./keys
              mkdir ./keys/$j
          fi

          #generates a random key
          openssl rand 32 > key.bin

          #copies the key to each users directory
          cp key.bin ./keys/$j

          #creates unique keys for each user
          for i in "${!keypath[@]}"
          do
            if [[ $i =~ .*$j.* ]]
            then
              openssl rsautl -encrypt -inkey $i -pubin -in ./keys/$j/key.bin | openssl base64 -out ./keys/$j/key.bin.enc
              encrypt_key=$( cat ./keys/$j/key.bin.enc )
            fi
          done

          #encrypts the message file for each user
          openssl enc -aes-256-cbc -nosalt -in ./keys/$j/SECRET_FILE -pass file:./keys/$j/key.bin | openssl base64 -out ./keys/$j/SECRET_FILE.enc
          secret_file=$( cat ./keys/$j/SECRET_FILE.enc )

          #generates the hash of the message
          openssl dgst -sha256 -sign ./my_keys/rsa_private.pem -out ./keys/$j/sign.sha256 ./keys/$j/SECRET_FILE

          #encodes the hash of the message
          openssl base64 -in ./keys/$j/sign.sha256 -out ./keys/$j/signature.dat
          signature=$( cat ./keys/$j/signature.dat )

          #these print statements write the generated data into the dataset.txt file
          printf "\n==$j $encrypt_key\n" >&3
          printf "\n++\n" >&3
          printf "\n$secret_file\n" >&3
          printf "\n-- $signature\n" >&3
      done
}
encrypt
