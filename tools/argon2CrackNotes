# Cracking Argon2 (Educational Notes)

- Make your passwords sufficiently complex that an attack vector like the below is not a practical feasibility. 

## Hash from viewing sql api_keys.db (unencrypted) raw, via sqlite viewer -> master_key -> BLOB Binary

- This is an example:

```
0000  24 61 72 67 6f 6e 32 69 64 24 76 3d 31 39 24 6d  $argon2id$v=19$m 
0010  3d 36 35 35 33 36 2c 74 3d 32 2c 70 3d 31 24 47  =65536,t=2,p=1$G 
0020  38 6f 6f 56 76 4e 57 6a 63 31 5a 6d 70 39 73 4d  8ooVvNWjc1Zmp9sM 
0030  71 56 31 35 41 24 47 36 62 5a 34 38 46 4c 49 6c  qV15A$G6bZ48FLIl 
0040  79 48 38 57 49 2b 69 44 54 35 75 6a 58 58 5a 72  yH8WI+iDT5ujXXZr 
0050  68 4c 69 2f 6f 6a 36 31 41 7a 73 6e 6c 6a 73 2b  hLi/oj61Azsnljs+ 
0060  6f                                               o                
```

## Cracking with Argon2_Cracker or any other similar tool

- https://cyberknight00.github.io/Argon2_Cracker/

```
$ git clone https://github.com/CyberKnight00/Argon2_Cracker.git
$ cd Argon2_Cracker
$ pip3 install -r requirement.txt
$ python3 ./crack_argon2.py -c '$argon2id$v=19$m=65536,t=2,p=1$G8ooVvNWjc1Zmp9sMqV15A$G6bZ48FLIlyH8WI+iDT5ujXXZrhLi/oj61Azsnljs+o' -w /home/anelson/Argon2_Cracker/wordList
$argon2id$v=19$m=65536,t=2,p=1$G8ooVvNWjc1Zmp9sMqV15A$G6bZ48FLIlyH8WI+iDT5ujXXZrhLi/oj61Azsnljs+o -> edison2 
Total time taken : 0.12975096702575684

# The wordlist
(video-tools) anelson@gpu0-rtx8000:~/Argon2_Cracker$ cat wordList
blah
blah2
blah3
words
Stuff
edison2
passwords
sexsexsex
```
