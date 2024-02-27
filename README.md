# yrhash (Yinyang Hash Utility Rust Version)



## Overview - 概要

The yrhash is a tool designed to compute hash values of files using various hash algorithms.

It supports a range of algorithms, including MD5, CRC32, SHA1, SHA256, SHA384, and SHA512.



yrhashは、さまざまなハッシュアルゴリズムを使用してファイルのハッシュ値を計算を行うツールです。

サポートされているハッシュアルゴリズムには、MD5、CRC32、SHA1、SHA256、SHA384、SHA512が含まれます。



```
Usage:
  yrhash <option> <file> [algorithm] [comparison string]

Options:
  -m <algorithm> <file>: Specify the algorithm to use for hashing the file. Available algorithms are  crc32, md5, sha1, sha256, sha384, sha512.
  -c <file1> <file2>: Compare the hash of two files using the SHA256 algorithm.
  -i <file> <string>: Compare the hash of a file with the provided hash string using the SHA256 algorithm.
  -h: Display this help message.

Examples:
  yrhash -m md5 myfile.txt: Compute the MD5 hash of 'myfile.txt'.
  yrhash -c file1.txt file2.txt: Compare the SHA256 hashes of 'file1.txt' and 'file2.txt'.
  yrhash -i myfile.txt 123456789abcdef: Compare the SHA256 hash of 'myfile.txt' with the provided hash string.
```



```
Usage:
  yrhash <オプション> <ファイル> [アルゴリズム] [ハッシュ]

オプション:
  -m <アルゴリズム> <ファイル>: ファイルを指定されたアルゴリズムでハッシュを計算します。
  対応しているアルゴリズムは crc32, md5, sha1, sha256, sha384, sha512 です。
  
  -c <ファイル1> <ファイル2>: ファイル1とファイル2を SHA256 で比較します。
  
  -i <ファイル> <SHA256ハッシュ値>: ファイルが入力されたSHA256ハッシュ値を一致するか比較します。
  
  -h: ヘルプを表示します。

例:
  yrhash -m md5 myfile.txt　: MD5で'myfile.txt'のハッシュ値を計算します。
  yrhash -c file1.txt file2.txt　: 'file1.txt' と 'file2.txt' を比較します。
  yrhash -i myfile.txt 123456789abcdef　: 'myfile.txt' のハッシュ値と入力されたハッシュ値を比較します。
```



---

