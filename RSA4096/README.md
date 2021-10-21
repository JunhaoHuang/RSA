<!--
 * @Author: your name
 * @Date: 2021-10-12 18:47:43
 * @LastEditTime: 2021-10-18 09:48:57
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: \RSA\RSA4096\README.md
-->
# RSA4096
Achieve RSA4096 with C language

1. 实现了RSA4096的加密解密过程，公钥加密与私钥解密合并, 去除公钥解密, 私钥加密功能, 仅保留公钥加密/私钥解密. 

2. 增加对任意数据的RSA加解密支持, 直接使用makefile. 测试testbench, 效率与验证正确性.
# To debug:
make clean && make debug

gdb ./debug/main
# To release:
make clean && make all/release

./release/main
