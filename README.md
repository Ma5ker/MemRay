# MemRay: Capturing Invalid Input Manipulations for Memory Corruption Diagnosis

Repo for the source code of MemRay. Mainly the off-line trace analysis module.

We have pushed one testcase for you to test the functionablity of our tool.

## About Execution Trace

The analyzed trace is generated with DECAF. We extend DECAF to support multi-tag taint analysis. The extened trace supported by MemRay is as shown in the testcase, each line of which consists of instruction address, instruction, numbers of operands, operand info and taint info.

MemRay also supports execution traces in the same format that you generate with other tools, such as pintool and so on.

## Using MemRay

To use MemRay, We need a objdump file to get the syscall info. Objdump file should be named as BinName-objdump.txt; trace file should be named as BinName.txt

```
python MemRay.py BinName
```

## Example

```
➜  MemRay git:(main) ✗ python MemRay.py ghttpd
Buffer Overflow in  347834 ['b7ef952a', 'movsw  %ds:(%esi),%es:(%edi)']
End...		Time cost:  32.668272733688354 s


# We put details in the BinName-moas.txt
➜  MemRay git:(main) ✗ cat .\ghttpd-result.txt
[[['__libc_start_main@plt', 'serveconnection'], '0xbfffd5d7'], 8216, 'stack', True]     ['__libc_start_main@plt', 'serveconnection', 'strstr@plt']      [329449, 'movzbl (%edx),%eax']  read    [[0, 369]]      [0, 369]
[[['__libc_start_main@plt', 'serveconnection'], '0xbfffd5d7'], 8216, 'stack', True]     ['__libc_start_main@plt', 'serveconnection']    [332070, 'movzbl (%edx,%edi,1),%eax']   read    [[0, 365]]      [0, 365]
[[['__libc_start_main@plt', 'serveconnection'], '0xbfffb5d7'], 5, 'stack', True['__libc_start_main@plt', 'serveconnection']     [332075, 'mov    %eax,-0x4151(%edx,%ebp,1)']    write   [[0, 364]]      [0, 364]
[[['__libc_start_main@plt', 'serveconnection'], '0xbfffb5d7'], 5, 'stack', True['__libc_start_main@plt', 'serveconnection', 'strtok@plt']       [335458, 'mov    (%eax),%cl']   read    [[0, 350]]      [0, 350]
[[['__libc_start_main@plt', 'serveconnection'], '0xbfffd5d7'], 8216, 'stack', True]     ['__libc_start_main@plt', 'serveconnection', 'strstr@plt']      [336763, 'movzbl (%edx),%eax']  read    [[0, 345]]      [0, 346]
[[['__libc_start_main@plt', 'serveconnection', 'Log'], '0xbfffb426'], 200, 'stack', True]       ['__libc_start_main@plt', 'serveconnection', 'Log', 'vsprintf@plt']     [347834, 'movsw  %ds:(%esi),%es:(%edi)']        write   [[4, 349]]     [46, 391]
[[['__libc_start_main@plt', 'serveconnection', 'Log'], '0xbfffb35e'], 200, 'stack', True]       ['__libc_start_main@plt', 'serveconnection', 'Log', 'sprintf@plt']      [365475, 'movsb  %ds:(%esi),%es:(%edi)']        write   [[286, 311], [316, 349]]        [0, 273]
[[['__libc_start_main@plt', 'serveconnection'], '0xbfffb5e0'], 8183, 'stack', True]     ['__libc_start_main@plt', 'serveconnection']    [368407, 'mov    -0x4160(%ebp),%eax']   read    [[9, 12]]       [0, 3]
[[['__libc_start_main@plt', 'serveconnection'], '0xbfffb5dc'], 4, 'stack', True['__libc_start_main@plt', 'serveconnection']     [368619, 'mov    -0x4164(%ebp),%ebx']   read    [[5, 8]]        [0, 3]
[[['__libc_start_main@plt', 'serveconnection'], '0xbfffb5e0'], 8183, 'stack', True]     ['__libc_start_main@plt', 'serveconnection']    [369538, 'mov    -0x4160(%ebp),%edx']   read    [[9, 12]]       [0, 3]
[[['__libc_start_main@plt', 'serveconnection'], '0xbfffb5dc'], 4, 'stack', True['__libc_start_main@plt', 'serveconnection']     [370465, 'mov    -0x4164(%ebp),%eax']   read    [[5, 8]]        [0, 3]
[[['__libc_start_main@plt', 'serveconnection'], '0xbfffb5e0'], 8183, 'stack', True]     ['__libc_start_main@plt', 'serveconnection']    [370684, 'mov    -0x4160(%ebp),%eax']   read    [[9, 12]]       [0, 3]
[[['__libc_start_main@plt', 'serveconnection'], '0xbfffb5dc'], 4, 'stack', True['__libc_start_main@plt', 'serveconnection']     [373028, 'mov    -0x4164(%ebp),%esi']   read    [[5, 8]]        [0, 3]
[[['__libc_start_main@plt', 'serveconnection'], '0xbffff5ef'], 281, 'stack', True]      ['__libc_start_main@plt', 'serveconnection', 'strlen@plt']      [374139, 'cmp    %ch,(%eax)']   read    [[328, 328]]    [0, 63]
```
