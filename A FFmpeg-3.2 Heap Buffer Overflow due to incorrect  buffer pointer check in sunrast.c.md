# Overview
A Heap Buffer Overflow vulnerability in FFmpeg-3.2 was found with AFL (http://lcamtuf.coredump.cx/afl/). The vulnerability was trigged when FFmpeg trying to decode an input image (a frame) to a JP2 file. The vulnerability is a Heap Buffer Overflow vulnerability due to some improper out-of-bound access check (in fact, an improper integer check). The vulnerability can cause Denial-of-Service and Information Disclosure and may cause more critical impact.

# Software & Environments
## Software
  FFmpeg (https://www.ffmpeg.org/)
  The latest version (download from: https://www.ffmpeg.org/releases/ffmpeg-snapshot.tar.bz2 OR https://github.com/FFmpeg/FFmpeg )
 
## Operating System 
  Ubuntu 16.04 i686 Desktop
  > uname –a
  >> Linux ubuntu 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:34:49 UTC 2016 i686 i686 i686 GNU/Linux
 
## Compilers 
  GCC + CLANG + rr
  > gcc --version  
  >> gcc (Ubuntu 5.3.1-14ubuntu2.1) 5.3.1 20160413
                  
  > clang --version
  >> clang version 3.8.0-2ubuntu3 (tags/RELEASE_380/final)  
 
  > rr --version 
  >> rr version 4.4.0
  
# Reproduction
  The crash can be trigged by executing ‘ffmpeg’ (or its debug version, ‘ffmpeg_g’) with the PoC image file as its input and output to a JP2 file. 
## GCC version:

    mkdir build-gcc-debug<br/>
    cd build-gcc-debug
    ../configure --extrac-cflags=”-g” --extra-cxxflags=”-g” --extra-ldflags=”-g” --enable-debug  
    make
    ./ffmpeg –i  /* the poc file */ a.jp2` 
## Clang with asan:

    mkdir build-clang-asan
    cd build-clang-asan
    ../configure --cc=clang --cxx=clang++ --extra-cflags=”-O1 -fno-omit-frame-pointer -g” --extra-cxxflags=”-O1 -fno-omit-frame-pointer -g” --extra-ldflags=”-fsanitize=address” --enable-debug
    make
    ./ffmpeg –i /* the poc file */ a.jp2

# EXCEPTION WITH ASAN

    ffmpeg version N-82145-g0779396 Copyright (c) 2000-2016 the FFmpeg developers
      built with clang version 3.8.0-2ubuntu4 (tags/RELEASE_380/final)
      configuration: --cc=clang --cxx=clang++ --extra-cflags='-O1 -fno-omit-frame-pointer -g' --extra-cxxflags='-O1 -fno-omit-frame-pointer -g' --extra-ldflags='-fsanitize=address' --enable-debug
      libavutil      55. 35.100 / 55. 35.100
      libavcodec     57. 65.100 / 57. 65.100
      libavformat    57. 57.100 / 57. 57.100
      libavdevice    57.  2.100 / 57.  2.100
      libavfilter     6. 66.100 /  6. 66.100
      libswscale      4.  3.100 /  4.  3.100
      libswresample   2.  4.100 /  2.  4.100
    =============================================================
    ==18178==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xb4202ff8 at pc 0x080f0a58 bp 0xbff3b998 sp 0xbff3b570
    READ of size 3 at 0xb4202ff8 thread T0
        #0 0x80f0a57  (/home/fire/bing/afl/libraries/ffmpeg/build-clang-asan/ffmpeg+0x80f0a57)
        #1 0x8783a0c  (/home/fire/bing/afl/libraries/ffmpeg/build-clang-asan/ffmpeg+0x8783a0c)
 
    0xb4202ff8 is located 1 bytes to the right of 119-byte region [0xb4202f80,0xb4202ff7)
    allocated by thread T0 here:
        #0 0x813d734  (/home/fire/bing/afl/libraries/ffmpeg/build-clang-asan/ffmpeg+0x813d734)
        #1 0x8d787ff  (/home/fire/bing/afl/libraries/ffmpeg/build-clang-asan/ffmpeg+0x8d787ff)
        #2 0xbff3bb7f  (<unknown module>)
 
    SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/fire/bing/afl/libraries/ffmpeg/build-clang-asan/ffmpeg+0x80f0a57)
    Shadow bytes around the buggy address:
      0x368405a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
      0x368405b0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
      0x368405c0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
      0x368405d0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
      0x368405e0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
    =>0x368405f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 07[fa]
      0x36840600: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
      0x36840610: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
      0x36840620: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
      0x36840630: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
      0x36840640: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
    Shadow byte legend (one shadow byte represents 8 application bytes):
      Addressable:           00
      Partially addressable: 01 02 03 04 05 06 07
      Heap left redzone:       fa
      Heap right redzone:      fb
      Freed heap region:       fd
      Stack left redzone:       f1
      Stack mid redzone:       f2
      Stack right redzone:      f3
      Stack partial redzone:    f4
      Stack after return:       f5
      Stack use after scope:    f8
      Global redzone:         f9
      Global init order:        f6
      Poisoned by user:        f7
      Container overflow:      fc
      Array cookie:            ac
      Intra object redzone:     bb
      ASan internal:           fe
      Left alloca redzone:      ca
      Right alloca redzone:     cb
    ==18178==ABORTING

# Analysis
The crash happens in function “sunrast_decode_frame” when copying data from source buffer (aka. avpkt->data) to destination buffer (aka. ptr).

## crash stack

    Program received signal SIGSEGV, Segmentation fault.
    __memcpy_sse2_unaligned () at ../sysdeps/i386/i686/multiarch/memcpy-sse2-unaligned.S:651
    651  ../sysdeps/i386/i686/multiarch/memcpy-sse2-unaligned.S: No such file or directory.
    (rr) bt
    #0  __memcpy_sse2_unaligned () at ../sysdeps/i386/i686/multiarch/memcpy-sse2-unaligned.S:651
    #1  0x08682438 in memcpy (__len=3, __src=0xb4a1000, __dest=<optimized out>) at /usr/include/i386-linux-gnu/bits/string3.h:53
    #2  sunrast_decode_frame (avctx=0xb481760, data=0xb481e80, got_frame=0xbff30568, avpkt=0xbff304d8) at src/libavcodec/sunrast.c:173
    #3  0x086bb643 in avcodec_decode_video2 (avctx=0xb481760, picture=0xb481e80, got_picture_ptr=0xbff30568, avpkt=0xbff30668) at src/libavcodec/utils.c:2257
    #4  0x086bc5fd in do_decode (avctx=avctx@entry=0xb481760, pkt=pkt@entry=0xbff30668) at src/libavcodec/utils.c:2788
    #5  0x086bd3bb in avcodec_send_packet (avctx=0xb481760, avpkt=<optimized out>) at src/libavcodec/utils.c:2877
    #6  0x0831d4be in try_decode_frame (s=s@entry=0xb4801e0, st=st@entry=0xb480fe0, avpkt=avpkt@entry=0xbff307f0, options=0xb480aa0) at src/libavformat/utils.c:2967
    #7  0x08327962 in avformat_find_stream_info (ic=0xb4801e0, options=0xb480aa0) at src/libavformat/utils.c:3668
    #8  0x080caa97 in open_input_file (o=o@entry=0xbff30b0c, filename=<optimized out>) at src/ffmpeg_opt.c:1019
    #9  0x080cd657 in open_files (l=0xb48002c, l=0xb48002c, open_file=0x80ca600 <open_input_file>, inout=0x8c6d542 "input")
    at src/ffmpeg_opt.c:3135
    #10 ffmpeg_parse_options (argc=4, argv=0xbff312a4) at src/ffmpeg_opt.c:3175
    #11 0x080bca58 in main (argc=4, argv=0xbff312a4) at src/ffmpeg.c:4564

The code around the crash point:

    src/libavcodec/sunrast.c
    170            for (y = 0; y < h; y++) {
    171                if (buf_end - buf < len)
    172                    break;
    173                memcpy(ptr, buf, len);
    174                ptr += stride;
    175                buf += alen;
    176     }

The crash happens when copying data from ‘buf’ to ‘ptr’ which can cause out-of-bound read/write. The above code has already included a buffer-overflow check, aka line 171-172, however, the check is incomplete and can be bypassed when ‘alen’ is greater than ‘len’ and (buf_end - buf) % alen (aka. remainder) is not less than ‘len’ (in fact, equal to ‘len’). When ‘alen’ and ‘len’ satisfy the noted condition, ‘buf’ will pass through ‘buf_end’ (i.e. ‘buf’ becomes greater than ‘buf_end’) and (buf_end - buf) will become a negative number, here, (buf_end - buf) will become a big unsigned positive integer because type of ‘buf_end’ and ‘buf’ is “unsigned char*” i.e. unsigned int; then, the check (line 171-172) will become useless. Further, out-of-bound read\write will happen when (len * h) is greater than the length of ‘buf’.

Next, I need to know which related variables (such as h, buf_end, len, alen, buf, ptr, stride) can be controlled by attackers.
 
    =================The related code in src/libavcodec/sunrast.c======
    29     static int sunrast_decode_frame(AVCodecContext *avctx, void *data,
    30                                  int *got_frame, AVPacket *avpkt)
    31     {
    32              const uint8_t *buf       = avpkt->data;
    33              const uint8_t *buf_end   = avpkt->data + avpkt->size;
    …
    48              w         = AV_RB32(buf + 4);
    49              h         = AV_RB32(buf + 8);
    50              depth     = AV_RB32(buf + 12);
    51              type      = AV_RB32(buf + 20);
    52              maptype   = AV_RB32(buf + 24);
    53              maplength = AV_RB32(buf + 28);
    54              buf      += 32;
    …
    127            buf += maplength;
    …
    140            len  = (depth * w + 7) >> 3;
    141            alen = len + (len & 1);
    ==========================================================
    
From the above related code, I know those variables almost come from “avpkt->data”. Checking the content of “avpkt->data”, I found the content is same with the content of the input poc file, i.e. “avpkt->data” stores the content read in from the poc file.

    =============================DEBUG WITH RR===============
    (rr) break sunrast_decode_frame
    Breakpoint 1 at 0x86820f0: file src/libavcodec/sunrast.c, line 31.
    (rr) reverse-continue
    Continuing.
 
    Program received signal SIGSEGV, Segmentation fault.
    __memcpy_sse2_unaligned ()
        at ../sysdeps/i386/i686/multiarch/memcpy-sse2-unaligned.S:651
    651  in ../sysdeps/i386/i686/multiarch/memcpy-sse2-unaligned.S
    (rr) reverse-continue
    Continuing.
 
    Breakpoint 1, sunrast_decode_frame (avctx=0xb481760, data=0xb481e80, got_frame=0xbff30568, avpkt=0xbff304d8) at src/libavcodec/sunrast.c:31
    31     {
    (rr) p/x avpkt
    $22 = 0xbff304d8
    (rr) p/x *avpkt
    $23 = {buf = 0xb482280, pts = 0x7ffeffffffffffff, dts = 0x7ffeffffffffffff, data = 0xb4821d8, size = 0x57, stream_index = 0x0, flags = 0x1, side_data = 0x0, side_data_elems = 0x0, duration = 0x1, pos = 0x0, convergence_duration = 0x0}
    (rr) p/x avpkt->size
    $24 = 0x57
    (rr) x/87b avpkt->data
    0xb4821d8:      0x59 0xa6 0x6a 0x95 0x00 0x00 0x00 0x01
    0xb4821e0:      0x00 0x00 0xde 0x01 0x00 0x00 0x00 0x18
    0xb4821e8:      0x00 0x20 0x00 0x01 0x00 0x00 0x00 0x01
    0xb4821f0:      0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00
    0xb4821f8:      0x01 0x00 0x18 0x00 0x00 0x00 0x00 0x00
    0xb482200:      0x00 0x00 0x00 0x00 0x00 0x18 0x00 0x20
    0xb482208:      0x00 0x01 0x00 0x00 0x00 0x01 0x00 0x00
    0xb482210:      0x00 0x01 0x00 0x00 0x00 0x00 0x01 0x00
    0xb482218:      0x18 0x00 0x00 0x6a 0x50 0x20 0x20 0x00
    0xb482220:      0x00 0xff 0x00 0x00 0x00 0x00 0x00 0x00
    0xb482228:      0xec 0x00 0x00 0x00 0x00 0x00 0x00
    =============================================================

From the above code in function “sunrast_decode_frame”, I can infer the format of the input file, like the following:
    
    ----------------------------------------------------------------------------------------------------------
    |  magic (4 bytes)  |   w (4bytes)    |    h (4 bytes)      |  depth (4 bytes)   |
    ----------------------------------------------------------------------------------------------------------
    |   (4 bytes)      |   type (4 bytes)  |  maptype (4 bytes)  | maplength (4 bytes) |
    ----------------------------------------------------------------------------------------------------------
    |                               data ((avpkt->size - 32) bytes)                      
    ----------------------------------------------------------------------------------------------------------
 
So, in this debugging (big-endian), magic = 0x5aa66a95, w = 0x01, h = 0xde01, depth = 0x18, type = 0x01, maptype = 0x01, maplength = 0x00, buf_end – buf_begin = 0x57
==> len = (0x18 * 0x01 + 7) >> 3 = 0x03, alen = 0x03 + (0x03 & 0x01) = 0x04 ==> (buf_end – buf_begin - 0x20) / alen = 0x0d, (buf_end – buf_begin – 0x20) % alen = 0x03
==> when y = 0x0d, (buf_end – buf) = 0x03 (not less than ‘len’); when y = 14, buf_end – buf = -1 = 0xffffffff > len
 
Beside the above analysis, in order to confer that buffer overflow is possible, I need to know the max loop times and the capacity of buffer ‘buf’ (aka. avpkt->data). The max loop times is h which can be directly controlled from the input file (here is 0xde01) and the max number of bytes read from ‘buf’ is (h * len). Next, I need to know the capacity of buffer ‘avpkt->data’.

    ========================DEBUG WITH RR=======================
    (rr) p avpkt
    $1 = (AVPacket *) 0xbff304d8
    (rr) p/x *avpkt
    $2 = {buf = 0xb482280, pts = 0x7ffeffffffffffff, dts = 0x7ffeffffffffffff, data = 0xb4821d8, size = 0x57, stream_index = 0x0, flags = 0x1, side_data = 0x0, side_data_elems = 0x0, duration = 0x1, pos = 0x0, convergence_duration = 0x0}
    (rr) watch -l avpkt->data
    Hardware watchpoint 2: -location avpkt->data
    (rr) reverse-continue
    Continuing.
 
    Hardware watchpoint 2: -location avpkt->data
 
    Old value = (uint8_t *) 0xb4821d8 "Y\246j\225"
    New value = (uint8_t *) 0x8bb2251 <av_opt_find2+113> "\203\304\020\205\300u؁\177\f\200"
    avcodec_decode_video2 (avctx=0xb481760, picture=0xb481e80, got_picture_ptr=0xbff30568, avpkt=0xbff30668) at src/libavcodec/utils.c:2220
    2220             AVPacket tmp = *avpkt;
    (rr) p avpkt
    $3 = (const AVPacket *) 0xbff30668
    (rr) p &tmp
    $4 = (AVPacket *) 0xbff304d8
    (rr) p/x *avpkt
    $5 = {buf = 0xb482280, pts = 0x7ffeffffffffffff, dts = 0x7ffeffffffffffff, data = 0xb4821d8, size = 0x57, stream_index = 0x0, flags = 0x1, side_data = 0x0, side_data_elems = 0x0, duration = 0x1, pos = 0x0, convergence_duration = 0x0}
    (rr) watch -l avpkt->data
    Hardware watchpoint 3: -location avpkt->data
    (rr) disable 2
    (rr) reverse-continue
    Continuing.
 
    Hardware watchpoint 3: -location avpkt->data
 
    Old value = (uint8_t *) 0xb4821d8 "Y\246j\225"
    New value = (uint8_t *) 0x20 <error: Cannot access memory at address 0x20>
try_decode_frame (s=s@entry=0xb4801e0, st=st@entry=0xb480fe0, avpkt=0xbff30804, avpkt@entry=0xbff307f0, options=0xb480aa0) at src/libavformat/utils.c:2912
    2912             AVPacket pkt = *avpkt;
    (rr) p avpkt
    $6 = (AVPacket *) 0xbff30804
    (rr) p &pkt
    $7 = (AVPacket *) 0xbff30668
    (rr) p/x *avpkt
    $8 = {buf = 0xb4821d8, pts = 0x57, dts = 0x1, data = 0x0, size = 0x1, stream_index = 0x0, flags = 0x0, side_data = 0x0, side_data_elems = 0x0, duration = 0x0, pos = 0x0, convergence_duration = 0xb4808a00b480fe0}
    (rr) break src/libavformat/utils.c:2912
    Breakpoint 4 at 0x831d239: file src/libavformat/utils.c, line 2912.
    (rr) reverse-continue
    Continuing.
 
    Breakpoint 4, try_decode_frame (s=s@entry=0xb4801e0, st=st@entry=0xb480fe0, avpkt=avpkt@entry=0xbff307f0, options=0xb480aa0) at src/libavformat/utils.c:2912
    2912             AVPacket pkt = *avpkt;
    (rr) p &pkt
    $9 = (AVPacket *) 0xbff30668
    (rr) p avpkt
    $10 = (AVPacket *) 0xbff307f0
    (rr) p/x *avpkt
    $11 = {buf = 0xb482280, pts = 0x7ffeffffffffffff, dts = 0x7ffeffffffffffff, data = 0xb4821d8, size = 0x57, stream_index = 0x0, flags = 0x1, side_data = 0x0, side_data_elems = 0x0, duration = 0x1, pos = 0x0, convergence_duration = 0x0}
    (rr) disable 3
    (rr) watch -l avpkt->data
    Hardware watchpoint 5: -location avpkt->data
    (rr) disable 4
    (rr) reverse-continue
    Continuing.
 
    Hardware watchpoint 5: -location avpkt->data
 
    Old value = (uint8_t *) 0xb4821d8 "Y\246j\225"
    New value = (uint8_t *) 0x3ff00000 <error: Cannot access memory at address 0x3ff00000>
    0x08321e91 in read_frame_internal (s=s@entry=0xb4801e0, pkt=pkt@entry=0xbff307f0) at src/libavformat/utils.c:1570
    1570                     *pkt = cur_pkt;
    (rr) p pkt
    $12 = (AVPacket *) 0xbff307f0
    (rr) p &cur_pkt
    $13 = (AVPacket *) 0xbff305b8
    (rr) p/x cur_pkt
    $14 = {buf = 0xb482280, pts = 0x8000000000000000, dts = 0x8000000000000000, data = 0xb4821d8, size = 0x57, stream_index = 0x0, flags = 0x1, side_data = 0x0, side_data_elems = 0x0, duration = 0x0, pos = 0x0, convergence_duration = 0x0}
    (rr) disable 5
    (rr) watch -l cur_pkt.data
    Hardware watchpoint 6: -location cur_pkt.data
    (rr) reverse-continue
    Continuing.
 
    Hardware watchpoint 6: -location cur_pkt.data
 
    Old value = (uint8_t *) 0xb4821d8 "Hkg\267Hkg\267\320!H\v\320!H\v"
    New value = (uint8_t *) 0x0
    av_new_packet (pkt=0xbff305b8, size=87) at src/libavcodec/avpacket.c:95
    95         pkt->data     = buf->data;
    (rr) p pkt
    $15 = (AVPacket *) 0xbff305b8
    (rr) p buf
    $16 = (AVBufferRef *) 0xb482280
    (rr) disable 6
    (rr) watch -l buf->data
    Hardware watchpoint 7: -location buf->data
    (rr) reverse-continue
    Continuing.
 
    Hardware watchpoint 7: -location buf->data
 
    Old value = (uint8_t *) 0xb4821d8 "Hkg\267Hkg\267\320!H\v\320!H\v"
    New value = (uint8_t *) 0x0
    av_buffer_create (flags=0, opaque=0x0, free=0x8b93b70 <av_buffer_default_free>, size=119, data=0xb4821d8 "Hkg\267Hkg\267\320!H\v\320!H\v") at src/libavutil/buffer.c:55
    55         ref->data   = data;
    (rr) p ref
    $17 = (AVBufferRef *) 0xb482280
    =============================================================
   
From above debugging infomation, ‘avpkt->data’ comes from ‘data’ in function ‘av_buffer_create’. Next, the question becomes what size of ‘data’ is.
 
    ==========================DEBUG WITH RR=====================
    (rr) bt
    #0  av_buffer_create (flags=0, opaque=0x0, free=0x8b93b70 <av_buffer_default_free>, size=119, data=0xb4821d8 "Hkg\267Hkg\267\320!H\v\320!H\v") at src/libavutil/buffer.c:55
    #1  av_buffer_realloc (pbuf=0xbff2f768, size=119) at src/libavutil/buffer.c:180
    #2  0x0837c2ae in packet_alloc (size=87, buf=0xbff2f768) at src/libavcodec/avpacket.c:77
    #3  av_new_packet (pkt=0xbff305b8, size=87) at src/libavcodec/avpacket.c:89
    #4  0x0824b2ae in ff_img_read_packet (s1=0xb4801e0, pkt=0xbff305b8) at src/libavformat/img2dec.c:459
    #5  0x0831df46 in ff_read_packet (s=0xb4801e0, pkt=0xbff305b8) at src/libavformat/utils.c:795
    #6  0x08321b6c in read_frame_internal (s=s@entry=0xb4801e0, pkt=pkt@entry=0xbff307f0) at src/libavformat/utils.c:1493
    #7  0x0832718c in avformat_find_stream_info (ic=0xb4801e0, options=0xb480aa0) at src/libavformat/utils.c:3537
    #8  0x080caa97 in open_input_file (o=o@entry=0xbff30b0c, filename=<optimized out>) at src/ffmpeg_opt.c:1019
    #9  0x080cd657 in open_files (l=0xb48002c, l=0xb48002c, open_file=0x80ca600 <open_input_file>, inout=0x8c6d542 "input") at src/ffmpeg_opt.c:3135
    #10 ffmpeg_parse_options (argc=4, argv=0xbff312a4) at src/ffmpeg_opt.c:3175
    #11 0x080bca58 in main (argc=4, argv=0xbff312a4) at src/ffmpeg.c:4564
    ============================================================= 
    
‘data’ is passed in by function ‘av_buffer_realloc’, and the related code is:
 
    =====================function ‘av_buffer_realloc’===================
    176            uint8_t *data = av_realloc(NULL, size);
    177            if (!data)
    178            return AVERROR(ENOMEM);
    179          
    180            buf = av_buffer_create(data, size, av_buffer_default_free, NULL, 0);
    ==============================================================

    So, the size of data is ‘size’, which is passed in from function ‘packet_alloc’, and the related code is
 
    ====================function ‘packet_alloc’=======================
         77     ret = av_buffer_realloc(buf, size + AV_INPUT_BUFFER_PADDING_SIZE);
    =============================================================

‘size’ is (size + AV_INPUT_BUFFER_PADDING_SIZE) and AV_INPUT_BUFFER_PADDING_SIZE is 32. Next, the question is what value of the current ‘size’ is. The current ‘size’ from function ‘ff_img_read_packet’ through function “av_new_packet”. The related code is
        
    ====================function “ff_img_read_packet”=================
         459            res = av_new_packet(pkt, size[0] + size[1] + size[2]);
    =============================================================

Debugging:
    ============================DEBUG WITH RR=======================
    (rr) break src/libavformat/img2dec.c:459
    Breakpoint 8 at 0x824b2a0: file src/libavformat/img2dec.c, line 459.
    (rr) reverse-continue
    Continuing.
 
    Breakpoint 8, ff_img_read_packet (s1=0xb4801e0, pkt=0xbff305b8) at src/libavformat/img2dec.c:459
    459      res = av_new_packet(pkt, size[0] + size[1] + size[2]);
    (rr) p/x size
    $18 = {0x57, 0x0, 0x0}
    (rr) watch -l size[0]
    Hardware watchpoint 9: -location size[0]
    (rr) reverse-continue
    Continuing.
 
    Hardware watchpoint 9: -location size[0]
 
    Old value = 87
    New value = 0
    0x0824b967 in ff_img_read_packet (s1=0xb4801e0, pkt=0xbff305b8) at src/libavformat/img2dec.c:453
    453              size[0] = avio_size(s1->pb);
    (rr) break src/libavformat/img2dec.c:453
    Breakpoint 10 at 0x824b95c: file src/libavformat/img2dec.c, line 453.
    (rr) reverse-continue
    Continuing.
 
    Breakpoint 10, ff_img_read_packet (s1=0xb4801e0, pkt=0xbff305b8) at src/libavformat/img2dec.c:453
    453              size[0] = avio_size(s1->pb);
    (rr) s
    avio_size (s=0xb488b40) at src/libavformat/aviobuf.c:310
    310  {
    (rr) n
    313      if (!s)
    (rr) n
    316      if (!s->seek)
    (rr) n
    318      size = s->seek(s->opaque, 0, AVSEEK_SIZE);
    (rr) s
    io_seek (opaque=0xb480a40, offset=0, whence=65536) at src/libavformat/aviobuf.c:858
    858      return ffurl_seek(internal->h, offset, whence);
    (rr) s
    ffurl_seek (h=0xb480980, pos=0, whence=65536) at src/libavformat/avio.c:435
    435  {
    (rr) n
    438      if (!h->prot->url_seek)
    (rr) n
    440      ret = h->prot->url_seek(h, pos, whence & ~AVSEEK_FORCE);
    (rr) s
    442  }
    (rr) s
    440      ret = h->prot->url_seek(h, pos, whence & ~AVSEEK_FORCE);
    (rr) s
    file_seek (h=0xb480980, pos=0, whence=65536) at src/libavformat/file.c:235
    235  {
    (rr) n
    236      FileContext *c = h->priv_data;
    (rr) n
    235  {
    (rr) n
    239      if (whence == AVSEEK_SIZE) {
    (rr) n
    236      FileContext *c = h->priv_data;
    (rr) n
    239      if (whence == AVSEEK_SIZE) {
    (rr) n
    241          ret = fstat(c->fd, &st);
    (rr) n
    242          return ret < 0 ? AVERROR(errno) : (S_ISFIFO(st.st_mode) ? 0 : st.st_size);
    (rr) p/x ret
    $19 = 0x0
    (rr) p/x st
    $20 = {st_dev = 0x801, __pad1 = 0x0, __st_ino = 0xc454b, st_mode = 0x8180, st_nlink = 0x1, st_uid = 0x3e8, st_gid = 0x3e8, st_rdev = 0x0, __pad2 = 0x0, st_size = 0x57, st_blksize = 0x1000, st_blocks = 0x8, st_atime = 0x58176c8d, st_atimensec = 0x224eaac, st_mtime = 0x58157526, st_mtimensec = 0x34912fd4, st_ctime = 0x58157526, st_ctimensec = 0x34912fd4, st_ino = 0xc454b}
    (rr) p/x st.st_size
    $21 = 0x57
    (rr)
    
Finallly, I know it is the physical size of the input file.
 
So, the capacity of buffer ‘avpkt->data’ is (physical size of input file + 32) (here is 0x57 + 0x20 = 0x77). Crafting the poc file to make (h * len) greater than 0x77 (in this debugging) will cause out-of-bound read.
 
Also, I can analyze the capacity of buf ‘ptr’, however, the analysis is a little more complicated. I think it’s possible to trigger out-of-bound write to buffer ‘ptr’, however, it needs more skill to set ‘w’, ‘h’, ‘depth’ and craft the sample to make it have proper physical size.

# Conclusions
The vulnerability is a Heap Buffer Overflow vulnerability due to an incomplete buffer-overflow check which are already there and can be bypassed by crafting an input image with proper header data. The vulnerability can cause Denial-of-Service, Information Disclosure and may cause more critical impact.

**This vulnerability was firstly reported to RedHat Security Team. Now it has been confirmed by the upstream and has been patched, which can be found by this link:**
  http://ffmpeg.org/pipermail/ffmpeg-cvslog/2016-November/102693.html
