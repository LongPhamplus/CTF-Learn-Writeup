
# CTF challenges and solutions (part 2)

## Riyadh
- Khá giống với 1 bài đã từng làm là Reykjavik nhưng mà phức tạp hơn.
- Cần debug từng bước một và đọc code cùng kiểm tra các giá trị của hàm.
- Đầu tiên cứ chạy file thì ta sẽ biết được cần chạy file với input là flag: `Usage: Riyadh flag`.
- Ròi giờ thử với 
    ```
    ./Riyadh hehe                          
    Welcome to CTFlearn Riyadh Reversing Challenge!
    Compile Options: ${CMAKE_CXX_FLAGS} -O0 -fno-stack-protector -mno-sse
    You entered the wrong flag :-(

    ```
- Tới đây thì chắc hẳn sẽ phải mở gdb lên rồi. À mà trước đó nhớ đọc code dạng asm nhé hoặc decomplie gì gì đó để hiểu đoạn dưới.
- Đầu tiên đặt breakpoint tại main+0x49. Tức là từ đoạn kiểm tra input.
- Tiếp đó chạy từng dòng trên gdb để kiểm tra các giá trị thì thấy có 1 đoạn so sánh như này: `0x555555555160 <main+0060>      call   0x5555555550e0 <strcmp@plt>`và đọc kĩ thì sẽ biết được giá trị input sẽ được so sánh với `"CTFlearn{Reversing_Is_Easy}"` vậy ta thử thêm flag này xem sao: 

    ```
    run 'CTFlearn{Reversing_Is_Easy}'
    ```
- Ok và sau đó ta đã nhận được 1 cú lừa :),
- Rồi thì đọc kĩ code thì ta cần nhảy qua đoạn cú lừa này ok giờ run lại với input cũ và tới bước kiểm tra ta sẽ set thanh ghi `rdi = 0x00007fffffffe19c`.
- Để giải thích đoạn trên thì khi chạy bdg tới dòng main+60 thì sẽ cho ta biết là hàm strcmp sẽ so sánh 2 giá trị ở 2 thanh ghi rsi và rdi với giá trị trong rdi chính là cái mà mình set cho rsi. Vậy ta có thể giữ nguyên input cũ mà vẫn có thể nhảy qua cái đoạn cú lừa này :). À mà theo code thì phải thỏa mãn việc 2 thanh ghi bằng nhau thì mới chạy tiếp được.
    ```
    (gdb) set $rdi = 0x00007fffffffe19c
    ```
- Ok tiếp với input hehe thì chạy hoài vẫn bị in ra sai flag vậy ta quay lại với code. 
- Chú ý ở dòng main+75 có so sánh RAX với 0x1e và đọc ở decomplie nghĩa là độ dài xâu nào đó và trong trường hợp này sẽ so sánh với độ dài lấy từ thanh ghi rdi vậy nên ta cần sửa rdi chứ không phải rsi như trên.
    ```
        (gdb) run 'hehehehehehehehehehehehehehehe'
    ```
- Và sau một hồi chạy chạy ta có được 1 flag là `CTFlearn{Masmak_Fortress_1865}` đem chạy thử thì ok chính xác luôn.
    ```
    ./Riyadh CTFlearn{Masmak_Fortress_1865}
    Welcome to CTFlearn Riyadh Reversing Challenge!
    Compile Options: ${CMAKE_CXX_FLAGS} -O0 -fno-stack-protector -mno-sse

    CONGRATULATIONS!! You found the flag:  CTFlearn{Masmak_Fortress_1865}

    All Done!

    ```
![Riyadh1](https://github.com/LongPhamplus/CTF-Learn-Writeup/blob/master/Part2_pic/Riyadh1.png)