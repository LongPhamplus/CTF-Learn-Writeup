
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

<details><summary>Đoạn mã chuyển đổi cho dễ đọc để tham khảo</summary>
<p>
```
# I wrote and debugged this code with all the convoluted "EAT" variable names.
# Was it confusing? Yes. Was debugging hard? Yes.
# Did I spend more time than I should have on this problem? Yes

toInt = int
sizeOfString = len
toString = str
checkCharNotNum = toString.isdigit # kiem tra xem ATE co chua ki tu khac so hay khong

def Eating(eat):
    return toString(toInt(eat)*roundLen3) #chuyen so eat thanh so roi nhan voi roundLen3 roi chuyen ket qua thanh string

def EAt(eat, eats):
    print(eat, eats)
    eat1 = 0
    eat2 = 0
    i = 0
    eAt = ""
    while eat1 < sizeOfString(eat) and eat2 < sizeOfString(eats):
        if i%roundLen3 == roundLen3Sub1//roundLen3Plus1: # i%3 == 0:
            eAt += eats[eat2]
            eat2 += 1
        else:
            eAt += eat[eat1]
            eat1 += 1
        i += 1
    return eAt

def reverse(eat):
    return eat[::roundLen3-roundLen3Plus1]  # cat xau voi buoc nhay -1 hay co the hieu la dao xau

def eaT(eat):
    return Eating(eat[:roundLen3]) + reverse(eat) # Eating(eat[:3]) + reverse(eat)

def aTE(eat):
    return eat
	# Lap lai xau sizeOfString(eat) lan
def Ate(eat):
    return "Eat" + toString(sizeOfString(eat)) + eat[:roundLen3] # "Eat" + toString(9) + eat[:3]

def Eat(eat):
    if sizeOfString(eat) == 9: #checkCharNotNum(eat[:3]) 
        if checkCharNotNum(eat[:roundLen3]) and\
            checkCharNotNum(eat[sizeOfString(eat)-roundLen3+1:]): # checkCharNotNum(eat[7:])
                eateat = EAt(eaT(eat), Ate(aTE(reverse(eat))))
                if eateat == "E10a23t9090t9ae0140":
                    flag = "eaten_" + eat
                    print("absolutely EATEN!!! CTFlearn{",flag,"}")
                else:
                    print("thats not the answer. you formatted it fine tho, here's what you got\n>>", eateat)
        else:
            print("thats not the answer. bad format :(\
            \n(hint: 123abc456 is an example of good format)")
    else:
        print("thats not the answer. bad length :(")

print("what's the answer")
eat = input()
roundLen3 = sizeOfString(eat)//3 	# Lay kich thuoc string roi chia 3 lay phan nguyen
roundLen3Plus1 = roundLen3+1
roundLen3Sub1 = roundLen3-1
Eat(eat)

```
</p>
</details>