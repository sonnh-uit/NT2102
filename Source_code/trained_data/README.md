Để chạy công cụ đầu tiên cần thực hiện:
* Chạy công cụ ở mode train:
B1: Mở msfconsole chạy câu lệnh: 
    load msgrpc ServerHost=<IP_host> ServerPort=<Port_host> User=<username> Pass=<password>
    Trong đó:
    IP_host : địa chỉ IP của máy đang chạy công cụ
    Port_host : port muốn mở để lắng nghe trên máy đang chạy công cụ
    username, password : giá trị tùy theo người dùng
B2: Mở file config.ini và sửa lại các giá trị:
    server_host = IP_host
    server_port = Port_host
    msgrpc_user = username
    msgrpc_pass = password
B3: Chạy câu lệnh sau để training 
    python3 DeepExploit.py -t <IP_target> -m train
    Trong đó:
    IP_target : địa chỉ IP của training server
--> Sau khi training sẽ xuất hiện thư mục Value lưu trữ kết quả trong quá trình training như: loss value, bingo, step,... mục đích cho người dùng có thể tổng hợp lại kết quả của nhiều lần training nếu muốn.
--> Muốn training tiếp thì cần đổi tên hoặc xóa thư mục Value đó đi.

* Chạy công cụ ở mode test:
B1 và B2 như mode train.
B3: Chạy câu lệnh sau để testing:
    python3 DeepExploit.py -t <IP_target> -m test
    Trong đó:
    IP_target : địa chỉ IP của testing server
--> Sau khi chạy xong nếu khai thác thành công thì sẽ lưu lại session ở msfconsole. Chỉ cần gọi ID của session muốn sử dụng.