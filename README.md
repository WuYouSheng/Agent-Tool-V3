# Agent-Tool-V3


  "interface": "en0", // 監聽介面
  "listen_role": "src", //監聽的Port 是接收(dst)還是發送端(src)
  "listen_port": 50051, //間聽Port
  "service_type": "Sender", //服務本身是發送端還是接收端
  "time_gap": 1, 
  "target_ip": "10.52.52.97", //目標主機
  "target_port": 9999, //目標主機Port
  "max_packet_size": 1000,
  "debug":true, //啟動註解觀看
  "proto_path":"./Protobuf/" //Protofile 存存位置

