#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import json
import logging
import subprocess
from typing import Dict, Any, Optional
import xml.etree.ElementTree as ET
import signal



class Sender:
    def __init__(self, config_path="./sender_config.json"):
        # Log.log define
        self.DEBUG_MODE = True
        self.log_path = None
        self.format = None
        self.logging_setting()

        # config define
        self.config_path = config_path
        self.config = {}

        # Monitoring
        self.protobuf_path = None
        self.listen_role = None
        self.listen_port = None
        self.interface = None
        self.tshark_process = None

        signal.signal(signal.SIGINT, self._signal_handler)  # 處理Ctrl + c 中斷訊號，signal.SIGINT 為 2
        signal.signal(signal.SIGTERM, self._signal_handler)  # 處理其他程式中斷訊號，signal.SIGTERM 為 15

    def start_process(self):
        if not self.load_config():  # 載入config.json 檔案
            sys.exit(2)
        if not self.apply_config():  # 套用config.json 檔案
            sys.exit(4)

        self.monitor()  # 啟動監聽

        return True


    def load_config(self):
        """載入完整配置"""
        try:
            with open(self.config_path) as f:
                self.config = json.load(f)

            # 驗證 service_type
            service_type = self.config.get("service_type","").lower() #強制轉換為小寫便於處理
            if service_type != "sender":
                logging.error(f"This module only support 'Sender' mode, and current mode is {service_type}")
                raise ValueError(f"此模組僅支援 Sender 模式，當前配置: {service_type}")

            # 驗證必要的配置項目
            required_keys = [
                "interface",
                "listen_port",
                "listen_role",
                "service_type",
                "target_ip",
                "target_port",
                "debug",
                "proto_path"
            ]

            missing_keys = [key for key in required_keys if key not in self.config]
            if missing_keys:
                logging.critical(f'Missing required value')
                raise ValueError(f"配置檔案缺少必要項目: {missing_keys}")

            self.DEBUG_MODE = self.config['debug'] if isinstance(self.config['debug'], bool) else self.config['debug'].lower() == 'true'

            if self.DEBUG_MODE:
                logging.getLogger().setLevel(logging.DEBUG) # DEBUG模式 將log 的level 改為 DEBUG 10
                print("=== 發送端端配置載入成功 ===")
                print(f"服務模式: 發送端")
                print(f"監聽介面: {self.config['interface']}")
                print(f"監聽Port: {self.config['listen_port']}")
                print(f"發送目標: {self.config['target_ip']}:{self.config['target_port']}")
                print("=" * 30)

                logging.info("Successfully Load config.json")
                logging.info("Service Type: Sender")
                logging.info(f"Monitoring interface: {self.config['interface']}")
                logging.info(f"Monitoring Port: {self.config['listen_port']}")
                logging.info(f"Sending Target: {self.config['target_ip']}:{self.config['target_port']}")

            return True

        except FileNotFoundError:
            print(f"配置檔案未找到: {self.config_path}")
            logging.error(f'File {self.config_path} not found')
            return False
        except json.JSONDecodeError as e:
            print(f"配置檔案JSON格式錯誤: {e}")
            logging.error(f'JSON Format Error: {e} ')
            return False
        except Exception as e:
            print(f"載入config 時發生錯誤: {e}")
            logging.critical(f'Loading config.json error: {e} ')
            return False
    def apply_config(self):
        self.protobuf_path = self.config['proto_path']  # 讀取proto檔案
        self.listen_role = self.config['listen_role']  # 被監聽的Port是接收端還是發送端
        self.listen_port = self.config['listen_port']  # 監聽Port
        self.interface = self.config['interface']  # 監聽介面
        return True

    def logging_setting(self):
        # 定義輸出格式
        self.format = '%(asctime)s %(filename)s %(levelname)s:%(message)s'
        self.log_path = './Log.log' # 儲存目錄
        logging.basicConfig(level=logging.ERROR,format=self.format,filename=self.log_path,filemode='w')

    def _build_tshark_command(self) -> list:
        """構建 tshark 命令"""

        # 基本命令結構
        cmd = [
            'tshark',
            '-i', f'{self.interface}',
            '-f', f'{self.listen_role} port {self.listen_port}',
            '-Y', 'grpc',
            '-T', 'pdml',
            '-l',
        ]

        # 檢查並添加 protobuf 解析選項
        proto_files = self._find_proto_files()
        if proto_files:
            # 添加搜尋路徑
            cmd.extend(['-o', f'protobuf.search_paths:{self.protobuf_path}'])

            if self.DEBUG_MODE:
                print("Wireshark 將使用這些 proto 檔案進行解析")

            logging.info(f"Protobuf search path set: {self.protobuf_path}")
            logging.info(f"Proto files found: {', '.join(proto_files)}")
        else:
            if self.DEBUG_MODE:
                print("未找到 proto 檔案")
            logging.warning("No proto files found")

        return cmd

    def _check_tshark_(self):
        result = subprocess.run(['tshark', '--version'],capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            logging.info(f"tshark version : {result}")
            return True
        else:
            logging.error(f"tshark is not available.")
            return False

    def _signal_handler(self, signum, frame):
        # frame不可省略，必須帶入此參數
        if signum==2 or signum==15:
            """處理中斷信號"""
            print(f"\n收到信號 {signum}，正在停止監聽...")
            self.stop()

    def _find_proto_files(self)->list:
        """尋找 proto 檔案"""
        proto_files = []
        for file in os.listdir(self.protobuf_path):
            if file.endswith('.proto'):
                proto_files.append(file)

        if proto_files:
            if self.DEBUG_MODE:
                print(f"找到 proto 檔案: {', '.join(proto_files)}")
            logging.info(f"proto file :{', '.join(proto_files)}")
        else:
            if self.DEBUG_MODE:
                print("未找到 proto 檔案")
            logging.info(f"There is no proto file in the path")

        return proto_files

    def _parse_pdml_packet(self, pdml_data: str) -> Optional[Dict[str, Any]]:
        """解析 PDML 格式的封包數據"""
        try:
            root = ET.fromstring(pdml_data)
            packet_info = {
                'timestamp': None,
                'source': None,
                'destination': None,
                'stream_id': None,
                'grpc_message_type': None,
                'grpc_data': [],
                'protobuf_fields': []
            }

            # 解析封包基本資訊
            for proto in root.findall('.//proto'):
                proto_name = proto.get('name', '')

                # 解析 gRPC 層資訊
                if proto_name == 'grpc':
                    grpc_message = proto.find('.//field[@name="grpc.message_type"]')
                    if grpc_message is not None and grpc_message.get('show') == '1':
                        # gRPC DATA 訊息
                        packet_info['grpc_message_type'] = 'DATA'
                        logging.info(f"gRPC DATA: {packet_info['grpc_message_type']}")
                        if self.DEBUG_MODE:
                            print(f"gRPC DATA: {packet_info['grpc_message_type']}")

                # 解析 Protocol Buffers 資訊
                elif proto_name == 'protobuf':
                    self._extract_protobuf_fields(proto, packet_info['protobuf_fields'])

            return packet_info if packet_info['protobuf_fields'] else None

        except ET.ParseError as e:
            print(f"PDML 解析錯誤: {e}")
            return None
        except Exception as e:
            print(f"封包解析錯誤: {e}")
            return None

    def _extract_protobuf_fields(self, proto_element, fields_list: list):
        """遞迴提取 Protocol Buffers 欄位值"""
        for field in proto_element.findall('.//field'):
            field_name = field.get('name', '')

            # 尋找 protobuf 欄位
            if field_name.startswith('protobuf.field'):
                field_info = {
                    'name': field_name,
                    'show': field.get('show'),
                    'value': field.get('value'),
                    'nested_fields': []
                }

                # 遞迴處理巢狀訊息
                nested_messages = field.findall('.//field[@name="protobuf.message"]')
                for nested_msg in nested_messages:
                    self._extract_protobuf_fields(nested_msg, field_info['nested_fields'])

                fields_list.append(field_info)

    def _print_protobuf_fields(self, fields: list, indent: int = 0):
        """遞迴列印 Protocol Buffers 欄位"""
        prefix = "  " * indent  # 縮排

        for field in fields:
            if "ffd9" in field['value'] and "ffd8" in field['value']:  # ffd8 開頭、 ffd9 結尾 為JPEG固定二進位編碼
                if self.DEBUG_MODE:
                    print(f"{prefix}  原始值: {field['value']}")
                    logging.info("Capture a JPEG image")

    def monitor(self):
        if not self._check_tshark_(): # 確認是否有安裝Wireshark
            sys.exit(5)

        cmd = self._build_tshark_command()

        if self.DEBUG_MODE:
            print(f"執行命令: {' '.join(cmd)}")
            print("-" * 60)

        try:
            self.tshark_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            ) # 建立一個tshark 的子process

            # 讀取 tshark 輸出
            pdml_buffer = ""
            in_packet = False

            for line in self.tshark_process.stdout:
                line = line.strip()

                # 檢測封包開始
                if line.startswith('<packet>'):
                    in_packet = True
                    pdml_buffer = line + '\n'
                elif in_packet:
                    pdml_buffer += line + '\n'

                    # 檢測封包結束
                    if line.startswith('</packet>'):
                        packet_data = self._parse_pdml_packet(pdml_buffer)
                        if packet_data:
                            if self.DEBUG_MODE:
                                self._print_protobuf_fields(packet_data['protobuf_fields'], indent=1)

                        # 重置緩衝區
                        pdml_buffer = ""
                        in_packet = False

        except KeyboardInterrupt:
            print("\n收到中斷信號，停止監聽...")
        except Exception as e:
            print(f"監聽過程中發生錯誤: {e}")
        finally:
            self.stop()
    def stop(self):
        """停止監聽"""
        if self.tshark_process:
            try:
                self.tshark_process.terminate()
                self.tshark_process.wait(timeout=5)
                logging.info(f"Listening Terminate")
            except subprocess.TimeoutExpired:
                self.tshark_process.kill()
                logging.info(f"Listening Terminate")
            except Exception as e:
                print(f"停止 tshark 時發生錯誤: {e}")
                logging.info(f"Listening Terminate ERROR")
            finally:
                self.tshark_process = None

        print("監聽已停止")


def main():
    sender = Sender()
    success = sender.start_process()

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
