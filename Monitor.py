#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from datetime import datetime
import os
import sys
import json
import logging
import subprocess
from typing import Dict, Any, Optional
import xml.etree.ElementTree as ET
import signal
import time
from collections import deque
import threading
import hashlib

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

        # FPS 計數相關
        self.image_timestamps = deque()
        self.current_fps = 0
        self.fps_lock = threading.Lock()
        self.last_fps_display_time = 0
        self.fps_display_interval = 1.0  # 每多少秒顯示一次FPS
        self.image_save = None # 是否儲存每一幀影像
        self.image_save_path = None

        # JPEG完整幀檢測變數
        self.jpeg_buffer = bytearray()  # 累積JPEG數據
        self.in_jpeg_frame = False  # 是否正在接收JPEG幀
        self.jpeg_start_marker = bytes.fromhex('ffd8')  # JPEG開始標記
        self.jpeg_end_marker = bytes.fromhex('ffd9')  # JPEG結束標記

        # 幀去重複相關變數
        self.frame_hashes = deque(maxlen=100)  # 保存最近100幀的hash值
        self.frame_timestamps = {}  # 儲存幀的時間戳記
        self.current_stream_time = None  # 當前幀的時間戳記
        self.frame_hash_lock = threading.Lock()

        # JPEG驗證
        self.min_jpeg_size = 1024  # 最小JPEG大小（bytes）
        self.max_jpeg_size = 10 * 1024 * 1024  # 最大JPEG大小（10MB）

        # 簡單統計
        self.total_packets = 0  # 總封包數
        self.complete_frames = 0  # 完整幀數
        self.duplicate_frames = 0  # 重複幀數

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
                "listen_role",
                "listen_port",
                "service_type",
                "fps_display_interval",
                "target_ip",
                "target_port",
                "debug",
                "proto_path",
                "image_save"
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
        self.fps_display_interval = float(self.config['fps_display_interval'])  # 多久顯示一次fps數值更新
        self.image_save = self.config['image_save']
        self.image_save_path = self.config['image_save_path']
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
        if signum == 2 or signum == 15:
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

                # 解析 Protocol Buffers 資訊
                if proto_name == 'protobuf':
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
                    'value': field.get('value', ''),  # 加入空字串預設值
                    'nested_fields': []
                }

                fields_list.append(field_info)

    def _get_image_fields(self, fields: list, indent: int = 0):
        """處理JPEG分片並重組完整幀"""
        # 重置當前幀的時間戳
        self.current_stream_time = None

        for field in fields:
            if isinstance(field.get('value'), str) and field['value']:
                # 只處理包含數據的欄位
                hex_data = field['value']
                if len(hex_data) > 8:  # 過濾太短的data
                    self._process_jpeg_data(hex_data)

    def _get_time_fields(self, fields: list):
        """提取時間欄位"""
        for field in fields:
            if field['name'] == 'protobuf.field.value.int64':
                try:
                    stream_time = int(field.get('show'))
                    self.current_stream_time = stream_time
                    self.latency_count(stream_time)
                except (ValueError, TypeError):
                    if self.DEBUG_MODE:
                        print(f"無法解析時間戳記: {field.get('show')}")

    def _process_jpeg_data(self, hex_data: str):
        """處理JPEG數據分片"""
        try:
            data_bytes = bytes.fromhex(hex_data)
            self.total_packets += 1

            # 檢測JPEG開始標記
            jpeg_start_pos = data_bytes.find(self.jpeg_start_marker)
            if jpeg_start_pos != -1:
                # 如果正在處理前一幀，先完成它
                if self.in_jpeg_frame and len(self.jpeg_buffer) > 0:
                    self._complete_current_frame()

                # 開始新幀
                self.in_jpeg_frame = True
                self.jpeg_buffer = bytearray()
                self.jpeg_buffer.extend(data_bytes[jpeg_start_pos:])

                if self.DEBUG_MODE:
                    print(f"新JPEG幀開始")

            elif self.in_jpeg_frame:
                # 累積數據
                self.jpeg_buffer.extend(data_bytes)

            # 檢測JPEG結束標記
            jpeg_end_pos = data_bytes.find(self.jpeg_end_marker)
            if jpeg_end_pos != -1 and self.in_jpeg_frame:
                self._complete_current_frame()

        except ValueError:
            if self.DEBUG_MODE:
                print("警告: 無效的十六進位數據")
        except Exception as e:
            if self.DEBUG_MODE:
                print(f"JPEG處理錯誤: {e}")

    def _complete_current_frame(self):
        """完成當前JPEG幀"""
        if not self.in_jpeg_frame or len(self.jpeg_buffer) == 0:
            return

        frame_size = len(self.jpeg_buffer)

        # JPEG驗證
        if not self._is_valid_jpeg_enhanced():
            if self.DEBUG_MODE:
                print(f"無效的JPEG幀，大小: {frame_size} bytes")
            self._reset_frame_state()
            return

        # 計算幀的hash值用於去重複幀
        frame_hash = self._calculate_frame_hash(self.jpeg_buffer)

        # 檢查是否為重複幀
        if self._is_duplicate_frame(frame_hash):
            self.duplicate_frames += 1
            if self.DEBUG_MODE:
                print(f"檢測到重複幀 (Hash: {frame_hash[:8]}...), 總重複數: {self.duplicate_frames}")
            self._reset_frame_state()
            return

        # 這是新的一幀
        self.complete_frames += 1
        self._add_frame_hash(frame_hash)

        # 計入FPS
        self.fps_count()

        if self.DEBUG_MODE:
            print(f"完整JPEG幀: {frame_size:,} 字節 (總計: {self.complete_frames}, 重複: {self.duplicate_frames})")
            print(f"幀Hash: {frame_hash[:8]}...")

        # 儲存影像
        if self.image_save:
            self.save_image_bytes(self.jpeg_buffer, frame_hash)

        # 重置狀態
        self._reset_frame_state()

    def _is_valid_jpeg_enhanced(self):
        """驗證JPEG有效性"""
        if len(self.jpeg_buffer) < self.min_jpeg_size:
            return False

        if len(self.jpeg_buffer) > self.max_jpeg_size:
            return False

        # 檢查JPEG標頭和結尾
        has_start = self.jpeg_buffer[:2] == self.jpeg_start_marker
        has_end = self.jpeg_buffer[-2:] == self.jpeg_end_marker

        if not (has_start and has_end):
            return False

        # 檢查JPEG檔案結構的基本標記
        # 尋找APP0標記 (FFE0) 或其他常見的JPEG標記
        has_app_marker = False
        for i in range(2, min(20, len(self.jpeg_buffer) - 1)):
            if self.jpeg_buffer[i] == 0xFF:
                next_byte = self.jpeg_buffer[i + 1]
                # 檢查是否為有效的JPEG標記
                if next_byte in [0xE0, 0xE1, 0xE2, 0xDB, 0xC0, 0xC4]:  # APP0, APP1, APP2, DQT, SOF0, DHT
                    has_app_marker = True
                    break

        return has_app_marker

    def _calculate_frame_hash(self, frame_data: bytearray) -> str:
        """計算幀的SHA256 hash值"""
        return hashlib.sha256(frame_data).hexdigest()

    def _is_duplicate_frame(self, frame_hash: str) -> bool:
        """檢查是否為重複幀"""
        with self.frame_hash_lock:
            return frame_hash in self.frame_hashes

    def _add_frame_hash(self, frame_hash: str):
        """添加每一幀的hash到 frame_hashes 中"""
        with self.frame_hash_lock:
            self.frame_hashes.append(frame_hash)
            # 如果有時間戳記，也記錄下來
            if self.current_stream_time:
                self.frame_timestamps[frame_hash] = self.current_stream_time

    def _reset_frame_state(self):
        """重置幀數處理狀態"""
        self.in_jpeg_frame = False
        self.jpeg_buffer = bytearray()
        self.current_stream_time = None

    def save_image_bytes(self, image_bytes: bytearray, frame_hash: str = None):
        """儲存完整的JPEG影像bytes"""
        try:
            # 確保儲存資料夾存在
            if not os.path.exists(self.image_save_path):
                os.makedirs(self.image_save_path)

            # 產生以當前時間和hash為名稱的檔案名
            current_time = datetime.now()
            timestamp = current_time.strftime("%Y%m%d_%H%M%S_%f")

            if frame_hash:
                filename = f"{timestamp}_{frame_hash[:8]}.jpg"
            else:
                filename = f"{timestamp}.jpg"

            # 完整檔案路徑
            file_path = os.path.join(self.image_save_path, filename)

            # 寫入檔案
            with open(file_path, 'wb') as f:
                f.write(image_bytes)

            logging.info(f"完整影像已儲存至: {file_path}")
            return file_path

        except Exception as e:
            logging.error(f"儲存影像失敗: {e}")
            return None

    def fps_count(self):
        """FPS計數功能 - 只計算完整且非重複的JPEG幀"""
        current_time = time.time()
        with self.fps_lock:
            # 添加當前時間戳
            self.image_timestamps.append(current_time)

            # 移除超過1秒的舊時間戳
            while self.image_timestamps and current_time - self.image_timestamps[0] > 1.0:
                self.image_timestamps.popleft()

            # 更新當前FPS
            self.current_fps = len(self.image_timestamps)

            # 每時間間隔顯示一次FPS
            if current_time - self.last_fps_display_time >= self.fps_display_interval:
                self.last_fps_display_time = current_time
                print(f"[真實FPS] 完整且唯一幀率: {self.current_fps} fps (排除重複: {self.duplicate_frames})")
                logging.info(f"Real Unique Frame FPS: {self.current_fps}, Duplicates: {self.duplicate_frames}")

        return self.current_fps

    def latency_count(self,stream_time_int64):
        current_time = int(time.time_ns() // 1_000_000) #取得目前時間到毫秒
        # print(current_time)
        # print(stream_time_int64)

        latency_time = current_time - stream_time_int64
        if self.DEBUG_MODE:
            print(f"延遲為 {latency_time} 毫秒")
        print(f"延遲為 {latency_time} 毫秒")

    def monitor(self):
        if not self._check_tshark_(): # 確認是否有安裝Wireshark
            sys.exit(5)

        cmd = self._build_tshark_command()

        if self.DEBUG_MODE:
            print(f"執行命令: {' '.join(cmd)}")
            print("開始監聽影像流，FPS計數器已啟動...")  # 更新這行
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
                            self._get_time_fields(packet_data['protobuf_fields'])  # 一定要先計算延遲
                            self._get_image_fields(packet_data['protobuf_fields'], indent=1)  # 再處理影片，不然延遲會大幅增加

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

def main():
    sender = Sender()
    success = sender.start_process()

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()