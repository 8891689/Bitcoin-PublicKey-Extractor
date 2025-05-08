# author：8891689
import requests
import json
import sys
import hashlib
import logging
import time
import io
import re
import concurrent.futures # 导入多线程模块
import threading # 用于线程安全的计数器

# ANSI colors
C_RED = "\x1b[31m"
C_GREEN = "\x1b[32m"
C_YELLOW = "\x1b[33m"
C_MAG = "\x1b[35m" # Magenta
C_CYAN = "\x1b[36m"
C_RESET = "\x1b[0m"

# 设置日志记录
# 确保日志文件写入，控制台输出使用INFO级别
logging.basicConfig(filename='block_processing.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO) # 在控制台只显示 INFO 及以上的消息
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)

# 避免重复添加 console handler
# 使用 logger 对象来检查，而不是 logging 模块
main_logger = logging.getLogger()
if not any(isinstance(h, logging.StreamHandler) for h in main_logger.handlers):
     main_logger.addHandler(console_handler)

# RPC 连接设置 (从配置文件加载)
# 这些变量会在 load_rpc_config 中被赋值
RPC_HOST = ''
RPC_PORT = ''
RPC_USER = ''
RPC_PASSWORD = ''
RPC_URL = ''
RPC_CONFIG_FILE = 'rpc_config.json'
NUM_WORKERS = 1 # 默认线程数

# RPC 连续失败计数器和阈值 (全局共享，使用锁保护)
RPC_CONSECUTIVE_FAILURES = 0
RPC_FAILURE_THRESHOLD = 10 # 连续失败 10 次后触发等待

# 比特币脚本操作码
OP_PUSHDATA1 = 0x4c # 76
OP_PUSHDATA2 = 0x4d # 77
OP_PUSHDATA4 = 0x4e # 78
OP_0 = 0x00       # 0

# 公钥十六进制格式的正则表达式 (只包含压缩和非压缩)
# Compressed: 33 bytes (66 hex), starts with 02 or 03
# Uncompressed: 65 bytes (130 hex), starts with 04
PUBKEY_HEX_REGEX = re.compile(r'^(02|03)[0-9a-fA-F]{64}$|^04[0-9a-fA-F]{128}$')

# 用于在多线程环境下安全更新总计数器和失败计数器
global_state_lock = threading.Lock()
total_keys_extracted_value = 0
processed_blocks_count = 0 # 添加已完成区块计数器

def load_rpc_config(filename):
    """从 JSON 文件加载 RPC 配置"""
    # 这些变量只在此函数中被赋值（首次写入），需要 global
    global RPC_HOST, RPC_PORT, RPC_USER, RPC_PASSWORD, RPC_URL, NUM_WORKERS
    try:
        with open(filename, 'r') as f:
            config = json.load(f)

            RPC_HOST = config.get('rpc_host', '127.0.0.1')
            RPC_PORT = str(config.get('rpc_port', 8332))
            RPC_USER = config.get('rpc_user')
            RPC_PASSWORD = config.get('rpc_password')
            # 读取线程数，默认为 1，确保至少为 1
            NUM_WORKERS = max(1, int(config.get('num_workers', 1)))
            RPC_URL = f'http://{RPC_HOST}:{RPC_PORT}'

            if not RPC_USER or not RPC_PASSWORD:
                 raise ValueError("RPC user and password must be specified in the config file.")

            logging.info(f"{C_GREEN}成功从 {filename} 加载 RPC 配置.{C_RESET}")
            logging.info(f"RPC 连接到 {RPC_URL} with user {RPC_USER}")
            print(f"{C_GREEN}成功加载 RPC 配置.{C_RESET} RPC URL: {RPC_URL}")
            print(f"{C_CYAN}使用 {NUM_WORKERS} 个工作线程.{C_RESET}")

    except FileNotFoundError:
        logging.critical(f"错误：找不到 RPC 配置文件: {filename}")
        print(f"{C_RED}错误：找不到 RPC 配置文件: {filename}{C_RESET}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.critical(f"错误：RPC 配置文件 {filename} 格式无效: {e}")
        print(f"{C_RED}错误：RPC 配置文件 {filename} 格式无效: {e}{C_RESET}")
        sys.exit(1)
    except ValueError as e:
        logging.critical(f"错误：RPC 配置文件 {filename} 内容无效: {e}")
        print(f"{C_RED}错误：RPC 配置文件 {filename} 内容无效: {e}{C_RESET}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"加载 RPC 配置文件时发生未知错误: {e}", exc_info=True)
        print(f"{C_RED}加载 RPC 配置文件时发生未知错误: {e}{C_RESET}")
        sys.exit(1)


def rpc_request(method, params=None):
    # 这些变量在此函数中会被修改，需要 global
    global RPC_CONSECUTIVE_FAILURES, global_state_lock

    headers = {'Content-Type': 'application/json'}
    payload = {
        "jsonrpc": "1.0",
        "id": f"python_rpc_{threading.current_thread().ident}_{int(time.time()*1000)}", # 添加线程ID和时间戳到请求ID
        "method": method,
        "params": params or []
    }

    # RPC_URL, RPC_USER, RPC_PASSWORD 是全局的，但在这里只读，不需要 global 声明
    if not all([RPC_URL, RPC_USER, RPC_PASSWORD]):
         logging.critical("RPC 配置未加载或不完整，无法发起请求。")
         print(f"{C_RED}RPC 配置未加载或不完整，无法发起请求。{C_RESET}")
         return None # 返回 None 表示失败

    # 尝试 5 次
    for attempt in range(5):
        try:
            response = requests.post(
                RPC_URL,
                auth=(RPC_USER, RPC_PASSWORD),
                headers=headers,
                data=json.dumps(payload),
                timeout=120 # 120秒超时
            )
            response.raise_for_status() # HTTP 错误也会抛出异常

            response_data = response.json()

            if 'error' in response_data and response_data['error']:
                error = response_data['error']
                # 检查一些可忽略的错误码或消息
                ignorable_errors = [-5, -8, -25]
                error_message = error.get('message', '')
                if error.get('code') in ignorable_errors or "No such mempool or blockchain transaction" in error_message:
                     logging.warning(f"线程 {threading.current_thread().ident}: RPC 错误（可能可忽略） ({method} {params}): {error_message}")
                     # 可忽略的错误不计入连续失败，但也不算成功，不重置计数器
                     return None # 返回 None 表示该RPC调用未能获取有效数据
                else:
                    # 不可忽略的RPC错误
                    logging.error(f"线程 {threading.current_thread().ident}: RPC 错误 ({method} {params}, 尝试 {attempt+1}/5): {error}")
                    with global_state_lock: # 在更新全局失败计数器时加锁
                        RPC_CONSECUTIVE_FAILURES += 1
                        current_failures = RPC_CONSECUTIVE_FAILURES # 读取变量在这里发生，global 声明需要在之前

                    if current_failures >= RPC_FAILURE_THRESHOLD:
                        logging.critical(f"\nRPC 连接连续失败 {RPC_FAILURE_THRESHOLD} 次。请检查你的节点和配置。")
                        print(f"\n{C_RED}RPC 连接连续失败 {RPC_FAILURE_THRESHOLD} 次。请检查你的节点和配置。{C_RESET}")
                        print(f"{C_YELLOW}按任意键继续... (或按 Ctrl+C 退出){C_RESET}")

                        # --- 等待用户输入 ---
                        # 注意：在多线程环境下，多个线程同时调用 input() 可能导致不可预测的行为。
                        # 一个更健壮的实现会将等待逻辑集中到主线程。
                        # 此处保留原脚本的直接修改方式。
                        try:
                            input() # 等待用户按回车
                        except KeyboardInterrupt:
                            print(f"\n{C_RED}用户中断，程序退出。{C_RESET}")
                            logging.critical("用户中断，程序退出。")
                            sys.exit(1) # 用户选择退出

                        # 用户输入后，重置连续失败计数器
                        with global_state_lock:
                             RPC_CONSECUTIVE_FAILURES = 0
                        print(f"{C_YELLOW}继续执行...{C_RESET}")
                        logging.info("RPC 失败计数器已重置，继续执行。")

                        # 重置计数器后，不立即退出，而是继续尝试当前RPC请求
                        time.sleep(2) # 稍微等待一下再重试
                        continue # 跳到下一个尝试

                    # 未达到阈值，只是单次 RPC 错误，等待后重试
                    time.sleep(10) # 等待一段时间后重试
                    continue # 跳到下一个尝试


            # 请求成功 (HTTP 和 RPC 调用都成功)
            with global_state_lock: # 在重置全局失败计数器时加锁
                 RPC_CONSECUTIVE_FAILURES = 0
            return response_data['result']

        except requests.exceptions.RequestException as e:
            # HTTP 请求级别的失败 (连接错误、超时等)
            logging.error(f"线程 {threading.current_thread().ident}: RPC 请求失败 ({method} {params}, 尝试 {attempt+1}/5): {e}")
            with global_state_lock: # 在更新全局失败计数器时加锁
                RPC_CONSECUTIVE_FAILURES += 1
                current_failures = RPC_CONSECUTIVE_FAILURES

            if current_failures >= RPC_FAILURE_THRESHOLD:
                logging.critical(f"\nRPC 连接连续失败 {RPC_FAILURE_THRESHOLD} 次。请检查你的节点和配置。")
                print(f"\n{C_RED}RPC 连接连续失败 {RPC_FAILURE_THRESHOLD} 次。请检查你的节点和配置。{C_RESET}")
                print(f"{C_YELLOW}按任意键继续... (或按 Ctrl+C 退出){C_RESET}")
                # --- 等待用户输入 ---
                try:
                    input() # 等待用户按回车
                except KeyboardInterrupt:
                    print(f"\n{C_RED}用户中断，程序退出。{C_RESET}")
                    logging.critical("用户中断，程序退出。")
                    sys.exit(1) # 用户选择退出

                # 用户输入后，重置连续失败计数器
                with global_state_lock:
                     RPC_CONSECUTIVE_FAILURES = 0
                print(f"{C_YELLOW}继续执行...{C_RESET}")
                logging.info("RPC 失败计数器已重置，继续执行。")

                # 重置计数器后，不立即退出，而是继续尝试当前RPC请求
                time.sleep(2) # 稍微等待一下再重试
                continue # 跳到下一个尝试

            # 未达到阈值，等待后重试
            time.sleep(10)
            continue # 跳到下一个尝试

        except json.JSONDecodeError:
            # RPC 返回无效 JSON
            logging.error(f"线程 {threading.current_thread().ident}: RPC 返回无效 JSON ({method} {params}, 尝试 {attempt+1}/5): {response.text if 'response' in locals() and response else '无响应'}")
            with global_state_lock: # 在更新全局失败计数器时加锁
                RPC_CONSECUTIVE_FAILURES += 1
                current_failures = RPC_CONSECUTIVE_FAILURES

            if current_failures >= RPC_FAILURE_THRESHOLD:
                 logging.critical(f"\nRPC 返回无效 JSON 连续 {RPC_FAILURE_THRESHOLD} 次。请检查 RPC 服务器响应。")
                 print(f"\n{C_RED}RPC 返回无效 JSON 连续 {RPC_FAILURE_THRESHOLD} 次。请检查 RPC 服务器响应。{C_RESET}")
                 print(f"{C_YELLOW}按任意键继续... (或按 Ctrl+C 退出){C_RESET}")
                 # --- 等待用户输入 ---
                 try:
                    input() # 等待用户按回车
                 except KeyboardInterrupt:
                    print(f"\n{C_RED}用户中断，程序退出。{C_RESET}")
                    logging.critical("用户中断，程序退出。")
                    sys.exit(1) # 用户选择退出

                 # 用户输入后，重置连续失败计数器
                 with global_state_lock:
                      RPC_CONSECUTIVE_FAILURES = 0
                 print(f"{C_YELLOW}继续执行...{C_RESET}")
                 logging.info("RPC 失败计数器已重置，继续执行。")
                 time.sleep(2) # 稍微等待一下再重试
                 continue # 跳到下一个尝试

        except Exception as e:
             # 其他未知错误
             logging.error(f"线程 {threading.current_thread().ident}: RPC 请求发生未知错误 ({method} {params}, 尝试 {attempt+1}/5): {e}", exc_info=True)
             with global_state_lock: # 在更新全局失败计数器时加锁
                 RPC_CONSECUTIVE_FAILURES += 1
                 current_failures = RPC_CONSECUTIVE_FAILURES

             if current_failures >= RPC_FAILURE_THRESHOLD:
                  logging.critical(f"\nRPC 请求发生未知错误连续 {RPC_FAILURE_THRESHOLD} 次：{e}.")
                  print(f"\n{C_RED}RPC 请求发生未知错误连续 {RPC_FAILURE_THRESHOLD} 次：{e}.{C_RESET}")
                  print(f"{C_YELLOW}按任意键继续... (或按 Ctrl+C 退出){C_RESET}")
                  # --- 等待用户输入 ---
                  try:
                     input() # 等待用户按回车
                  except KeyboardInterrupt:
                     print(f"\n{C_RED}用户中断，程序退出。{C_RESET}")
                     logging.critical("用户中断，程序退出。")
                     sys.exit(1) # 用户选择退出

                  # 用户输入后，重置连续失败计数器
                  with global_state_lock:
                       RPC_CONSECUTIVE_FAILURES = 0
                  print(f"{C_YELLOW}继续执行...{C_RESET}")
                  logging.info("RPC 失败计数器已重置，继续执行。")
                  time.sleep(2) # 稍微等待一下再重试
                  continue # 跳到下一个尝试

    # 所有尝试都失败了
    logging.critical(f"线程 {threading.current_thread().ident}: RPC 请求 {method} {params} 多次尝试后仍然失败。跳过处理。")
    # 返回 None 让调用者知道这次RPC调用失败了
    return None

def get_block_hash(block_height):
    # 如果 rpc_request 返回 None (表示失败或忽略错误)，这里也会返回 None
    return rpc_request('getblockhash', [block_height])

def get_block(block_hash):
    if not block_hash: # 如果 block_hash 是 None (例如上一步 get_block_hash 失败了)
        return None
    # 使用 verbosity 2 获取完整的交易数据
    # 如果 rpc_request 返回 None (表示失败或忽略错误)，这里也会返回 None
    return rpc_request('getblock', [block_hash, 2])

def is_valid_pubkey_hex(hex_string):
    """检查字符串是否匹配公钥十六进制格式"""
    if not isinstance(hex_string, str):
        return False
    return PUBKEY_HEX_REGEX.match(hex_string) is not None

def parse_script_hex(script_hex):
    """
    解析脚本的十六进制表示，提取 push 的数据。
    返回一个列表，包含所有被 push 的数据（十六进制字符串）。
    如果在解析過程中遇到錯誤（例如數據不足），會記錄警告並停止該腳本的解析。
    """
    data_pushes = []
    if not script_hex: # 处理空脚本
        return data_pushes
    try:
        # 检查 hex_string 长度是否为偶数
        if len(script_hex) % 2 != 0:
             logging.warning(f"线程 {threading.current_thread().ident}: 脚本 hex 长度为奇数，无效: {script_hex}")
             return []

        script_bytes = bytes.fromhex(script_hex)
        script_io = io.BytesIO(script_bytes)
        script_len = len(script_bytes)

        while script_io.tell() < script_len:
            current_pos = script_io.tell() # Bytes position
            opcode = script_io.read(1)
            if not opcode:
                break # 脚本结束或读取失败

            opcode_val = opcode[0]

            if opcode_val == OP_0:
                 data_pushes.append("") # Represent OP_0 as empty hex string
                 continue

            # OP_PUSHBYTES_1 to OP_PUSHBYTES_75
            if 0x01 <= opcode_val <= 0x4b:
                data_len = opcode_val
                if script_io.tell() + data_len > script_len:
                    logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 数据长度 ({data_len}) 超出脚本边界. Script: {script_hex}, pos: {current_pos*2}.")
                    break # 停止解析当前脚本
                data = script_io.read(data_len)
                data_pushes.append(data.hex())

            elif opcode_val == OP_PUSHDATA1:
                 if script_io.tell() + 1 > script_len:
                      logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 读取 PUSHDATA1 长度字节不足. Script: {script_hex}, pos: {current_pos*2}.")
                      break # 停止解析当前脚本
                 len_bytes = script_io.read(1)
                 data_len = len_bytes[0]
                 if script_io.tell() + data_len > script_len:
                      logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 读取 PUSHDATA1 数据长度 ({data_len}) 超出脚本边界. Script: {script_hex}, pos: {current_pos*2}.")
                      break # 停止解析当前脚本
                 data = script_io.read(data_len)
                 data_pushes.append(data.hex())

            elif opcode_val == OP_PUSHDATA2:
                 if script_io.tell() + 2 > script_len:
                      logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 读取 PUSHDATA2 长度字节不足. Script: {script_hex}, pos: {current_pos*2}.")
                      break # 停止解析当前脚本
                 len_bytes = script_io.read(2)
                 # int.from_bytes requires byteorder
                 data_len = int.from_bytes(len_bytes, 'little')
                 if script_io.tell() + data_len > script_len:
                      logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 读取 PUSHDATA2 数据长度 ({data_len}) 超出脚本边界. Script: {script_hex}, pos: {current_pos*2}.")
                      break # 停止解析当前脚本
                 data = script_io.read(data_len)
                 data_pushes.append(data.hex())

            elif opcode_val == OP_PUSHDATA4:
                 if script_io.tell() + 4 > script_len:
                      logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 读取 PUSHDATA4 长度字节不足. Script: {script_hex}, pos: {current_pos*2}.")
                      break # 停止解析当前脚本
                 len_bytes = script_io.read(4)
                 # int.from_bytes requires byteorder
                 data_len = int.from_bytes(len_bytes, 'little')
                 if script_io.tell() + data_len > script_len:
                      logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 读取 PUSHDATA4 数据长度 ({data_len}) 超出脚本边界. Script: {script_hex}, pos: {current_pos*2}.")
                      break # 停止解析当前脚本
                 data = script_io.read(data_len)
                 data_pushes.append(data.hex())

            else:
                # Non-push opcodes are ignored for data extraction
                # Just advance the position by the opcode byte (already done)
                pass # This simple parser just skips unknown opcodes

    except ValueError as e:
        # Handle errors during bytes.fromhex or int.from_bytes
        logging.warning(f"线程 {threading.current_thread().ident}: 脚本 hex 无效或数据解析错误 ({script_hex}): {e}")
        return []
    except Exception as e:
        logging.error(f"线程 {threading.current_thread().ident}: 解析脚本 hex 时发生未知错误 ({script_hex}): {e}", exc_info=True)
        return []

    return data_pushes


def extract_pubkeys_from_script(script_hex):
    """
    从给定的脚本 hex 中提取所有格式有效的公钥。
    这个函数用于解析 Redeem Script 或 Witness Script。
    只返回通过 is_valid_pubkey_hex 检查的 hex 字符串。
    """
    found_pubkeys = set()
    pushed_data = parse_script_hex(script_hex)
    for data_hex in pushed_data:
        if is_valid_pubkey_hex(data_hex):
            found_pubkeys.add(data_hex)
    # Note: The recursive call logic for redeem/witness script is handled in process_block
    # based on the original script's structure. This function just extracts direct pushes.
    return list(found_pubkeys) # Return list as in original function signature


def process_block(block_height, output_file_handle):
    """
    处理单个区块，提取公钥，并写入文件。
    此函数在工作线程中执行。
    """
    # 这些变量在此函数中会被修改，需要 global
    global total_keys_extracted_value, processed_blocks_count, global_state_lock

    thread_ident = threading.current_thread().ident
    logging.info(f"线程 {thread_ident}: 开始处理区块 {block_height}")

    block_hash = get_block_hash(block_height)
    # get_block_hash会返回 None 或触发等待/退出逻辑，这里只需要检查是否成功获取hash
    if not block_hash:
        logging.error(f"线程 {thread_ident}: 无法获取区块哈希: {block_height}. 跳过此区块。")
        # Increment processed_blocks_count even if skipped, to track progress correctly
        with global_state_lock:
            processed_blocks_count += 1
        return # 跳过此区块的处理

    block = get_block(block_hash)
    # get_block会返回 None 或触发等待/退出逻辑
    if not block:
        logging.error(f"线程 {thread_ident}: 无法获取区块数据: {block_height} ({block_hash}). 跳过此区块。")
        # Increment processed_blocks_count even if skipped
        with global_state_lock:
            processed_blocks_count += 1
        return # 跳过此区块的处理

    logging.debug(f"线程 {thread_ident}: 正在处理区块: {block_height} ({block_hash}) 交易数: {len(block.get('tx', []))}")

    transactions = block.get('tx', [])
    block_pubkeys_set = set() # 使用 set 确保区块内唯一性

    for tx in transactions:
        if not isinstance(tx, dict):
             logging.error(f"线程 {thread_ident}: 意外的交易格式在区块 {block_height}: {tx}")
             continue

        txid = tx.get('txid', '未知')

        # 1. 从交易输入 (vin) 中提取公钥
        # Exclude coinbase transaction's vin
        is_coinbase = False
        if 'vin' in tx and len(tx['vin']) == 1 and 'coinbase' in tx['vin'][0]:
             is_coinbase = True

        if not is_coinbase:
            for i, vin in enumerate(tx.get('vin', [])):
                 if not isinstance(vin, dict):
                      logging.warning(f"线程 {thread_ident}: 意外的VIN格式在 Tx {txid}, vin index {i}")
                      continue

                 extracted_pubkeys_from_vin = set()

                 # 从 scriptSig 提取
                 if 'scriptSig' in vin and isinstance(vin['scriptSig'], dict) and 'hex' in vin['scriptSig']:
                     scriptSig_hex = vin['scriptSig']['hex']
                     scriptSig_pushes = parse_script_hex(scriptSig_hex)
                     for j, push_hex in enumerate(scriptSig_pushes):
                         # 检查是否是直接的公钥 push
                         if is_valid_pubkey_hex(push_hex):
                              extracted_pubkeys_from_vin.add(push_hex)
                         # 检查是否是 Redeem Script (通常是最后一个 push)
                         # Note: This recursive call can be dangerous/slow for complex/malicious scripts
                         elif j == len(scriptSig_pushes) - 1 and len(push_hex) >= 4 and len(push_hex) % 2 == 0: # Basic checks if it looks like hex data
                             # Try parsing this push as a script
                             extracted_pubkeys_from_vin.update(extract_pubkeys_from_script(push_hex)) # Recursive call

                 # 从 txinwitness 提取
                 if 'txinwitness' in vin and isinstance(vin['txinwitness'], list):
                      witness_stack = vin['txinwitness']
                      for k, item_hex in enumerate(witness_stack):
                           if not isinstance(item_hex, str):
                                logging.warning(f"线程 {thread_ident}: 意外的witness item格式在 Tx {txid}, vin index {i}, witness index {k}")
                                continue

                           # 检查是否是直接的公钥 push
                           if is_valid_pubkey_hex(item_hex):
                                extracted_pubkeys_from_vin.add(item_hex)
                           # 检查是否是 Witness Script (通常是最后一个 push)
                           # Note: This recursive call can be dangerous/slow for complex/malicious scripts
                           elif k == len(witness_stack) - 1 and len(item_hex) >= 4 and len(item_hex) % 2 == 0: # Basic checks if it looks like hex data
                                # Try parsing this item as a script (Witness Script)
                                extracted_pubkeys_from_vin.update(extract_pubkeys_from_script(item_hex)) # Recursive call

                 block_pubkeys_set.update(extracted_pubkeys_from_vin)


        # 2. 从交易输出 (vout) 的 scriptPubKey 中提取直接包含的公钥
        # Vout scripts (scriptPubKey) usually only contain pubkeys directly in certain patterns (like P2PK, P2PKH)
        # or hashes of pubkeys/scripts. Extracting directly pushed pubkeys is the goal here.
        for i, vout in enumerate(tx.get('vout', [])):
             if not isinstance(vout, dict):
                  logging.warning(f"线程 {thread_ident}: 意外的VOUT格式在 Tx {txid}, vout index {i}")
                  continue

             scriptPubKey_data = vout.get('scriptPubKey')
             if not scriptPubKey_data or not isinstance(scriptPubKey_data, dict):
                  logging.warning(f"线程 {thread_ident}: VOUT {i} of Tx {txid} lacks scriptPubKey data.")
                  continue

             # Only extract directly pushed pubkeys from scriptPubKey
             if 'hex' in scriptPubKey_data:
                 script_pushes = parse_script_hex(scriptPubKey_data['hex'])
                 for push_hex in script_pushes:
                     if is_valid_pubkey_hex(push_hex):
                          block_pubkeys_set.add(push_hex) # Add directly to block set

    # 将提取到的公钥写入文件并更新总计数器
    keys_in_block = list(block_pubkeys_set) # Convert set to list to get count and iterate
    num_keys_extracted_this_block = len(keys_in_block)

    with global_state_lock:
         # Write to file (thread-safe using the lock)
         for key in keys_in_block:
              output_file_handle.write(f"{key}\n")
         # output_file_handle.flush() # Optional: flush immediately, can impact performance

         # Update total counter
         total_keys_extracted_value += num_keys_extracted_this_block

         # Update processed blocks counter
         processed_blocks_count += 1


    logging.debug(f"线程 {thread_ident}: 区块 {block_height} 处理完毕. 提取到 {num_keys_extracted_this_block} 个公钥。")
    # No need to return keys_in_block, they are written directly to file

def main(start_block, end_block, output_file):
    # These variables are modified in main, need global (optional but good practice for clarity)
    global total_keys_extracted_value, processed_blocks_count, global_state_lock

    load_rpc_config(RPC_CONFIG_FILE)

    if start_block < 0 or end_block < start_block:
        print(f"{C_RED}错误: 区块范围不合法{C_RESET}")
        logging.error("区块范围不合法")
        sys.exit(1)

    # Reset global counters
    with global_state_lock:
        total_keys_extracted_value = 0
        processed_blocks_count = 0 # Ensure this is 0 at start

    total_blocks_to_process = end_block - start_block + 1

    start_time = time.time()
    last_report_time = time.time()
    last_report_keys = 0
    last_report_blocks = 0

    print(f"{C_CYAN}开始处理区块 {start_block} 到 {end_block}...{C_RESET}")
    logging.info(f"开始处理区块 {start_block} 到 {end_block}...")

    try:
        # Open file before creating threads
        with open(output_file, 'w') as file_handle:
             # 使用 ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
                # 提交所有区块的处理任务
                # Pass file_handle and block height to the worker function
                futures = {executor.submit(process_block, block_height, file_handle): block_height for block_height in range(start_block, end_block + 1)}

                # Process completed tasks and update progress
                # Using a loop that checks completed blocks count is better than as_completed for consistent reporting
                while True:
                    with global_state_lock:
                         current_processed_blocks = processed_blocks_count
                         current_total_keys = total_keys_extracted_value

                    # Report progress periodically
                    elapsed_time = time.time() - start_time
                    # Report at least every 5 seconds OR if significant progress has been made OR when done
                    if (time.time() - last_report_time >= 5) or \
                       (current_processed_blocks - last_report_blocks >= max(1, total_blocks_to_process // 1000)) or \
                       (current_total_keys - last_report_keys >= 10000) or \
                       (current_processed_blocks == total_blocks_to_process):

                        report_duration = time.time() - last_report_time
                        report_keys_delta = current_total_keys - last_report_keys
                        report_blocks_delta = current_processed_blocks - last_report_blocks

                        key_rate_sec = report_keys_delta / report_duration if report_duration > 0 else 0
                        block_rate_sec = report_blocks_delta / report_duration if report_duration > 0 else 0
                        overall_elapsed = time.time() - start_time # Use current time for overall elapsed
                        overall_key_rate = current_total_keys / overall_elapsed if overall_elapsed > 0 else 0
                        overall_block_rate = current_processed_blocks / overall_elapsed if overall_elapsed > 0 else 0

                        # Use sys.stdout.write with \r and flush for scrolling effect
                        # Pad with spaces to clear previous text if new text is shorter
                        progress_str = (f"\r{C_YELLOW}进度: 完成区块 {current_processed_blocks}/{total_blocks_to_process}, 总计提取 {current_total_keys} 个公钥. "
                                         f"当前速度: {key_rate_sec:.2f} keys/s, {block_rate_sec:.2f} blocks/s. "
                                         f"总体速度: {overall_key_rate:.2f} keys/s, {overall_block_rate:.2f} blocks/s.{C_RESET}")
                        sys.stdout.write(progress_str.ljust(120)) # Pad with 120 spaces assuming max line length
                        sys.stdout.flush() # Important for \r

                        last_report_time = time.time()
                        last_report_keys = current_total_keys
                        last_report_blocks = current_processed_blocks

                    if current_processed_blocks == total_blocks_to_process:
                         break # All blocks are processed or skipped

                    # Add a small sleep to avoid busy waiting in the main loop
                    time.sleep(0.05) # Shorter sleep for faster updates

                # After the loop, check for any exceptions from the futures
                # as_completed loop is good for error handling *as* they happen,
                # but our current loop structure means we wait until all are done.
                # We can check results after the processing loop finishes to see if any thread failed.
                # If process_block returns None on failure, the future result will be None.
                # If process_block raises an exception, future.result() will re-raise it.
                for future in concurrent.futures.as_completed(futures):
                    block_height = futures[future]
                    try:
                        # Calling result() will raise any exception that occurred in the worker
                        # If worker finished normally (even if block skipped due to RPC), result() is None, no exception.
                        future.result()
                        # logging.debug(f"Future for block {block_height} completed without exception.") # Too verbose
                    except Exception as exc:
                        logging.error(f"主线程: 区块 {block_height} 处理任务发生未捕获异常: {exc}", exc_info=True)
                        print(f"\n{C_RED}主线程: 区块 {block_height} 处理任务发生未捕获错误: {exc}{C_RESET}")
                        # Continue checking other futures

            # Ensure all data is written to file before closing
            file_handle.flush()

        # Print a final newline after the progress reporting finishes
        sys.stdout.write("\n")

    except FileNotFoundError:
         logging.critical(f"无法打开输出文件: {output_file}")
         print(f"{C_RED}错误: 无法打开输出文件 {output_file}{C_RESET}")
         sys.exit(1)
    except Exception as e:
         logging.critical(f"主处理循环发生未捕获的异常: {e}", exc_info=True)
         print(f"\n{C_RED}发生严重错误，请查看日志文件: {e}{C_RESET}")
         sys.exit(1)

    end_time = time.time()
    total_duration = end_time - start_time
    final_total_keys = total_keys_extracted_value
    final_processed_blocks = processed_blocks_count


    print(f"\n{C_GREEN}--- 处理完成 ---{C_RESET}")
    logging.info("--- 处理完成 ---")
    print(f"处理区块范围: {C_CYAN}{start_block}{C_RESET} - {C_CYAN}{end_block}{C_RESET}")
    logging.info(f"处理区块范围: {start_block} - {end_block}")
    print(f"完成/跳过区块数量: {C_GREEN}{final_processed_blocks}{C_RESET}/{total_blocks_to_process}{C_RESET}")
    logging.info(f"完成/跳过区块数量: {final_processed_blocks}/{total_blocks_to_process}")
    print(f"总共提取公钥数量: {C_GREEN}{final_total_keys}{C_RESET}")
    logging.info(f"总共提取公钥数量: {final_total_keys}")
    print(f"总耗时: {C_CYAN}{total_duration:.2f} 秒{C_RESET}")
    logging.info(f"总耗时: {total_duration:.2f} 秒")
    if total_duration > 0:
        final_key_rate = final_total_keys / total_duration
        final_block_rate = final_processed_blocks / total_duration
        print(f"平均速度: {C_GREEN}{final_key_rate:.2f} 公钥/秒{C_RESET}, {C_GREEN}{final_block_rate:.2f} 区块/秒{C_RESET}")
        logging.info(f"平均速度: {final_key_rate:.2f} 公钥/秒, {final_block_rate:.2f} 区块/秒")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"{C_YELLOW}用法: python3 {sys.argv[0]} <start_block> <end_block> <output_file>{C_RESET}")
        sys.exit(1)

    try:
        start_block = int(sys.argv[1])
        end_block = int(sys.argv[2])
        output_file = sys.argv[3]
    except ValueError:
        print(f"{C_RED}错误: 起始区块和结束区块必须是整数{C_RESET}")
        logging.error("起始区块和结束区块必须是整数")
        sys.exit(1)

    main(start_block, end_block, output_file)
