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
C_MAG = "\x1b[35m"
C_CYAN = "\x1b[36m"
C_RESET = "\x1b[0m"

# 设置日志记录
logging.basicConfig(filename='block_processing.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
# 避免重复添加 console handler
if not any(isinstance(h, logging.StreamHandler) for h in logging.getLogger().handlers):
     logging.getLogger().addHandler(console_handler)

# RPC 连接设置 (从配置文件加载)
RPC_HOST = ''
RPC_PORT = ''
RPC_USER = ''
RPC_PASSWORD = ''
RPC_URL = ''
RPC_CONFIG_FILE = 'rpc_config.json'
NUM_WORKERS = 1 # 默认线程数

# RPC 连续失败计数器和阈值 (全局共享，但由 rpc_request 管理)
RPC_CONSECUTIVE_FAILURES = 0
RPC_FAILURE_THRESHOLD = 10 # 连续失败 10 次后退出

# 比特币脚本操作码
OP_PUSHDATA1 = 0x4c # 76
OP_PUSHDATA2 = 0x4d # 77
OP_PUSHDATA4 = 0x4e # 78
OP_0 = 0x00       # 0

# 公钥十六进制格式的正则表达式 (只包含压缩和非压缩)
# Compressed: 33 bytes (66 hex), starts with 02 or 03
# Uncompressed: 65 bytes (130 hex), starts with 04
PUBKEY_HEX_REGEX = re.compile(r'^(02|03)[0-9a-fA-F]{64}$|^04[0-9a-fA-F]{128}$')

# 用于在多线程环境下安全更新总计数器
total_keys_extracted_lock = threading.Lock()
total_keys_extracted_value = 0

def load_rpc_config(filename):
    """从 JSON 文件加载 RPC 配置"""
    try:
        with open(filename, 'r') as f:
            config = json.load(f)
            global RPC_HOST, RPC_PORT, RPC_USER, RPC_PASSWORD, RPC_URL, NUM_WORKERS
            RPC_HOST = config.get('rpc_host', '127.0.0.1')
            RPC_PORT = str(config.get('rpc_port', 8332))
            RPC_USER = config.get('rpc_user')
            RPC_PASSWORD = config.get('rpc_password')
            NUM_WORKERS = int(config.get('num_workers', 1)) # 读取线程数，默认为 1
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
    headers = {'Content-Type': 'application/json'}
    payload = {
        "jsonrpc": "1.0",
        "id": f"python_rpc_{threading.current_thread().ident}", # 添加线程ID到请求ID
        "method": method,
        "params": params or []
    }
    global RPC_CONSECUTIVE_FAILURES

    if not all([RPC_URL, RPC_USER, RPC_PASSWORD]):
         logging.critical("RPC 配置未加载或不完整，无法发起请求。")
         print(f"{C_RED}RPC 配置未加载或不完整，无法发起请求。{C_RESET}")
         return None

    for attempt in range(3): # 尝试 3 次
        try:
            response = requests.post(
                RPC_URL,
                auth=(RPC_USER, RPC_PASSWORD),
                headers=headers,
                data=json.dumps(payload),
                timeout=60 # 60秒超时
            )
            response.raise_for_status() # HTTP 错误也会抛出异常
            response_data = response.json()

            if 'error' in response_data and response_data['error']:
                error = response_data['error']
                # 检查一些可忽略的错误码或消息
                if error.get('code') in [-5, -8, -25] or "No such mempool or blockchain transaction" in error.get('message', ''):
                     logging.warning(f"线程 {threading.current_thread().ident}: RPC 错误（可能可忽略） ({method} {params}): {error['message']}")
                     # 可忽略的错误不计入连续失败
                     # RPC_CONSECUTIVE_FAILURES = 0 # 不要在这里重置，因为这是全局的
                     return None
                else:
                    logging.error(f"线程 {threading.current_thread().ident}: RPC 错误 ({method} {params}, 尝试 {attempt+1}/3): {error}")
                    with total_keys_extracted_lock: # 在更新全局失败计数器时加锁
                        RPC_CONSECUTIVE_FAILURES += 1
                        current_failures = RPC_CONSECUTIVE_FAILURES

                    if current_failures >= RPC_FAILURE_THRESHOLD:
                        logging.critical(f"RPC 连接连续失败 {RPC_FAILURE_THRESHOLD} 次。请检查你的节点和配置。退出程序。")
                        print(f"{C_RED}\nRPC 连接连续失败 {RPC_FAILURE_THRESHOLD} 次。请检查你的节点和配置。退出程序。{C_RESET}")
                        sys.exit(1) # 达到阈值，直接退出

                    time.sleep(10) # 等待一段时间后重试
                    continue

            # 请求成功，重置连续失败计数器 (需要加锁)
            with total_keys_extracted_lock:
                 RPC_CONSECUTIVE_FAILURES = 0
            return response_data['result']

        except requests.exceptions.RequestException as e:
            logging.error(f"线程 {threading.current_thread().ident}: RPC 请求失败 ({method} {params}, 尝试 {attempt+1}/3): {e}")
            with total_keys_extracted_lock: # 在更新全局失败计数器时加锁
                RPC_CONSECUTIVE_FAILURES += 1
                current_failures = RPC_CONSECUTIVE_FAILURES

            if current_failures >= RPC_FAILURE_THRESHOLD:
                logging.critical(f"RPC 连接连续失败 {RPC_FAILURE_THRESHOLD} 次。请检查你的节点和配置。退出程序。")
                print(f"{C_RED}\nRPC 连接连续失败 {RPC_FAILURE_THRESHOLD} 次。请检查你的节点和配置。退出程序。{C_RESET}")
                sys.exit(1) # 达到阈值，直接退出
            time.sleep(10)

        except json.JSONDecodeError:
            logging.error(f"线程 {threading.current_thread().ident}: RPC 返回无效 JSON ({method} {params}, 尝试 {attempt+1}/3): {response.text if response else '无响应'}")
            with total_keys_extracted_lock: # 在更新全局失败计数器时加锁
                RPC_CONSECUTIVE_FAILURES += 1
                current_failures = RPC_CONSECUTIVE_FAILURES

            if current_failures >= RPC_FAILURE_THRESHOLD:
                 logging.critical(f"RPC 返回无效 JSON 连续 {RPC_FAILURE_THRESHOLD} 次。请检查 RPC 服务器响应。退出程序。")
                 print(f"{C_RED}\nRPC 返回无效 JSON 连续 {RPC_FAILURE_THRESHOLD} 次。请检查 RPC 服务器响应。退出程序。{C_RESET}")
                 sys.exit(1) # 达到阈值，直接退出
            time.sleep(10)

        except Exception as e:
             logging.error(f"线程 {threading.current_thread().ident}: RPC 请求发生未知错误 ({method} {params}, 尝试 {attempt+1}/3): {e}", exc_info=True)
             with total_keys_extracted_lock: # 在更新全局失败计数器时加锁
                 RPC_CONSECUTIVE_FAILURES += 1
                 current_failures = RPC_CONSECUTIVE_FAILURES

             if current_failures >= RPC_FAILURE_THRESHOLD:
                  logging.critical(f"RPC 请求发生未知错误连续 {RPC_FAILURE_THRESHOLD} 次：{e}. 退出程序。")
                  print(f"{C_RED}\nRPC 请求发生未知错误连续 {RPC_FAILURE_THRESHOLD} 次：{e}. 退出程序。{C_RESET}")
                  sys.exit(1) # 达到阈值，直接退出
             time.sleep(10)


    logging.critical(f"线程 {threading.current_thread().ident}: RPC 请求 {method} {params} 多次尝试后仍然失败，且未达到全局退出阈值。返回 None。")
    return None

def get_block_hash(block_height):
    return rpc_request('getblockhash', [block_height])

def get_block(block_hash):
    # 使用 verbosity 2 获取完整的交易数据
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
        script_bytes = bytes.fromhex(script_hex)
        script_io = io.BytesIO(script_bytes)
        script_len = len(script_bytes)

        while script_io.tell() < script_len:
            current_pos = script_io.tell()
            opcode = script_io.read(1)
            if not opcode:
                break # 脚本结束

            opcode_val = opcode[0]

            if opcode_val == OP_0:
                 data_pushes.append("") # Represent OP_0 as empty hex string
                 continue

            # OP_PUSHBYTES_1 to OP_PUSHBYTES_75
            if 0x01 <= opcode_val <= 0x4b:
                data_len = opcode_val
                if script_io.tell() + data_len > script_len:
                    logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 数据长度不足 ({data_len} bytes). Script: {script_hex}, pos: {current_pos*2}.")
                    break
                data = script_io.read(data_len)
                data_pushes.append(data.hex())

            elif opcode_val == OP_PUSHDATA1:
                 if script_io.tell() + 1 > script_len:
                      logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 读取 PUSHDATA1 长度字节不足. Script: {script_hex}, pos: {current_pos*2}.")
                      break
                 len_bytes = script_io.read(1)
                 data_len = len_bytes[0]
                 if script_io.tell() + data_len > script_len:
                      logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 读取 PUSHDATA1 数据长度不足 ({data_len} bytes). Script: {script_hex}, pos: {current_pos*2}.")
                      break
                 data = script_io.read(data_len)
                 data_pushes.append(data.hex())

            elif opcode_val == OP_PUSHDATA2:
                 if script_io.tell() + 2 > script_len:
                      logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 读取 PUSHDATA2 长度字节不足. Script: {script_hex}, pos: {current_pos*2}.")
                      break
                 len_bytes = script_io.read(2)
                 data_len = int.from_bytes(len_bytes, 'little')
                 if script_io.tell() + data_len > script_len:
                      logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 读取 PUSHDATA2 数据长度不足 ({data_len} bytes). Script: {script_hex}, pos: {current_pos*2}.")
                      break
                 data = script_io.read(data_len)
                 data_pushes.append(data.hex())

            elif opcode_val == OP_PUSHDATA4:
                 if script_io.tell() + 4 > script_len:
                      logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 读取 PUSHDATA4 长度字节不足. Script: {script_hex}, pos: {current_pos*2}.")
                      break
                 len_bytes = script_io.read(4)
                 data_len = int.from_bytes(len_bytes, 'little')
                 if script_io.tell() + data_len > script_len:
                      logging.warning(f"线程 {threading.current_thread().ident}: 脚本解析错误: 读取 PUSHDATA4 数据长度不足 ({data_len} bytes). Script: {script_hex}, pos: {current_pos*2}.")
                      break
                 data = script_io.read(data_len)
                 data_pushes.append(data.hex())

            else:
                # Non-push opcodes are ignored for data extraction
                pass

    except ValueError as e:
        logging.warning(f"线程 {threading.current_thread().ident}: 脚本 hex 无效 ({script_hex}): {e}")
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
    return list(found_pubkeys)


def process_block(block_height):
    """
    处理单个区块，提取公钥，并返回列表。
    此函数在工作线程中执行。
    """
    thread_ident = threading.current_thread().ident
    logging.info(f"线程 {thread_ident}: 开始处理区块 {block_height}")

    block_hash = get_block_hash(block_height)
    if not block_hash:
        logging.error(f"线程 {thread_ident}: 无法获取区块哈希: {block_height}. 跳过此区块。")
        return []

    block = get_block(block_hash)
    if not block:
        logging.error(f"线程 {thread_ident}: 无法获取区块数据: {block_height} ({block_hash}). 跳过此区块。")
        return []

    logging.debug(f"线程 {thread_ident}: 正在处理区块: {block_height} ({block_hash}) 交易数: {len(block.get('tx', []))}")

    transactions = block.get('tx', [])
    block_pubkeys_set = set() # 使用 set 确保区块内唯一性

    for tx in transactions:
        if not isinstance(tx, dict):
             logging.error(f"线程 {thread_ident}: 意外的交易格式在区块 {block_height}: {tx}")
             continue

        txid = tx.get('txid', '未知')

        # 1. 从交易输入 (vin) 中提取公钥
        if 'vin' in tx and len(tx['vin']) == 1 and 'coinbase' in tx['vin'][0]:
            pass # 跳过 coinbase vin
        else:
            for i, vin in enumerate(tx.get('vin', [])):
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
                         elif j == len(scriptSig_pushes) - 1 and len(push_hex) >= 4 and len(push_hex) % 2 == 0:
                             extracted_pubkeys_from_vin.update(extract_pubkeys_from_script(push_hex))

                 # 从 txinwitness 提取
                 if 'txinwitness' in vin and isinstance(vin['txinwitness'], list):
                      witness_stack = vin['txinwitness']
                      for k, item_hex in enumerate(witness_stack):
                           # 检查是否是直接的公钥 push
                           if is_valid_pubkey_hex(item_hex):
                                extracted_pubkeys_from_vin.add(item_hex)
                           # 检查是否是 Witness Script (通常是最后一个 push)
                           elif k == len(witness_stack) - 1 and len(item_hex) >= 4 and len(item_hex) % 2 == 0:
                                extracted_pubkeys_from_vin.update(extract_pubkeys_from_script(item_hex))

                 block_pubkeys_set.update(extracted_pubkeys_from_vin)


        # 2. 从交易输出 (vout) 的 scriptPubKey 中提取直接包含的公钥
        for i, vout in enumerate(tx.get('vout', [])):
             scriptPubKey_data = vout.get('scriptPubKey')
             if not scriptPubKey_data or not isinstance(scriptPubKey_data, dict):
                  logging.warning(f"线程 {thread_ident}: VOUT {i} of Tx {txid} lacks scriptPubKey data.")
                  continue

             extracted_pubkeys_from_vout = set()
             if 'hex' in scriptPubKey_data:
                 script_pushes = parse_script_hex(scriptPubKey_data['hex'])
                 for push_hex in script_pushes:
                     if is_valid_pubkey_hex(push_hex):
                          extracted_pubkeys_from_vout.add(push_hex)

             block_pubkeys_set.update(extracted_pubkeys_from_vout)

    logging.debug(f"线程 {thread_ident}: 区块 {block_height} 处理完毕. 提取到 {len(block_pubkeys_set)} 个公钥。")
    return list(block_pubkeys_set)


def main(start_block, end_block, output_file):
    load_rpc_config(RPC_CONFIG_FILE)

    if start_block < 0 or end_block < start_block:
        print(f"{C_RED}错误: 区块范围不合法{C_RESET}")
        logging.error("区块范围不合法")
        sys.exit(1)

    global total_keys_extracted_value
    total_keys_extracted_value = 0
    processed_blocks_count = 0
    total_blocks_to_process = end_block - start_block + 1

    start_time = time.time()
    last_report_time = time.time()
    last_report_keys = 0
    last_report_blocks = 0

    print(f"{C_CYAN}开始处理区块 {start_block} 到 {end_block}...{C_RESET}")
    logging.info(f"开始处理区块 {start_block} 到 {end_block}...")

    try:
        with open(output_file, 'w') as file_handle:
             # 使用 ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
                # 提交所有区块的处理任务
                futures = {executor.submit(process_block, block_height): block_height for block_height in range(start_block, end_block + 1)}

                # 处理已完成的任务
                for future in concurrent.futures.as_completed(futures):
                    block_height = futures[future]
                    try:
                        keys_in_block = future.result() # 获取线程返回的公钥列表
                        processed_blocks_count += 1

                        if keys_in_block is not None: # 确保任务成功返回了列表 (即使是空的)
                             # 将提取到的公钥写入文件
                             for key in keys_in_block:
                                  file_handle.write(f"{key}\n")
                             # file_handle.flush() # 可以选择性地实时刷新到磁盘

                             # 更新总计数器 (多线程安全)
                             with total_keys_extracted_lock:
                                  total_keys_extracted_value += len(keys_in_block)

                             logging.info(f"主线程: 区块 {block_height} 处理结果收集完毕. 提取 {len(keys_in_block)} 个公钥. 总计: {total_keys_extracted_value}. 已完成 {processed_blocks_count}/{total_blocks_to_process} 个区块.")

                        else: # process_block 返回 None 表示该区块处理失败或被跳过
                             logging.warning(f"主线程: 区块 {block_height} 处理任务失败或被跳过 (process_block returned None).")


                        # 进度报告
                        elapsed_time = time.time() - start_time
                        current_total_keys = total_keys_extracted_value
                        current_processed_blocks = processed_blocks_count

                        # 每隔一段时间或处理一定数量的公钥后更新报告
                        if (time.time() - last_report_time >= 60) or (current_total_keys - last_report_keys >= 100000) or (current_processed_blocks - last_report_blocks >= 1000) or (current_processed_blocks == total_blocks_to_process):
                            report_duration = time.time() - last_report_time
                            report_keys_delta = current_total_keys - last_report_keys
                            report_blocks_delta = current_processed_blocks - last_report_blocks

                            key_rate_sec = report_keys_delta / report_duration if report_duration > 0 else 0
                            block_rate_sec = report_blocks_delta / report_duration if report_duration > 0 else 0
                            overall_key_rate = current_total_keys / elapsed_time if elapsed_time > 0 else 0
                            overall_block_rate = current_processed_blocks / elapsed_time if elapsed_time > 0 else 0

                            print(f"{C_YELLOW}进度: 完成区块 {current_processed_blocks}/{total_blocks_to_process}, 总计提取 {current_total_keys} 个公钥. "
                                  f"当前速度: {key_rate_sec:.2f} keys/s, {block_rate_sec:.2f} blocks/s. "
                                  f"总体速度: {overall_key_rate:.2f} keys/s, {overall_block_rate:.2f} blocks/s.{C_RESET}")

                            last_report_time = time.time()
                            last_report_keys = current_total_keys
                            last_report_blocks = current_processed_blocks

                    except Exception as exc:
                        logging.error(f"主线程: 处理区块 {block_height} 的结果时发生未捕获的异常: {exc}", exc_info=True)
                        print(f"{C_RED}主线程: 处理区块 {block_height} 的结果时发生错误: {exc}{C_RESET}")
                        # 可以在这里选择是否继续或退出

            file_handle.flush() # 确保所有数据都写入文件

    except FileNotFoundError:
         logging.critical(f"无法打开输出文件: {output_file}")
         print(f"{C_RED}错误: 无法打开输出文件 {output_file}{C_RESET}")
         sys.exit(1)
    except Exception as e:
         logging.critical(f"主处理循环发生未捕获的异常: {e}", exc_info=True)
         print(f"{C_RED}发生严重错误，请查看日志文件: {e}{C_RESET}")
         sys.exit(1)

    end_time = time.time()
    total_duration = end_time - start_time
    final_total_keys = total_keys_extracted_value

    print(f"\n{C_GREEN}--- 处理完成 ---{C_RESET}")
    logging.info("--- 处理完成 ---")
    print(f"处理区块范围: {C_CYAN}{start_block}{C_RESET} - {C_CYAN}{end_block}{C_RESET}")
    logging.info(f"处理区块范围: {start_block} - {end_block}")
    print(f"总共提取公钥数量: {C_GREEN}{final_total_keys}{C_RESET}")
    logging.info(f"总共提取公钥数量: {final_total_keys}")
    print(f"总耗时: {C_CYAN}{total_duration:.2f} 秒{C_RESET}")
    logging.info(f"总耗时: {total_duration:.2f} 秒")
    if total_duration > 0:
        final_rate = final_total_keys / total_duration
        print(f"平均速度: {C_GREEN}{final_rate:.2f} 公钥/秒{C_RESET}")
        logging.info(f"平均速度: {final_rate:.2f} 公钥/秒")

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
