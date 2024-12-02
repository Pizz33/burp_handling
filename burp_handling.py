import os
import xml.etree.ElementTree as ET
import csv
import base64

input_file = "burp_history.xml"
output_file = "burp_history.csv"

if os.path.exists(output_file):
    try:
        os.rename(output_file, output_file)
    except PermissionError:
        print(f"文件 {output_file} 正在被占用，请关闭相关程序后重试。")
        exit(1)

tree = ET.parse(input_file)
root = tree.getroot()

try:
    with open(output_file, mode="w", newline="", encoding="utf-8") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["Method", "API Endpoint", "POST Content"])

        for item in root.findall('./item'):
            request_element = item.find('request')

            if request_element is not None and request_element.text:
                try:
                    request_data = base64.b64decode(request_element.text).decode("utf-8", errors="ignore")
                except Exception as e:
                    print(f"Base64 解码失败: {e}")
                    continue

                header_body_split = request_data.split("\r\n\r\n", 1)

                if len(header_body_split) == 2:
                    headers = header_body_split[0]
                    body = header_body_split[1].strip()

                    header_lines = headers.split("\r\n")
                    if header_lines:
                        first_line = header_lines[0].strip()
                        parts = first_line.split(" ")
                        if len(parts) >= 2:
                            method = parts[0].upper()
                            path = parts[1]
                        else:
                            method = "UNKNOWN"
                            path = first_line

                        post_content = body if method == "POST" else ""
                        csv_writer.writerow([method, path, post_content])
                else:
                    csv_writer.writerow(["ERROR", "INVALID REQUEST", ""])
            else:
                csv_writer.writerow(["ERROR", "EMPTY REQUEST", ""])

    print(f"已成功将数据整理为 {output_file}")

except PermissionError:
    print(f"无法创建或写入文件 {output_file}，请检查权限。")
except Exception as e:
    print(f"发生意外错误：{e}")
