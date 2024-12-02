# burp_handling
处理burp history导出的数据，方便进一步的渗透

![image](https://github.com/user-attachments/assets/c29256f8-51e7-494f-9aa1-543fb4dfc086)

右键选中 save item，导出对应的xml文件

![image](https://github.com/user-attachments/assets/a859be37-6f0d-467d-8f82-9c643565d261)

导出文件格式还需要做进一步的处理：

1. **Base64 解码**：

   - 将 XML 中的 `<request>` 元素的内容进行 Base64 解码，解码得到完整的 HTTP 请求内容。
     
3. **解析请求**：

    - 根据 HTTP 请求格式，第一行包含了请求方法和路径，例如：POST /api/login HTTP/1.1，提取 `/api/login`
  
4. **提取 POST 数据**：

   - 通过检查是否遇到 HTTP 请求头结束标志 `\r\n\r\n`，来提取请求体
     
5. **写入 CSV 文件**：

   - 将提取到的请求方法、API 路径和 POST 数据写入到 CSV 文件中

导出文件命名为 `burp_history.xml`，导出文件为 `burp_history.csv`

```
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
```

![image](https://github.com/user-attachments/assets/1395820f-279f-485a-bb0e-9b1538a582ba)

intruder测试选择 `Pitchfork` 模式进行发包

![image](https://github.com/user-attachments/assets/2505674d-9eb9-4c26-8b09-df7635e3dc7a)

payload encoding 取消勾选

![image](https://github.com/user-attachments/assets/2633e612-908f-4058-ad14-9b3f78648fc1)

