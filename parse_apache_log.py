import re
import csv

log_path = "access.log"
csv_path = "access_parsed.csv"

pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<method>\S+)? (?P<path>\S+)? (?P<protocol>\S+?)?" (?P<status>\d{3}) (?P<size>\d+|-) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

with open(log_path, "r") as infile, open(csv_path, "w", newline='') as outfile:
    writer = csv.writer(outfile)
    writer.writerow(["ip", "datetime", "method", "path", "status", "size", "referrer", "user_agent"])
    
    for line in infile:
        match = pattern.match(line)
        if match:
            writer.writerow([
                match.group("ip"),
                match.group("datetime"),
                match.group("method"),
                match.group("path"),
                match.group("status"),
                match.group("size"),
                match.group("referrer"),
                match.group("user_agent"),
            ])
