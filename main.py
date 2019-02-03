
import json

from IDRAC6_API import IDRAC6_API

file = open("config.json", "r")

all_lines = file.readlines()
all_str = ""

for line in all_lines:
    all_str += line

config_dict = json.loads(all_str)


id1 = IDRAC6_API(config_dict["url"], config_dict["username"], config_dict["password"], debug=True)

power_status = id1.get_power_status()
print("Current power status: ", power_status)
#id1.set_power_status(1)
id1.logout()