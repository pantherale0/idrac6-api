from IDRAC6_API import IDRAC6_API

idrac = IDRAC6_API('10.20.1.10', 'root', 'calvin', debug=False)

power_status = idrac.get_attribute("pwState")
print("Current power status: ", power_status.pwState)
id1.logout()
